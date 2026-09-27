# tls — TLS 作为 `IoStream`（com.netonstream:tls）

状态：v1（2026-09-28）已实现并验证（§6）；评审意见按条修订。

## 1. 定位与边界

- 把 `com.netonstream:openssl`（openssl-kotlin，OpenSSL 4.0.2 的无 I/O 安全封装 `TlsContext` / `TlsEngine`）接到
  `com.netonstream:io` 的 `IoStream` 上：`TlsStream(inner: IoStream, engine)` 本身也是 `IoStream`，http（https）、websocket（wss）
  直接使用；QUIC 不走这里（QUIC 用 openssl-kotlin 的 QUIC TLS 接口，另见 quic SPEC §4）。
- **不实现任何密码学或 TLS 协议逻辑**：握手、记录层、证书与主机名验证、ALPN 全部由 `TlsEngine` 完成；本库只负责在协程里
  搬运密文、调度读写、把状态映射到 `IoStream` 契约（neton-io SPEC §28.6）。
- 配置（信任根、证书、版本、套件、ALPN、客户端认证）就是 `TlsContext` 的构造参数，本库不重复包装；只提供连接级的便捷入口
  `tlsConnect(stream, context, peer)` / `tlsAccept(stream, context)`。
- 不依赖、也不修改 neton-io 的内部实现，只用其公开 API。

## 2. 数据路径

- 入站：`inner.read` 读密文到本连接的密文输入缓冲 → `engine.feedCiphertext`（引擎内部 BIO 有界，可能只收下一部分，余下留在输入缓冲）
  → `engine.read` 直接解密进调用方 `dst` 的底层数组（`reserve` / `commitWrite`，不经中间缓冲）。
- 出站：`engine.write` 直接从调用方 `src` 的底层数组取明文（每次至多 16 KiB，一条记录）→ `engine.drainCiphertext` 取出密文 →
  `inner.write`。**`src` 只在该段明文对应的密文全部交给 `inner` 之后才前移**。
- **按 OpenSSL 的重试契约调度**（SSL_get_error(3)，4.0.2 原文："If you get SSL_ERROR_WANT_WRITE from SSL_write() ... you should not do any
  other operation that could trigger IO other than to repeat the previous SSL_write() call"；WANT_READ 时则可以在两次重试之间读取）：
  - WANT_WRITE（读、写、握手、close_notify 都可能）：立即、不挂起地把引擎输出取入暂存缓冲，然后重复同一调用；两者之间不做任何其他引擎操作，
    也**不跨越网络等待**。因此不存在"写重试悬而未决、同时阻塞在网络写上"的状态，对端不读时也不会挡住本端的读。
  - 写返回 WANT_READ：写者自己取得更多输入（与读者用输入锁和"已喂入代次"协调，同一时刻只有一方读 `inner`，别人刚喂过就不再读），然后重复
    同一写入；期间读者等待（openssl-kotlin 当前在任何重试期间都拒绝读取；按 OpenSSL 契约 WANT_READ 时本可读取，已请其按原因区分）。
  - 密文经暂存缓冲写出：持有写锁者把暂存缓冲写给 `inner`；该次写入进行中新取出的密文放入溢出缓冲（正在发送的缓冲不被触碰，io_uring 时由内核
    持有），写完后接到暂存缓冲之后，顺序不变。暂存缓冲始终是同一数组（交替两个数组会让反应器的固定缓存失效、每次写一次分配，已实测）。
  - 读者产生的密文（告警、TLS 1.3 握手后消息的应答）：写锁空闲时读者自己写出；否则由持锁者在当前写完后一并写出；暂存超过 64 KiB 时读者等锁，
    防止对端不断诱发应答使暂存无界增长。
- 缓冲：每连接一个密文输入缓冲、一个暂存缓冲（各为引擎缓冲容量 + 一条记录的余量）与一个很少使用的溢出缓冲；连接存续期间复用。引擎缓冲容量
  不再有下限要求（1 KiB 已测）。

## 3. `IoStream` 契约（neton-io SPEC §28.6）

- `read`：追加到 `dst`，返回 > 0；对端发送 close_notify 后返回 -1。**没有 close_notify 的 EOF 是截断**，抛 `TlsTruncatedException`
  （`IoException`），不能当作正常结束——这是 TLS 防截断攻击的要求。
- `write`：写完全部明文才返回。
- `shutdownOutput`（声明 `HalfClose`）：发送 close_notify 并写出；之后仍可读。不关闭底层 TCP 的写方向（部分实现收到 TCP FIN 会中止）。
- `close`：立即、幂等；不发送 close_notify（`close` 不能挂起）。需要优雅结束时先 `shutdownOutput()`，或用 neton-io 的
  `closeGracefully`。关闭时挂起的读写得到 `ClosedException`。
- 并发：同时至多一个读、一个写，第二个并发调用抛 `IllegalStateException`。只在创建它的线程上使用（不声明 `AnyThread`）。
- 超时：`ReadTimeout` / `WriteTimeout` / `IdleTimeout` 随 `inner` 声明，透传给 `inner`。
- 取消：**不声明 `ResumableAfterCancel`**。读写被取消（或超时抛出）后流关闭：取消可能发生在一条记录只写出一半时，TLS 无法
  继续在同一连接上正确收发。被取消的写：`src` 只计入整条记录已交给 `inner` 的明文，对端收到的明文不会多于 `src` 的前移量
  （对端可能因半条记录而报错，而不是正常 EOF）。
- 握手：首次读或写时自动进行；也可显式 `handshake()`。TLS 失败抛 `TlsFailureException`（`IoException`，带
  `TlsFailureKind`、验证码、告警码，`duringHandshake` 区分握手阶段），失败前尽力把引擎生成的告警写给对端，然后关闭。
- 连接信息：握手完成后可取 `alpn`、`protocolVersion`、`cipherSuite`、`serverName`（服务端）、`peerCertificates()`（DER，叶子在前）、
  `exportKeyingMaterial`。

## 4. 测试

- `io-testkit` 一致性套件：`TlsStream`（TCP 之上、内存流之上）全部通过；取消相关检查按 §3 "不声明 ResumableAfterCancel" 的规则。
- 专项：TLS 1.2 / 1.3 握手与收发；分片（`inner` 每次只给 1 字节）；大块（1 MiB）双向同时收发；ALPN 协商；主机名错误 / 未知 CA /
  过期证书 → `TlsFailureException` 分类正确；mTLS；close_notify → -1；无 close_notify 的 EOF → `TlsTruncatedException`；
  `shutdownOutput` 后仍可读；关闭时挂起的读写得到 `ClosedException`；取消读 / 写后流关闭。
- 测试证书：测试代码内用 openssl-kotlin 的原始绑定生成自签 CA 与叶子证书（仅测试，不进入任何可用配置）。

## 5. 性能

- 验收沿用 neton-io SPEC §28.4 的规程与指标：同机 TLS 回显（本库）对照 Rust 的 tokio-rustls / tokio-openssl 回显，同等配置（TLS 1.3、
  AES-128-GCM、同样的证书）；每请求指令数与分配数用 callgrind 实测。
- 已知待测项：openssl-kotlin 的数组接口每次调用固定（pin）一次数组（`usePinned`），每请求至少四次；若实测分配 / 指令显著，向
  openssl-kotlin 提出显式不安全的指针接口（其契约已预留）。

## 6. 实现与验证记录（2026-09-28）

- 依赖：`com.netonstream:openssl:4.0.2`（本机 mavenLocal，openssl-kotlin 提交 aec636c）、`com.netonstream:io` 0.2.0-SNAPSHOT（兄弟目录复合构建）。
- 测试（初版）11/11：macOS arm64；colima Linux arm64 io_uring（multishot）/ io_uring 单次 RECV / epoll 各 2 次（这也是 openssl-kotlin 的 TLS 路径首次在 Linux 上实际运行）。
  含 `io-testkit` 一致性套件（TCP 之上、内存流之上）全部通过。
- **初版的全双工死锁与修正**：初版在 WANT_WRITE 后先把密文写到网络（可能阻塞）再重试，重试期间引擎拒绝读取；双方的写都阻塞在 TCP 上时双方都
  读不了——死锁（引擎缓冲 16 KiB、双向同时 1 MiB 时复现）。初版以"引擎缓冲至少一条记录（17 KiB）"规避，并错误地请 openssl-kotlin 放开重试期间的
  读取；审查指出 OpenSSL 契约对 WANT_WRITE 恰恰禁止这样做。现行版本按上面 §2 的规则调度：WANT_WRITE 就地取出并立即重试，重试从不跨越网络等待。
  测试：引擎缓冲 1 KiB / 4 KiB 下双向同时 1 MiB、慢速链路（每次至多 700 字节、写间停顿）下双向同时 96 KiB，均完成；把初版行为放回去，1 KiB 测试
  挂起（强制超时）。现行 12/12：macOS；colima Linux arm64 三种驱动配置各 2–3 次。
- **性能**（153，callgrind，TLS 1.3 AES-128-GCM，128 字节回显，12 连接，每请求 =（15 s − 5 s）差值）：

  | 版本 | 每请求指令（epoll / io_uring） | 每请求分配 |
  |---|---|---|
  | 初版（每个辅助函数一个挂起函数） | 26.2k / 28.0k | 12 |
  | 全部内联 | 28.8k / 30.3k | 4 → 2（加 `intResult`） |
  | 热路径内联、少见路径不内联 | 23.5k / 25.0k | 2 |
  | 按 OpenSSL 重试契约重写调度（现行） | 23.4k / 24.9k | 2 |
  | 对照：neton-io 原始回显（无 TLS） | 2.4k / 3.8k | 0 |

  发现：Kotlin/Native 在挂起函数每次进入与恢复时把整个栈帧中的 GC 槽清零；把少见路径也内联使 `read` 的帧涨到 2.7 KB（`memset` 每请求约 5.4k
  指令），反而更慢。现行版本 `read` / `write` 帧各约 1.4 KB。剩余 2 次分配是公开 `read` / `write` 各自的续体（一次调用一个）。
  现行版本每请求约 24.6k 指令中的主要项：`memset` 3.2k（其中 OpenSSL `tls_write_records_default` 每条记录约 2.4k，本库帧清零约 0.7k）、
  `ERR_clear_error` 1.1k（封装在每次引擎读写前调用）、OpenSSL 每条记录的 `malloc` / `free` 约 1.3k、数组固定与范围检查（`Pinned`、`checkRange`、
  `pendingCiphertext` 的句柄访问）约 0.9k、真正的加解密（AES-GCM、GHASH）约 2–3k。与 Rust（tokio-rustls / tokio-openssl）的同机对照尚未进行。

  现行版本，三类开销分开统计（epoll，每请求）：Kotlin 堆分配 2 次（66 指令；本库公开 `read` / `write` 的续体）；原生 `malloc` 4 次（172 指令，
  来自 OpenSSL `CRYPTO_zalloc`）、`free` 103 次（752 指令，`CRYPTO_free`）；`memset` 13 次共 3.1k 指令，其中 OpenSSL `tls_write_records_default`
  每条记录一次约 2.4k，其余为结构体清零与本库 / 反应器的栈帧清零（各数百指令）。原生分配与清零的用途（结构体初始化、记录缓冲、秘密数据清除）
  尚未逐项定位，不能为跑分删除秘密数据的清零。
- 未覆盖：TLS 1.3 KeyUpdate（openssl-kotlin 未提供触发接口，无法在测试中产生）；写入遇到 WANT_READ 的路径（TLS 1.3 下正常情况不会出现，代码按
  契约处理但尚无测试能触发）。
