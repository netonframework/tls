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
- 读方向产生的密文（TLS 1.3 会话票据的确认、KeyUpdate 应答、告警）由读者负责写出；读者与写者共用一把写锁，保证 `inner`
  上同一时刻只有一个写（§28.6 规则）。
- 缓冲：每连接一个密文输入缓冲、一个密文输出缓冲（各 `engine` 缓冲容量 + 一条记录的余量），连接存续期间复用。

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
- 测试 11/11：macOS arm64；colima Linux arm64 io_uring（multishot）/ io_uring 单次 RECV / epoll 各 2 次（这也是 openssl-kotlin 的 TLS 路径首次在 Linux 上实际运行）。
  含 `io-testkit` 一致性套件（TCP 之上、内存流之上）全部通过。
- **引擎的全双工限制**：openssl-kotlin 的 `TlsEngine` 在一次写入等待重试（NEED_WRITE）期间拒绝读取。若双方的写都在等待重试（各自阻塞在
  TCP 上等对方读），双方的读都不能进行——死锁（引擎缓冲 16 KiB、双向同时 1 MiB 时复现）。对策：每次写入前先写出待发密文，引擎缓冲至少容纳
  一条完整记录（`MIN_BUFFER` = 17 KiB，默认 32 KiB），应用写入因此不会进入重试；构造时拒绝更小的缓冲。已请 openssl-kotlin 允许重试期间读取
  （OpenSSL 本身允许在两次 `SSL_write` 重试之间 `SSL_read`）。
- **性能**（153，callgrind，TLS 1.3 AES-128-GCM，128 字节回显，12 连接，每请求 =（15 s − 5 s）差值）：

  | 版本 | 每请求指令（epoll / io_uring） | 每请求分配 |
  |---|---|---|
  | 初版（每个辅助函数一个挂起函数） | 26.2k / 28.0k | 12 |
  | 全部内联 | 28.8k / 30.3k | 4 → 2（加 `intResult`） |
  | 热路径内联、少见路径不内联（现行） | 23.5k / 25.0k | 2 |
  | 对照：neton-io 原始回显（无 TLS） | 2.4k / 3.8k | 0 |

  发现：Kotlin/Native 在挂起函数每次进入与恢复时把整个栈帧中的 GC 槽清零；把少见路径也内联使 `read` 的帧涨到 2.7 KB（`memset` 每请求约 5.4k
  指令），反而更慢。现行版本 `read` / `write` 帧各约 1.4 KB。剩余 2 次分配是公开 `read` / `write` 各自的续体（一次调用一个）。
  现行版本每请求约 24.6k 指令中的主要项：`memset` 3.2k（其中 OpenSSL `tls_write_records_default` 每条记录约 2.4k，本库帧清零约 0.7k）、
  `ERR_clear_error` 1.1k（封装在每次引擎读写前调用）、OpenSSL 每条记录的 `malloc` / `free` 约 1.3k、数组固定与范围检查（`Pinned`、`checkRange`、
  `pendingCiphertext` 的句柄访问）约 0.9k、真正的加解密（AES-GCM、GHASH）约 2–3k。与 Rust（tokio-rustls / tokio-openssl）的同机对照尚未进行。
