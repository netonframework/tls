#!/bin/sh
# SPEC §5: TLS echo, server under callgrind, Ir and heap allocations per request = (15 s - 5 s) / (req15 - req5).
# Allocations: sum the caller counts of kotlin::alloc::CustomAllocator::Allocate in `callgrind_annotate --tree=caller`.
cd /root/bench/tls; ulimit -n 65536; mkdir -p cert
wait_port(){ for _ in $(seq 1 600); do nc -z 127.0.0.1 18300 2>/dev/null && return 0; sleep 0.1; done; return 1; }
for d in epoll iouring; do for s in 5 15; do
  rm -f cg-$d-$s.out
  sh -c "exec env NETON_IO_DRIVER=$d NETON_TLS_RUN_SECONDS=$((s + 25)) valgrind --tool=callgrind --callgrind-out-file=cg-$d-$s.out ./tlsEcho.kexe server 18300 cert" > /dev/null 2>&1 & pid=$!
  wait_port || { echo "never bound"; kill $pid; continue; }
  sleep 2
  req=$(NETON_IO_DRIVER=$d ./tlsEcho.kexe client 18300 cert 12 $s 128 | awk '/^requests/{print $2}')
  wait $pid
  ir=$(callgrind_annotate cg-$d-$s.out 2>/dev/null | awk '/PROGRAM TOTALS/{gsub(",","",$1); print $1}')
  echo "$d secs=$s requests=$req Ir=$ir"
done; done
echo TLSCG-DONE
