# frida-afl-proxy-poc
```
AFL_SKIP_BIN_CHECK=1 AFL_DEBUG=1 /home/ax/AFLplusplus/afl-fuzz -t 100000 -m 2048 -i ./in -o ./out -- ./fafl-poc 127.0.0.1:27042 $(pidof vuln-tcp-server) fafl-poc.js
```
