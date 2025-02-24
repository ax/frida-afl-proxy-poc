# :rabbit2: frida-afl-proxy-poc
What follows here is merely a proof of concept to explore an idea.

frida-afl-proxy is an afl proxy based on Frida that can be used with AFL++ for coverage-guided binary-only fuzzing. 

It should run on all platforms supported by Frida. It can be used when all the others AFL++ modes are not suitable.
## How frida-afl-proxy works
frida-afl-proxy can be used to fuzz network servers with AFL++. frida-afl-proxy, afl-fuzz and a frida-server must run on the target platform.
- AFL++'s afl-fuzz spawns frida-afl-proxy that connects to the frida-server and load the frida-afl-proxy.js script.
- The frida-afl-proxy.js script attach the frida interceptor to the target function. onEnter the frida Staker will follow the current thread id for coverage collection.
- afl-fuzz writes its mutated payloads to frida-afl-proxy that repeatedly connects, sends the payload, and close the socket.
- During the execution and processing of the input, the target will, due to the injected code, gather coverage info and write it to AFL++'s coverage bitmap in the AFL++'s shared memory.
## Run frida-afl-proxy against vuln-tcp-server
frida-afl-proxy.js should be modified to fit the needs of the target, you have to setup `module_start`, `module_end` and `base`.
`module_start` and `module_end` are used to limit the stalker tracing (mandatory?) and `base` is the address of the function that 
Frida will instrument and gather coverage from.

- Run `getfrida.sh`
- Compile the fafl-poc `make fafl-poc`
- Compile the vuln-tcp-server `make vuln-tcp-server`
- Compile just afl-fuzz
- Run the frida server `./frida-server-16.5.6-linux-x86_64`
- `mkdir in; echo "CIAO" > in/1`
- `touch crashshmfile` `touch shmfile`
- Then `fafl-net` can be run and it should find the infamous vuln-tcp-server crash in a matter of time:

```
AFL_SKIP_BIN_CHECK=1 AFL_DEBUG=1 /home/ax/AFLplusplus/afl-fuzz -t 100000 -m 2048 -i ./in -o ./out -- ./fafl-poc 127.0.0.1:27042 $(pidof vuln-tcp-server) fafl-poc.js
```
- The payload that crashes the server will be written in `./CRASH.txt` also.

## References
- https://github.com/AFLplusplus/AFLplusplus/blob/stable/utils/afl_proxy/
- https://github.com/ttdennis/fpicker
