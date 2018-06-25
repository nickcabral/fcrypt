This package contains some code I wrote while figuring out channels and goroutines. It uses the
Resty HTTP REST lib, as well as my fcrypt lib.

Function `ProcessIncomingMsgs` uses a goroutine pipeline to GET and encrypt incoming messages.

Function `UnlockMsgs` decrypts messages and returns their contents via the result channel.

To run the tests and benchmarks:
``` sh
go test github.com/nickcabral/fcrypt/demo -bench=.
```