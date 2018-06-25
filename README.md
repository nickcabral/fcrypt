[![Go Report Card](https://goreportcard.com/badge/github.com/nickcabral/fcrypt)](https://goreportcard.com/report/github.com/nickcabral/fcrypt)
[![GoDoc](https://godoc.org/github.com/nickcabral/fcrypt?status.svg)](https://godoc.org/github.com/nickcabral/fcrypt)
# fcrypt
fcrypt is a library for storing encrypted data on the local filesystem.

## Installation
``` sh
go get github.com/nickcabral/fcrypt
```

## Usage
### Initialize an existing filesystem directory for fcrypt use
``` go
cfg, err := fcrypt.Init(directoryPath)
```
The desired directory must already exist. This function returns a `Config` that is used to
call `Encrypt()` and `Decrypt()`
### Load an existing fcrypt directory
```go
cfg, err := fcrypt.Load(directoryPath)
```
This function returns a `Config` that is used to call `Encrypt()` and `Decrypt()`

### Encrypt data
``` go
id, err := cfg.Encrypt(dataBytes)
```
This function returns an ID for the data if successful and an `error` otherwise.

### Decrypt data
``` go
dataBytes, err := cfg.Decrypt(pw, dataID)
```
This function returns the plaintext data if successful and an `error` otherwise. The encrypted data
is deleted upon successful decryption of the data.

## How does it work?
- fcrypt maintains an RSA keypair for each initialized directory.
- The private key is encrypted with AES256 using a client-provided password; client code needs to
store this password securely (eg. in their user's head) because it's required for decryption.
- Data is encrypted using a randomly generated 256 bit key and AES GCM. The password is not
required to encrypt data.
- The content encryption key is encrypted using the RSA public key.
- The encrypted content is written to the initialized directory along with its ECEK.
- To decrypt data, client code provides the password and the data ID.
- The data's ECEK is decrypted using the RSA private key and the password.
- The content is then decrypted using the CEK and it is returned to the caller.

## Test and Benchmark Execution
Just tests:
``` sh
go test github.com/nickcabral/fcrypt
```
Just benchmarks:
``` sh
go test github.com/nickcabral/fcrypt -bench=. -run=XXX
```

## Known Issues
- A mechanism for backing up keys is needed so that a corrupted private key doesn't result in data loss
- Could be smarter about handling really large data to speed things up.

## License 
See [LICENSE](https://github.com/nickcabral/fcrypt/LICENSE) file.