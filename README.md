# fcrypt
fcrypt (short for file-encrypter) is a library that provides a simple API for encrypting files on
the local filesystem. It is a work in progress, and not ready for production use. The encrypted data
is encoded similarly to encrypted JSON web tokens (JWEs).
- fcrypt maintains an RSA keypair for each initialized directory.
- The private key is encrypted with AES256 using a client-provided password; client code needs to
store this password securely (eg. in their user's head) because it's required for decryption.
- Files are encrypted using a randomly generated 256 bit key and AES GCM. The password is not
required to encrypt files.
- The content encryption key is encrypted using the RSA public key.
- The encrypted content is written to the initialized directory along with its ECEK.
- To decrypt a file, client code provides the password and the original filename.
- The file's ECEK is decrypted using the RSA private key and the password.
- The content is then decrypted using the CEK, and the original file is restored.

## Installation
`go get github.com/nickcabral/fcrypt`

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

### Encrypt a file
``` go
err := cfg.Encrypt(filePath)
```
This function returns `nil` if successful and an `error` otherwise. The original file is deleted
upon successful encryption.

### Decrypt a file
``` go
err := cfg.Decrypt(filePath)
```
This function returns `nil` if successful and an `error` otherwise. The encrypted data is deleted
upon successful restoration of the decrypted file.

## Test and Benchmark Execution
`sudo go test github.com/nickcabral/fcrypt -bench=.`

## Known Issues
- Duplicate file names are not allowed; need to add a UID-system for naming the encrypted data
- A mechanism for backing up keys is needed so that a corrupted private key doesn't result in data loss
- Could be smarter about handling really large files to speed things up.
- Need to change to a secure deletion alg.