# fcrypt
fcrypt (short for file-encrypter) is a library that provides a simple API for encrypting files on
the local filesystem. It is a work in progress, and not ready for production use. Data is stored
similarly to encrypted JSON web tokens.
- fcrypt maintains an RSA keypair for each initialized directory.
- The private key is encrypted with AES256 using a client-provided password; client needs to
store this password securely because it's required for decryption.
- Files are encrypted using a randomly generated 256 bit key (client does not need to
provide their password to encrypt files) and AES GCM.
- The content encryption key is encrypted using the RSA public key.
- The encrypted content is written to the initialized directory along with its ECEK.
- When client wants to decrypt files, the provide their password and the original filename.
- The file's ECEK is decrypted using the RSA private key and the client's password.
- Finally, the content is decrypted using the CEK, and the client's file is restored.

## Installation
`go get github.com/nickcabral/fcrypt`

## Usage
### Initialize a new fcrypt directory
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

## Test Execution
*NOTE: tests must be run with sudo until I figure out the golang file permission issue I'm stuck on*
`sudo go test github.com/nickcabral/fcrypt`

## Known Issues
- Duplicate file names are not allowed; need to add a UID-system for naming the encrypted data
- A mechanism for backing up keys is needed so that a corrupted private key doesn't result in data loss
- Could be smarter about handling really large files to speed things up.
- Need to use a secure deletion alg.