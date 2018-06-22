// Package fcrypt is a simple API for encrypting files on the local filesystem
package fcrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
)

const configFileName = "fcrypt-config.json"

// Config contains a private and public key pair, and a path to the encrypted data directory
type Config struct {
	privPem     *pem.Block
	pubPem      *pem.Block
	dataDirPath string
}

type configJSON struct {
	PrivPem string
	PubPem  string
}

type encryptedFileJSON struct {
	ECEK       string
	CipherText string
	Nonce      string
}

// Init dataDirPath for fcrypt storage by creating and storing an RSA key pair
func Init(pw, dataDirPath string) (config *Config, err error) {
	// generate a new RSA key pair
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to create RSA key: %v", err)
	}

	// create a Config using the public key and an encrypted private key
	result := &Config{
		privPem:     &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)},
		pubPem:      &pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(&key.PublicKey)},
		dataDirPath: dataDirPath,
	}
	result.privPem, err = x509.EncryptPEMBlock(rand.Reader, result.privPem.Type, result.privPem.Bytes,
		[]byte(pw), x509.PEMCipherAES256)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt RSA private key: %v", err)
	}

	// write the keys to a config file in dataDirPath
	cfgJSON := configJSON{
		PrivPem: string(pem.EncodeToMemory(result.privPem)[:]),
		PubPem:  string(pem.EncodeToMemory(result.pubPem)[:]),
	}
	jsonBytes, err := json.Marshal(cfgJSON)
	if err := ioutil.WriteFile(filepath.Join(dataDirPath, configFileName), jsonBytes, os.ModePerm); err != nil {
		return nil, fmt.Errorf("failed to store configuration: %v", err)
	}
	return result, nil
}

// Load a Config from dataDirPath, which should have already been initialized
func Load(dataDirPath string) (config *Config, err error) {
	// load the config json into memory
	byteArr, err := ioutil.ReadFile(filepath.Join(dataDirPath, configFileName))
	if err != nil {
		return nil, fmt.Errorf("failed to read configuration file: %v", err)
	}
	cfgJSON := &configJSON{}
	if err = json.Unmarshal(byteArr, cfgJSON); err != nil {
		return nil, fmt.Errorf("failed to parse configuration json: %v", err)
	}

	// decode the private and public pem files
	pubPem, _ := pem.Decode([]byte(cfgJSON.PubPem))
	if pubPem == nil {
		return nil, fmt.Errorf("invalid public key data")
	}
	privPem, _ := pem.Decode([]byte(cfgJSON.PrivPem))
	if privPem == nil {
		return nil, fmt.Errorf("invalid private key data")
	}
	return &Config{privPem, pubPem, dataDirPath}, nil
}

// Encrypt the file at fPath and store the encrypted data at cfg.DataDirPath, then deleted fPath
func (cfg *Config) Encrypt(fPath string) error {
	// load public key
	pubKey, err := x509.ParsePKCS1PublicKey(cfg.pubPem.Bytes)
	if err != nil {
		return fmt.Errorf("failed to read public key: %v", err)
	}

	// generate a random content encryption key (CEK) use it to encrypt the content
	cek := make([]byte, 32)
	rand.Read(cek)
	plaintext, err := ioutil.ReadFile(fPath)
	if err != nil {
		return fmt.Errorf("failed to read file: %v", err)
	}
	cipherBlock, err := aes.NewCipher(cek)
	if err != nil {
		return fmt.Errorf("failed to create AES cipher block: %v", err)
	}
	gcm, err := cipher.NewGCM(cipherBlock)
	if err != nil {
		return fmt.Errorf("failed to create GCM cipher: %v", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	rand.Read(nonce)
	cipherText := gcm.Seal(nil, nonce, plaintext, nil)

	// encrypt the CEK, then write the ECEK and cipher text to dataDirPath as JSON
	ecek, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey, cek, make([]byte, 0))
	if err != nil {
		return fmt.Errorf("failed to encrypt CEK: %v", err)
	}
	cipherJSON := encryptedFileJSON{
		ECEK:       base64.StdEncoding.EncodeToString(ecek),
		CipherText: base64.StdEncoding.EncodeToString(cipherText),
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
	}
	jsonBytes, _ := json.Marshal(cipherJSON)
	if err := ioutil.WriteFile(cfg.getOutFilePath(fPath), jsonBytes, os.ModePerm); err != nil {
		return fmt.Errorf("failed to store encrypted data: %v", err)
	}
	if err = os.Remove(fPath); err != nil {
		return fmt.Errorf("failed to delete the unencrypted file: %v", err)
	}
	return nil
}

// Decrypt the encrypted data that came from fPath and restore it to its original location; the
// encrypted datafile is deleted upon completion
func (cfg *Config) Decrypt(pw, fPath string) error {
	// load the cipher text JSON from disk
	byteArr, err := ioutil.ReadFile(cfg.getOutFilePath(fPath))
	if err != nil {
		return fmt.Errorf("failed to read the encrypted file: %v", err)
	}
	encFileJSON := &encryptedFileJSON{}
	if err = json.Unmarshal(byteArr, encFileJSON); err != nil {
		return fmt.Errorf("failed to parse the encrypted data file: %v", err)
	}

	// unencrypt the private key and load it
	privPEM, err := x509.DecryptPEMBlock(cfg.privPem, []byte(pw))
	if err != nil {
		return fmt.Errorf("failed to decrypt RSA private key; bad password? : %v", err)
	}
	privKey, _ := x509.ParsePKCS1PrivateKey(privPEM)

	// use the private key to decrypt the ECEK
	ecekBytes, _ := base64.StdEncoding.DecodeString(encFileJSON.ECEK)
	cek, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privKey, ecekBytes, make([]byte, 0))
	if err != nil {
		return fmt.Errorf("failed to decrypt CEK: %v", err)
	}

	// use the CEK to decrypt the content and write it to its original location
	cipherBlock, err := aes.NewCipher(cek)
	if err != nil {
		return fmt.Errorf("failed to create AES cipher block: %v", err)
	}
	gcm, err := cipher.NewGCM(cipherBlock)
	if err != nil {
		return fmt.Errorf("failed to create GCM cipher: %v", err)
	}
	nonce, _ := base64.StdEncoding.DecodeString(encFileJSON.Nonce)
	cipherText, _ := base64.StdEncoding.DecodeString(encFileJSON.CipherText)
	plainText, err := gcm.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return fmt.Errorf("failed to decrypt the file content: %v", err)
	}
	if err := ioutil.WriteFile(fPath, plainText, os.ModePerm); err != nil {
		return fmt.Errorf("failed to write the decrypted file: %v", err)
	}
	if err = os.Remove(cfg.getOutFilePath(fPath)); err != nil {
		return fmt.Errorf("failed to delete the encrypted file: %v", err)
	}
	return nil
}

// getOutFilePath takes a file path as it would be received from a client and returns
// the path to the corresponding JSON file with the input-file's encrypted data
func (cfg *Config) getOutFilePath(inPath string) string {
	return fmt.Sprintf("%v.json", filepath.Join(cfg.dataDirPath, filepath.Base(inPath)))
}
