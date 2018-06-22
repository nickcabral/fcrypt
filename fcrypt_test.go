package fcrypt

import (
	"crypto/rand"
	"io/ioutil"
	"os"
	"path"
	"testing"
)

const unknowndir = "_____dir"
const pw = "pw"
const content = "secret message"

var cfg *Config
var encrypteddir string
var insecuredir string
var existingfile string
var encrypteddatafile string

func setup() {
	encrypteddir, _ = ioutil.TempDir("", "")
	insecuredir, _ = ioutil.TempDir("", "")
	existingfile = path.Join(insecuredir, "test.txt")
	encrypteddatafile = path.Join(encrypteddir, "test.txt.json")
	ioutil.WriteFile(existingfile, []byte(content), os.ModePerm)
	cfg, _ = Init(pw, encrypteddir)
}

func teardown() {
	os.RemoveAll(encrypteddir)
	os.RemoveAll(insecuredir)
	os.RemoveAll(unknowndir)
}

func TestInit_NonExistentPath_Err(t *testing.T) {
	_, err := Init(pw, unknowndir)

	if err == nil {
		t.Error()
	}
	teardown()
}

func TestInit_EmptyPassword_NoErr(t *testing.T) {
	_, err := Init("", encrypteddir)

	if err != nil {
		t.Error(err)
	}
	teardown()
}

func TestInit_GoodPath_NoErr(t *testing.T) {
	_, err := Init(pw, encrypteddir)

	if err != nil {
		t.Error(err)
	}
	teardown()
}

func TestLoad_InitializedDir_NoErr(t *testing.T) {
	setup()

	if _, err := Load(encrypteddir); err != nil {
		t.Error(err)
	}
	teardown()
}

func TestLoad_UninitializedDir_Err(t *testing.T) {
	setup()

	if _, err := Load(unknowndir); err == nil {
		t.Error()
	}
	teardown()
}

func TestConfig_Encrypt_FileExists_NoErr(t *testing.T) {
	setup()

	err := cfg.Encrypt(existingfile)

	if err != nil {
		t.Error(err)
	}
	teardown()
}

func TestConfig_Encrypt_FileExists_ExpectedEncryptedDataExists(t *testing.T) {
	setup()

	_ = cfg.Encrypt(existingfile)

	if _, err := os.Stat(encrypteddatafile); err != nil {
		t.Error(err)
	}
	teardown()
}

func TestConfig_Encrypt_FileDoesntExist_Err(t *testing.T) {
	setup()

	if err := cfg.Encrypt("someotherfile"); err == nil {
		t.Error()
	}
	teardown()
}

func TestConfig_Decrypt_KnownFileGoodPassword_NoErr(t *testing.T) {
	setup()
	_ = cfg.Encrypt(existingfile)

	if err := cfg.Decrypt(pw, existingfile); err != nil {
		t.Error(err)
	}
	teardown()
}

func TestConfig_Decrypt_KnownFileGoodPassword_ExpectedDataRestored(t *testing.T) {
	setup()
	_ = cfg.Encrypt(existingfile)

	_ = cfg.Decrypt(pw, existingfile)

	if _, err := os.Stat(existingfile); err != nil {
		t.Error(err)
	}
	if bytes, _ := ioutil.ReadFile(existingfile); string(bytes) != content {
		t.Error()
	}
	teardown()
}

func TestConfig_Decrypt_KnownFileBadPassword_DataNotDecrypted(t *testing.T) {
	setup()
	_ = cfg.Encrypt(existingfile)

	_ = cfg.Decrypt("wrong password", existingfile)

	if _, err := os.Stat(existingfile); err == nil {
		t.Error()
	}
	teardown()
}

func TestConfig_Decrypt_KnownFileBadPassword_Err(t *testing.T) {
	setup()
	_ = cfg.Encrypt(existingfile)

	if err := cfg.Decrypt("no good", existingfile); err == nil {
		t.Error()
	}
	teardown()
}

func BenchmarkEncrypt_4KBFile(b *testing.B) {
	setup()
	content := make([]byte, 1<<12)
	rand.Read(content)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		b.StopTimer()
		ioutil.WriteFile(existingfile, []byte(content), os.ModePerm)
		b.StartTimer()

		cfg.Encrypt(existingfile)
	}
	b.StopTimer()
	teardown()
}

func BenchmarkEncrypt_1MBFile(b *testing.B) {
	setup()
	content := make([]byte, 1<<20)
	rand.Read(content)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		b.StopTimer()
		ioutil.WriteFile(existingfile, []byte(content), os.ModePerm)
		b.StartTimer()

		cfg.Encrypt(existingfile)
	}
	b.StopTimer()
	teardown()
}

func BenchmarkEncrypt_256MBFile(b *testing.B) {
	setup()
	content := make([]byte, 1<<28)
	rand.Read(content)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		b.StopTimer()
		ioutil.WriteFile(existingfile, []byte(content), os.ModePerm)
		b.StartTimer()

		cfg.Encrypt(existingfile)
	}
	b.StopTimer()
	teardown()
}

func BenchmarkDecrypt_4KBFile(b *testing.B) {
	setup()
	content := make([]byte, 1<<12)
	rand.Read(content)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		b.StopTimer()
		cfg.Encrypt(existingfile)
		b.StartTimer()

		cfg.Decrypt(pw, existingfile)
	}
	b.StopTimer()
	teardown()
}

func BenchmarkDecrypt_1MBFile(b *testing.B) {
	setup()
	content := make([]byte, 1<<20)
	rand.Read(content)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		b.StopTimer()
		cfg.Encrypt(existingfile)
		b.StartTimer()

		cfg.Decrypt(pw, existingfile)
	}
	b.StopTimer()
	teardown()
}

func BenchmarkDecrypt_256MBFile(b *testing.B) {
	setup()
	content := make([]byte, 1<<28)
	rand.Read(content)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		b.StopTimer()
		cfg.Encrypt(existingfile)
		b.StartTimer()

		cfg.Decrypt(pw, existingfile)
	}
	b.StopTimer()
	teardown()
}
