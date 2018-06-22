package fcrypt

import (
	"io/ioutil"
	"os"
	"path"
	"testing"
)

var encrypteddir = path.Join(os.TempDir(), "testdir")
var insecuredir = path.Join(os.TempDir(), "anothertestdir")
var unknowndir = path.Join(os.TempDir(), "_____dir")
var existingfile = path.Join(os.TempDir(), "anothertestdir/test1.txt")
var encrypteddatafile = path.Join(os.TempDir(), "testdir/test1.txt.json")
var content = "my secret message"

func TestMain(m *testing.M) {
	os.Mkdir(encrypteddir, 0644)
	os.Mkdir(insecuredir, 0644)
	ioutil.WriteFile(existingfile, []byte(content), 0644)

	result := m.Run()
	os.RemoveAll(encrypteddir)
	os.RemoveAll(insecuredir)
	os.RemoveAll(unknowndir)
	os.Exit(result)
}

func TestInit_NonExistentPath_Err(t *testing.T) {
	_, err := Init("pw", "____dir")
	if err == nil {
		t.Error()
	}
}

func TestInit_EmptyPassword_NoErr(t *testing.T) {
	_, err := Init("", encrypteddir)
	if err != nil {
		t.Error(err)
	}
}

func TestInit_GoodPath_NoErr(t *testing.T) {
	_, err := Init("pw", encrypteddir)
	if err != nil {
		t.Error(err)
	}
}

func TestLoad_InitializedDir_NoErr(t *testing.T) {
	_, _ = Init("pw", encrypteddir)
	_, err := Load(encrypteddir)
	if err != nil {
		t.Error(err)
	}
}

func TestLoad_UninitializedDir_Err(t *testing.T) {
	_, err := Load(unknowndir)
	if err == nil {
		t.Error()
	}
}

func TestConfig_Encrypt_FileExists_NoErr(t *testing.T) {
	cfg, _ := Init("pw", encrypteddir)
	err := cfg.Encrypt(existingfile)
	if err != nil {
		t.Error(err)
	}
}

func TestConfig_Encrypt_FileExists_ExpectedEncryptedDataExists(t *testing.T) {
	cfg, _ := Init("pw", encrypteddir)
	_ = cfg.Encrypt(existingfile)
	if _, err := os.Stat(encrypteddatafile); err != nil {
		t.Error(err)
	}
}

func TestConfig_Encrypt_FileDoesntExist_Err(t *testing.T) {
	cfg, _ := Init("pw", encrypteddir)

	err := cfg.Encrypt("someotherfile")

	if err == nil {
		t.Error()
	}
}

func TestConfig_Decrypt_KnownFile_NoErr(t *testing.T) {
	cfg, _ := Init("pw", encrypteddir)
	_ = cfg.Encrypt(existingfile)

	err := cfg.Decrypt("pw", existingfile)

	if err != nil {
		t.Error(err)
	}
}

func TestConfig_Decrypt_KnownFile_ExpectedDataRestored(t *testing.T) {
	cfg, _ := Init("pw", encrypteddir)
	_ = cfg.Encrypt(existingfile)

	_ = cfg.Decrypt("pw", existingfile)

	if _, err := os.Stat(existingfile); err != nil {
		t.Error(err)
	}
}

func BenchmarkEncrypt_SmallFile(b *testing.B) {
	cfg, _ := Init("pw", encrypteddatafile)
	for i := 0; i < b.N; i++ {
		cfg.Encrypt(existingfile)
	}
}
