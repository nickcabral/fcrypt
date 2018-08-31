package fcrypt

import (
  "fmt"
  "io/ioutil"
  "math/rand"
  "os"
  "path"
  "reflect"
  "testing"
)

const unknowndir = "_____dir"
const pw = "pw"

var cfg *Config
var encrypteddir string
var content = []byte("secret message")

func setup() {
  encrypteddir, _ = ioutil.TempDir("", "")
  cfg, _ = Init(pw, encrypteddir)
}

func teardown() {
  os.RemoveAll(encrypteddir)
  os.RemoveAll(unknowndir)
}

func TestInit_NonExistentPath_Err(t *testing.T) {
  setup()
  defer teardown()
  if _, err := Init(pw, unknowndir); err == nil {
    t.Error()
  }
}

func TestInit_EmptyPassword_NoErr(t *testing.T) {
  setup()
  defer teardown()
  if _, err := Init("", encrypteddir); err != nil {
    t.Error(err)
  }
}

func TestInit_GoodPath_NoErr(t *testing.T) {
  setup()
  defer teardown()
  if _, err := Init(pw, encrypteddir); err != nil {
    t.Error(err)
  }
}

func TestLoad_InitializedDir_NoErr(t *testing.T) {
  setup()
  defer teardown()
  if _, err := Load(encrypteddir); err != nil {
    t.Error(err)
  }
}

func TestLoad_UninitializedDir_Err(t *testing.T) {
  setup()
  defer teardown()
  if _, err := Load(unknowndir); err == nil {
    t.Error(err)
  }
}

func TestConfig_Encrypt_GoodData_NoErr(t *testing.T) {
  setup()
  defer teardown()
  _, err := cfg.Encrypt(content)
  if err != nil {
    t.Error(err)
  }
}

func TestConfig_Encrypt_GoodData_ExpectedEncryptedDataExists(t *testing.T) {
  setup()
  defer teardown()
  id, _ := cfg.Encrypt(content)
  if _, err := os.Stat(path.Join(encrypteddir, fmt.Sprintf("%v.json", id))); err != nil {
    t.Error(err)
  }
}

func TestConfig_Encrypt_NilContent_NoErr(t *testing.T) {
  setup()
  defer teardown()
  if _, err := cfg.Encrypt(nil); err != nil {
    t.Error(err)
  }
}

func TestConfig_Decrypt_KnownIDGoodPassword_NoErr(t *testing.T) {
  setup()
  defer teardown()
  id, _ := cfg.Encrypt(content)
  if _, err := cfg.Decrypt(pw, id); err != nil {
    t.Error(err)
  }
}

func TestConfig_Decrypt_KnownIDGoodPassword_ExpectedDataReturned(t *testing.T) {
  setup()
  defer teardown()
  id, _ := cfg.Encrypt(content)
  result, _ := cfg.Decrypt(pw, id)
  if !reflect.DeepEqual(result, content) {
    t.Error()
  }
}

func TestConfig_Decrypt_KnownIDBadPassword_DataNotDecrypted(t *testing.T) {
  setup()
  defer teardown()
  id, _ := cfg.Encrypt(content)
  if data, _ := cfg.Decrypt("wrong password", id); data != nil {
    t.Error()
  }
  if _, err := os.Stat(path.Join(encrypteddir, fmt.Sprintf("%v.json", id))); err != nil {
    t.Error(err)
  }
}

func TestConfig_Decrypt_KnownIDBadPassword_Err(t *testing.T) {
  setup()
  defer teardown()
  id, _ := cfg.Encrypt(content)
  if _, err := cfg.Decrypt("wrong password", id); err == nil {
    t.Error(err)
  }
}

func BenchmarkEncrypt_64BFile(b *testing.B) {
  benchmarkEncrypt(b, 1<<6)
}

func BenchmarkEncrypt_16KBFile(b *testing.B) {
  benchmarkEncrypt(b, 1<<14)
}

func BenchmarkEncrypt_4MBFile(b *testing.B) {
  benchmarkEncrypt(b, 1<<22)
}

func BenchmarkEncrypt_1GBFile(b *testing.B) {
  benchmarkEncrypt(b, 1<<30)
}

func BenchmarkDecrypt_64BFile(b *testing.B) {
  benchmarkDecrypt(b, 1<<6)
}

func BenchmarkDecrypt_16KBFile(b *testing.B) {
  benchmarkDecrypt(b, 1<<14)
}

func BenchmarkDecrypt_4MBFile(b *testing.B) {
  benchmarkDecrypt(b, 1<<22)
}

func BenchmarkDecrypt_1GBFile(b *testing.B) {
  benchmarkDecrypt(b, 1<<30)
}

func benchmarkEncrypt(b *testing.B, dataLength uint64) {
  setupBenchmark(b, dataLength)
  defer teardown()
  for i := 0; i < b.N; i++ {
    b.StartTimer()
    cfg.Encrypt(content)
    b.StopTimer()
  }
}

func benchmarkDecrypt(b *testing.B, dataLength uint64) {
  setupBenchmark(b, dataLength)
  defer teardown()

  ids := make([]string, b.N)
  for idx := range ids {
    ids[idx], _ = cfg.Encrypt(content)
  }
  for i := 0; i < b.N; i++ {
    b.StartTimer()
    cfg.Decrypt(pw, ids[i])
    b.StopTimer()
  }
}

func setupBenchmark(b *testing.B, dataLength uint64) {
  b.StopTimer()
  b.ResetTimer()
  setup()
  content = make([]byte, dataLength)
  rand.Read(content)
}
