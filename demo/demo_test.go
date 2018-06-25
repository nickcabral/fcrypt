package demo

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/nickcabral/fcrypt"
)

const pw = "password!"

var dataDir string

func setup() {
	dataDir, _ = ioutil.TempDir("", "")
	_, _ = fcrypt.Init(pw, dataDir)
}

func teardown() {
	os.RemoveAll(dataDir)
}

func TestProcessIncomingMsgs_DataDirInitialized_ReturnsExpectedNumberOfIDs(t *testing.T) {
	setup()
	defer teardown()
	receiveCnt := 0
	for range ProcessIncomingMsgs(dataDir, 5) {
		receiveCnt++
	}
	if receiveCnt != 5 {
		t.Error(receiveCnt)
	}
}

func TestProcessIncomingMsgs_NoMessagesRequested_NoIDsReturned(t *testing.T) {
	setup()
	defer teardown()
	receiveCnt := 0
	for range ProcessIncomingMsgs(dataDir, 0) {
		receiveCnt++
	}
	if receiveCnt != 0 {
		t.Error(receiveCnt)
	}
}

func TestProcessIncomingMsgs_UnknownDataDir_NoIDsReturned(t *testing.T) {
	setup()
	defer teardown()
	uninitializedDir, _ := ioutil.TempDir("", "")
	defer os.RemoveAll(uninitializedDir)
	receiveCnt := 0
	for range ProcessIncomingMsgs(uninitializedDir, 5) {
		receiveCnt++
	}
	if receiveCnt != 0 {
		t.Error(receiveCnt)
	}
}

func TestUnlockMsgs_ValidArgs_ReturnsExpectedData(t *testing.T) {
	setup()
	defer teardown()
	ids := ProcessIncomingMsgs(dataDir, 5)

	for id := range ids {
		if _, ok := <-UnlockMsgs(pw, dataDir, []string{id}); !ok {
			t.Error()
		}
	}
}

func TestUnlockMsgs_WrongPassword_ReturnsNoData(t *testing.T) {
	setup()
	defer teardown()
	ids := ProcessIncomingMsgs(dataDir, 5)

	for id := range ids {
		if _, ok := <-UnlockMsgs("another password", dataDir, []string{id}); ok {
			t.Error()
		}
	}
}

func BenchmarkProcessIncomingMsgs_100Msgs(b *testing.B) {
	benchmarkProcessIncomingMsgs(100, b)
}

func BenchmarkProcessIncomingMsgs_1000Msgs(b *testing.B) {
	benchmarkProcessIncomingMsgs(1000, b)
}

func BenchmarkProcessIncomingMsgs_10000Msgs(b *testing.B) {
	benchmarkProcessIncomingMsgs(10000, b)
}

func BenchmarkProcessIncomingMsgs_100000Msgs(b *testing.B) {
	benchmarkProcessIncomingMsgs(100000, b)
}

func benchmarkProcessIncomingMsgs(count int, b *testing.B) {
	setup()
	defer teardown()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StartTimer()
		for range <-ProcessIncomingMsgs(dataDir, count) {
		}
		b.StopTimer()
	}
}
