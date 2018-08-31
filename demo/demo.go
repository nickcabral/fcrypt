// Package demo contains some code I wrote while figuring out channels and goroutines. It uses the
// Resty HTTP REST lib, as well as my fcrypt lib.
package demo

import (
  "encoding/json"
  "sync"

  "github.com/go-resty/resty"
  "github.com/nickcabral/fcrypt"
)

// ProcessIncomingMsgs uses a get/lock goroutine pipeline to process incoming messages
func ProcessIncomingMsgs(dataDir string, msgCnt int) <-chan string {
  msgs := make(chan string, msgCnt)
  result := make(chan string, msgCnt)
  go getter(msgs, msgCnt)
  go locker(dataDir, msgs, result)
  return result
}

// UnlockMsgs decrypts the msg for each ID and returns its contents via the result channel
func UnlockMsgs(pw, dataDir string, msgIDs []string) <-chan string {
  result := make(chan string, len(msgIDs))
  go func() {
    if fc, err := fcrypt.Load(dataDir); err == nil {
      for _, id := range msgIDs {
        if data, err := fc.Decrypt(pw, id); err == nil {
          result <- string(data[:])
        }
      }
    }
    close(result)
  }()
  return result
}

// getter GETs each plaintext msg via HTTP (with resty), deserializes it, and put it on the msgs chan
func getter(msgs chan<- string, count int) {
  // a WaitGroup is used to track completion of HTTP requests
  var httpWg sync.WaitGroup
  httpWg.Add(count)

  // after GETs are complete, close the msgs channel, and signal 'getter' completion
  defer close(msgs)
  defer httpWg.Wait()

  // GET each msg using the resty lib and pass its deserialized contents to the msgs chan
  for i := 0; i < count; i++ {
    go func() {
      defer httpWg.Done()
      // this gets 8 sentences of nonsense from an endpoint designed for that purpose
      resp, _ := resty.R().Get("https://baconipsum.com/api/?type=meat-and-filler&sentences=8")
      msg := make([]string, 0)
      json.Unmarshal([]byte(resp.String()), &msg)
      if len(msg) > 0 {
        msgs <- msg[0]
      }
    }()
  }
}

// locker encrypts each msg and puts its ID onto the result chan
func locker(dataDir string, msgs <-chan string, result chan<- string) {
  if fc, err := fcrypt.Load(dataDir); err == nil {
    for msg := range msgs {
      id, _ := fc.Encrypt([]byte(msg))
      result <- id
    }
  }
  close(result)
}
