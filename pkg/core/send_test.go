package core

import (
	"Buada_BFT/pkg/protobuf"
	"fmt"
	"testing"
	"time"
)

func TestMakeSendChannel(t *testing.T) {
	hostIP := "127.0.0.1"
	hostPort := "8882"

	sendChannel := MakeSendChannel(hostIP, hostPort)
	fmt.Println(sendChannel)

	for i := 0; i < 100; i++ {
		m := &protobuf.Message{
			Type:   "Alice",
			Sender: uint32(i),
			Data:   make([]byte, 10000000),
		}
		(sendChannel) <- m
		time.Sleep(time.Duration(1) * time.Second)
	}
	for {

	}

}
