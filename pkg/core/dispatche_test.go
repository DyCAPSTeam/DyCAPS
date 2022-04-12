package core

import (
	"sync"
	"testing"
)

var wg1 = sync.WaitGroup{}
var wg2 = sync.WaitGroup{}

func TestDispatche(t *testing.T) {
	// wg1.Add(1)
	// wg2.Add(1)
	// go func() {
	// 	port := "8882"
	// 	receiveChannel := MakeReceiveChannel(port)
	// 	dispatcheChannels := MakeDispatcheChannels(receiveChannel, 2)
	// 	wg1.Done()

	// 	aliceChannel := GetDispatcheChannel("Alice", []byte{0}, dispatcheChannels[0])

	// 	m := <-aliceChannel
	// 	if m.Type != "Alice" {
	// 		t.Errorf("aliceChannel failed")
	// 	}

	// 	m = <-aliceChannel
	// 	if m.Type != "Alice" {
	// 		t.Errorf("aliceChannel failed")
	// 	}

	// 	bobChannel := GetDispatcheChannel("Bob", []byte{0}, dispatcheChannels[1])

	// 	m = <-bobChannel
	// 	if m.Type != "Bob" {
	// 		t.Errorf("bobChannel failed")
	// 	}

	// 	m = <-bobChannel
	// 	if m.Type != "Bob" {
	// 		t.Errorf("bobChannel failed")
	// 	}
	// 	wg2.Done()
	// }()

	// wg1.Wait()
	// hostIP := "127.0.0.1"
	// hostPort := "8882"

	// sendChannel := MakeSendChannel(hostIP, hostPort)

	// for i := 0; i < 2; i++ {
	// 	m := &protobuf.Message{
	// 		Type:   "Alice",
	// 		Sender: uint32(0),
	// 		Data:   make([]byte, 10),
	// 	}
	// 	(sendChannel) <- m
	// 	time.Sleep(time.Duration(1) * time.Second)
	// }

	// for i := 0; i < 2; i++ {
	// 	m := &protobuf.Message{
	// 		Type:   "Bob",
	// 		Sender: uint32(1),
	// 		Data:   make([]byte, 10),
	// 	}
	// 	(sendChannel) <- m
	// 	time.Sleep(time.Duration(1) * time.Second)
	// }

	// wg2.Wait()
}
