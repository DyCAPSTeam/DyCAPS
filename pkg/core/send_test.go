package core

// import (
// 	"fmt"
// 	"testing"
// 	"time"

// 	"github.com/DyCAPSTeam/DyCAPS/pkg/protobuf"
// )

// func TestMakeSendChannel(t *testing.T) {
// 	receiveChannel := MakeReceiveChannel("8882")
// 	m := <-(receiveChannel)
// 	fmt.Println("The Message Received from channel is")
// 	fmt.Println("id==", m.Type)
// 	fmt.Println("sender==", m.Sender)
// 	fmt.Println("len==", len(m.Data))

// 	hostIP := "127.0.0.1"
// 	hostPort := "8882"

// 	sendChannel := MakeSendChannel(hostIP, hostPort)
// 	fmt.Println("sendchannel:", sendChannel)

// 	for i := 0; i < 100; i++ {
// 		m := &protobuf.Message{
// 			Type:   "Alice",
// 			Sender: uint32(i),
// 			Data:   make([]byte, 10000000),
// 		}
// 		(sendChannel) <- m
// 		time.Sleep(time.Duration(1) * time.Second)
// 	}
// 	for {

// 	}

// }
