package core

import (
	"fmt"
	"testing"
)

func TestMakeReceiveChannel(t *testing.T) {
	port := "8882"
	receiveChannel := MakeReceiveChannel(port)

	m := <-(receiveChannel)
	fmt.Println("The Message Received from channel is")
	fmt.Println("id==", m.Type)
	fmt.Println("sender==", m.Sender)
	fmt.Println("len==", len(m.Data))

}
