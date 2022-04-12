package main

import (
	"Buada_BFT/pkg/core"
	"fmt"
)

func main() {
	port := "8882"
	receiveChannel := core.MakeReceiveChannel(port)
	for {
		m := <-(receiveChannel)
		fmt.Println("The Message Received from channel is")
		fmt.Println("id==", m.Type)
		fmt.Println("sender==", m.Sender)
		fmt.Println("len==", len(m.Data))
	}
}
