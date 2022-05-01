package node

import (
	"fmt"
	"testing"
)

func TestServe(t *testing.T) {
	degree := 1
	counter := 3*degree + 1
	p := make([]Node, counter)
	fmt.Printf("len(p): %v\n", len(p))
	metadataPath := "../metadata"
	for label := 0; label < counter; label++ {
		var err error
		p[label], err = New(degree, label, counter, metadataPath)
		if err != nil {
			fmt.Println("err in New:", err)
		}
	}
	for label := 0; label < counter; label++ {
		fmt.Printf("p[%v] trying to serve\n", label)
		p[label].Serve(false)
		fmt.Printf("p[%v] serving now\n", label)
	}

	fmt.Printf("success \n")
}
