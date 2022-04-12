package core

import (
	"Buada_BFT/pkg/protobuf"
	"bytes"
	"encoding/binary"
	"log"
	"net"

	"google.golang.org/protobuf/proto"
)

//MAXMESSAGE is the size of channels
var MAXMESSAGE = 1024

//MakeSendChannel returns a channel to send messages to hostIP
func MakeSendChannel(hostIP string, hostPort string) chan *protobuf.Message {
	var addr *net.TCPAddr
	var conn *net.TCPConn
	var err1, err2 error
	//Retry to connet to node
	retry := true
	for retry {
		addr, err1 = net.ResolveTCPAddr("tcp4", hostIP+":"+hostPort)
		conn, err2 = net.DialTCP("tcp4", nil, addr)
		conn.SetKeepAlive(true)
		if err1 != nil || err2 != nil {
			log.Fatalln(err1)
			log.Fatalln(err2)
			retry = true
		} else {
			retry = false
		}
	}
	//Make the send channel and the handle func
	sendChannel := make(chan *protobuf.Message, MAXMESSAGE)
	go func(conn *net.TCPConn, channel chan *protobuf.Message) {
		for {
			//Pop protobuf.Message form sendchannel
			m := <-(channel)
			//Do Marshal
			byt, err1 := proto.Marshal(m)
			if err1 != nil {
				log.Fatalln(err1)
			}
			//Send bytes
			length := len(byt)
			_, err2 := conn.Write(IntToBytes(length))
			_, err3 := conn.Write(byt)
			if err2 != nil || err3 != nil {
				log.Fatalln("The send channel has bread down!", err2)
			}
		}
	}(conn, sendChannel)

	return sendChannel
}

//IntToBytes convert int to bytes
func IntToBytes(n int) []byte {
	data := uint32(n)
	bytebuf := bytes.NewBuffer([]byte{})
	binary.Write(bytebuf, binary.BigEndian, data)
	return bytebuf.Bytes()
}
