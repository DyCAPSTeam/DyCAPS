package core

import (
	"Buada_BFT/pkg/protobuf"
	"bytes"
	"encoding/binary"
	"io"
	"log"
	"net"

	"google.golang.org/protobuf/proto"
)

//MakeReceiveChannel returns a channel receiving messages
func MakeReceiveChannel(port string) chan *protobuf.Message {
	var addr *net.TCPAddr
	var lis *net.TCPListener
	var err1, err2 error
	retry := true
	//Retry to make listener
	for retry {
		addr, err1 = net.ResolveTCPAddr("tcp4", ":"+port)
		lis, err2 = net.ListenTCP("tcp4", addr)
		if err1 != nil || err2 != nil {
			log.Fatalln(err1)
			log.Fatalln(err2)
			retry = true
		} else {
			retry = false
		}
	}
	//Make the receive channel and the handle func
	var conn *net.TCPConn
	var err3 error
	receiveChannel := make(chan *protobuf.Message, MAXMESSAGE)
	go func() {
		for {
			//The handle func run forever
			conn, err3 = lis.AcceptTCP()
			conn.SetKeepAlive(true)
			if err3 != nil {
				log.Fatalln(err3)
			}
			//Once connect to a node, make a sub-handle func to handle this connection
			go func(conn *net.TCPConn, channel chan *protobuf.Message) {
				for {
					//Receive bytes
					lengthBuf := make([]byte, 4)
					_, err1 := io.ReadFull(conn, lengthBuf)
					length := BytesToInt(lengthBuf)
					buf := make([]byte, length)
					_, err2 := io.ReadFull(conn, buf)
					if err1 != nil || err2 != nil {
						log.Fatalln("The receive channel has bread down", err1, err2)
					}
					//Do Unmarshal
					var m protobuf.Message
					err3 := proto.Unmarshal(buf, &m)
					if err3 != nil {
						log.Fatalln(err3)
					}
					//Push protobuf.Message to receivechannel
					(channel) <- &m
				}

			}(conn, receiveChannel)
		}
	}()
	return receiveChannel
}

//BytesToInt convert bytes to int
func BytesToInt(byt []byte) int {
	bytebuff := bytes.NewBuffer(byt)
	var data uint32
	binary.Read(bytebuff, binary.BigEndian, &data)
	return int(data)
}
