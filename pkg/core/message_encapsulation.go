package core

import (
	"Buada_BFT/pkg/protobuf"
	"log"

	"google.golang.org/protobuf/proto"
)

//Encapsulation encapsulates a message to a general type(*protobuf.Message)
func Encapsulation(messageType string, ID []byte, sender uint32, payloadMessage any) *protobuf.Message {
	switch messageType {
	case "Value":
		data, err := proto.Marshal((payloadMessage).(*protobuf.Value))
		if err != nil {
			log.Fatalln(err)
		}
		return &protobuf.Message{
			Type:   messageType,
			Id:     ID,
			Sender: sender,
			Data:   data,
		}
	case "Echo":
		data, err := proto.Marshal((payloadMessage).(*protobuf.Echo))
		if err != nil {
			log.Fatalln(err)
		}
		return &protobuf.Message{
			Type:   messageType,
			Id:     ID,
			Sender: sender,
			Data:   data,
		}
	default:
		data, err := proto.Marshal((payloadMessage).(*protobuf.Message))
		if err != nil {
			log.Fatalln(err)
		}
		return &protobuf.Message{
			Type:   "Default",
			Id:     ID,
			Sender: sender,
			Data:   data,
		}
	}

}

//Decapsulation decapsulates a message to it's original type
func Decapsulation(messageType string, m *protobuf.Message) any {
	switch messageType {
	case "Value":
		var payloadMessage protobuf.Value
		proto.Unmarshal(m.Data, &payloadMessage)
		return &payloadMessage
	case "Echo":
		var payloadMessage protobuf.Echo
		proto.Unmarshal(m.Data, &payloadMessage)
		return &payloadMessage
	default:
		var payloadMessage protobuf.Message
		proto.Unmarshal(m.Data, &payloadMessage)
		return &payloadMessage
	}
}
