package core

import (
	"Buada_BFT/pkg/protobuf"
	"sync"
)

// MakeDispatcheChannels dispatche messages from receiveChannel
// and make a double layer Map : (messageType) --> (id) --> (channel)
func MakeDispatcheChannels(receiveChannel chan *protobuf.Message, N uint32) []*sync.Map {
	dispatcheChannels := make([]*sync.Map, N)
	for i := uint32(0); i < N; i++ {
		dispatcheChannels[i] = new(sync.Map)
	}

	go func() { //dispatcher
		for {
			m := <-(receiveChannel)
			value, ok1 := dispatcheChannels[m.Sender].Load(m.Type)

			var channel chan *protobuf.Message
			var tmpMap *sync.Map
			if !ok1 { //first time receive message (m.Type, m.Id, *) form m.sender
				tmpMap = new(sync.Map)
				dispatcheChannels[m.Sender].Store(m.Type, tmpMap)
				channel = make(chan *protobuf.Message, 1)
				tmpMap.Store(string(m.Id), channel)
				channel <- m
			} else {
				tmpMap = value.(*sync.Map)
				_, ok2 := tmpMap.Load(string(m.Id))
				if !ok2 { //first time receive message (m.Type, m.Id, *) form m.sender
					channel = make(chan *protobuf.Message, 1)
					tmpMap.Store(string(m.Id), channel)
					channel <- m
				} else { //m.sender reply message (m.Type, m.Id, *)
					//reply attack
					//drop this message
				}
			}
		}
	}()
	return dispatcheChannels
}

//GetDispatcheChannel TRY to get a distinct channel in a dispatcheChannels map according to messageType and instance id
func GetDispatcheChannel(messageType string, ID []byte, dispatcheChannels *sync.Map) (chan *protobuf.Message, bool) {
	var dispatcheChannel chan *protobuf.Message
	value1, ok1 := dispatcheChannels.Load(messageType)
	if ok1 {
		tmpMap := value1.(*sync.Map)
		value2, ok2 := tmpMap.Load(string(ID))
		if ok2 {
			dispatcheChannel = value2.(chan *protobuf.Message)
			return dispatcheChannel, true
		}
		return nil, false

	}
	return nil, false
}
