package party

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"sync"

	"github.com/DyCAPSTeam/DyCAPS/pkg/protobuf"
	"github.com/DyCAPSTeam/DyCAPS/pkg/utils"
	"github.com/klauspost/reedsolomon"
	"google.golang.org/protobuf/proto"
)

// received message shard (RS code) in RBC
type mReceived struct {
	j  int
	mj []byte
}

//RBC propose
func (p *HonestParty) RBCSend(M *protobuf.Message, ID []byte) {
	//encapsulate
	data, _ := proto.Marshal(M)
	p.Broadcast(&protobuf.Message{Type: "RBCPropose", Sender: p.PID, Id: ID, Data: data})
	fmt.Println("party", p.PID, "broadcasts RBC's Propose Message, instance ID: ", string(ID))
}

func (p *HonestParty) RBCSendExclude(M *protobuf.Message, ID []byte, pid uint32) {
	//encapsulate
	data, _ := proto.Marshal(M)
	p.BroadcastExclude(&protobuf.Message{Type: "RBCPropose", Sender: p.PID, Id: ID, Data: data}, pid)
	fmt.Println("party", p.PID, "broadcasts RBC's Propose Message (excluding party", pid, "), instance ID: ", string(ID))
}

func (p *HonestParty) RBCReceive(ID []byte) *protobuf.Message {
	hLocal := sha256.New()
	var M1 = make([][]byte, p.N) //  M' in the RBC paper (line 9, Algo 4). Must assign length (or copy will fail)
	var mLen int                 // the length of M_i
	//here we ignore P(.)

	//handle RBCPropose message
	go func() {
		m := <-p.GetMessage("RBCPropose", ID)
		M := m.Data
		mLen = len(M) // the length of M is used to remove the padding zeros after RS decoding
		hLocal.Write(M)

		//TODO: Check if the usage of RS code is correct
		//encode
		RSEncoder, _ := reedsolomon.New(int(p.N-(p.F+1)), int(p.F+1))
		shards, _ := RSEncoder.Split(M)
		RSEncoder.Encode(shards)
		//copy, avoid "M1" becoming nullPointer when "shards" is released at the end of this goroutine
		copy(M1, shards)
		for j := uint32(0); j < p.N; j++ {
			//encapsulate, append the length of M at the end of hash
			EchoData, _ := proto.Marshal(&protobuf.RBCEcho{Hash: append(hLocal.Sum(nil), utils.IntToBytes(mLen)...), M: shards[j]})
			p.Send(&protobuf.Message{Type: "RBCEcho", Sender: p.PID, Id: ID, Data: EchoData}, j)

			/*
				// This block is used for RBC_test when a party does not receive 2t+1 ECHO messages
				// In this case, the algorithm sends RBCReady message through line 15 upon receiving
				// t+1 RBCReady messages and t+1 matching RBCEcho messages

				if p.PID == 0 || p.PID == 1 {
					if j != uint32(2) {
						p.Send(&protobuf.Message{Type: "RBCEcho", Sender: p.PID, Id: ID, Data: EchoData}, j)
					}
				} else {
					p.Send(&protobuf.Message{Type: "RBCEcho", Sender: p.PID, Id: ID, Data: EchoData}, j)
				}
			*/
		}

	}()

	//map (hash,M) to counter. Key value doesn't support []byte, so we transform it to string type.
	var EchoMessageMap = make(map[string]map[string]int)

	//T_h in line 16, Algo 4, RBC paper. T maps the hash to []m_received = {(j,mj), ...}
	var T = make(map[string][]mReceived)
	var MaxReadyNumber = int(0)
	var MaxReadyHash []byte

	var isReadySent = false
	var mutex sync.Mutex // isReadySent will be written by two goroutines. (line 11 and 13, Algo 4)
	var mutexEchoMap sync.Mutex
	var mutexReadyMap sync.Mutex

	var RSDecStart = make(chan bool, 1)
	// var RecDone = make(chan bool)

	//handle Echo Message, line 11-12, Algo 4 in RBC paper
	go func() {
		for {
			m := <-p.GetMessage("RBCEcho", ID)
			var payloadMessage protobuf.RBCEcho
			proto.Unmarshal(m.Data, &payloadMessage)
			hash := string(payloadMessage.Hash)
			mi := string(payloadMessage.M)
			mutexEchoMap.Lock()
			_, ok1 := EchoMessageMap[hash]
			if ok1 {
				//ok1 denotes that the map of hash exists
				counter, ok2 := EchoMessageMap[hash][mi]
				if ok2 {
					//ok2 denotes that the map of (hash,M) exists, then increase the counter
					EchoMessageMap[hash][mi] = counter + 1
				} else {
					//else establish the map of (hash,M) and set it as 1
					EchoMessageMap[hash][mi] = 1
				}
			} else {
				//else establish the map of (hash,M) and set it as 1
				EchoMessageMap[hash] = make(map[string]int)
				EchoMessageMap[hash][mi] = 1
			}

			//send RBCReady, upon receiving n-t=2f+1 matching RBCEcho messages and not having sent RBCReady (line 11-12, Algo 4)
			mutex.Lock()
			if uint32(EchoMessageMap[hash][mi]) >= p.N-p.F && !isReadySent {
				isReadySent = true
				readyData, _ := proto.Marshal(&protobuf.RBCReady{Hash: []byte(hash), M: []byte(mi)})
				p.Broadcast(&protobuf.Message{Type: "RBCReady", Sender: p.PID, Id: ID, Data: readyData})
			}
			mutex.Unlock()
			mutexEchoMap.Unlock()

			//finish this goroutine when RBCReady is sent
			if isReadySent {
				break
			}
		}
	}()

	//handle RBCReady messages
	go func() {
		for {
			m := <-p.GetMessage("RBCReady", ID)
			var payloadMessage protobuf.RBCReady
			proto.Unmarshal(m.Data, &payloadMessage)
			hash := payloadMessage.Hash
			hashString := string(hash)
			mJ := payloadMessage.M
			j := m.Sender //sender's pid, i.e., the index of the sender

			mutexReadyMap.Lock()
			_, ok := T[hashString]
			if ok {
				T[hashString] = append(T[hashString], mReceived{int(j), mJ})
			} else {
				T[hashString] = make([]mReceived, 0)
				T[hashString] = append(T[hashString], mReceived{int(j), mJ})
			}

			if len(T[hashString]) > MaxReadyNumber {
				MaxReadyNumber = len(T[hashString])
				MaxReadyHash = hash
			}

			//send RBCReady messages, line 13-15, Algo 4 in RBC paper
			mutex.Lock()
			if uint32(len(T[hashString])) >= p.F+1 && !isReadySent {
				for {
					mutexEchoMap.Lock()
					for m_i, count := range EchoMessageMap[hashString] {
						if uint32(count) >= p.F+1 {
							isReadySent = true
							readyData, _ := proto.Marshal(&protobuf.RBCReady{Hash: hash, M: []byte(m_i)})
							p.Broadcast(&protobuf.Message{Type: "RBCReady", Sender: p.PID, Id: ID, Data: readyData})
							fmt.Printf("%v has broadcast RBCReady\n", p.PID)
							break
						}
					}
					mutexEchoMap.Unlock()
					if isReadySent {
						break
					}
				}
			}
			mutex.Unlock()

			// upon receiving |T| >= 2t+1 = n-t
			if uint32(len(T[string(hash)])) == p.N-p.F {
				RSDecStart <- true
			}
			mutexReadyMap.Unlock()

			//FIXME: kill this for loop when the RBC message is reconstructed
			// isRec := <-RecDone
			// if isRec {
			// 	break
			// }
		}
	}()

	// wait for at least 2t+1 = n-t RS shards in T_h, i.e., T[string(hash)]
	<-RSDecStart
	for r := uint32(0); r <= p.F; r++ {
		for {
			if uint32(MaxReadyNumber) >= p.N-p.F+r {
				break
			}
		}

		var mReceivedTemp = make([]mReceived, p.N-p.F+r)
		mutexReadyMap.Lock()
		copy(mReceivedTemp, T[string(MaxReadyHash)])
		mutexReadyMap.Unlock()

		var M = make([][]byte, p.N)
		for i := uint32(0); i < p.N-p.F+r; i++ {
			M[mReceivedTemp[i].j] = mReceivedTemp[i].mj
		}

		RSEncoder, _ := reedsolomon.New(int(p.N-(p.F+1)), int(p.F+1))
		ok, _ := RSEncoder.Verify(M)
		if !ok {
			RSEncoder.Reconstruct(M)
		}

		//parse M and remove the padding zeros
		var mReconstructed = make([]byte, 0)
		for i := uint32(0); i < p.N-(p.F+1); i++ {
			mReconstructed = append(mReconstructed, M[i]...)
		}

		//the last several bytes in MaxReadyHash are the lenth of M' (see line 9, Algo 4 in RBC paper)
		mLenNew := utils.BytesToInt(MaxReadyHash[256/8:])
		//the first 256/8 bytes in MaxReadyHash are the hash value
		MaxReadyHash = MaxReadyHash[:256/8]
		mReconstructed = mReconstructed[0:mLenNew]

		hNew := sha256.New()
		hNew.Write(mReconstructed)

		if bytes.Compare(hNew.Sum(nil), MaxReadyHash) == 0 {
			var replyMessage protobuf.Message
			proto.Unmarshal(mReconstructed, &replyMessage)
			return &replyMessage
		}
	}
	return nil
}
