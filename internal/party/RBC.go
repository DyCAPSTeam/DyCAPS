package party

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"sync"

	"github.com/DyCAPSTeam/DyCAPS/pkg/protobuf"
	"github.com/DyCAPSTeam/DyCAPS/pkg/utils"
	"github.com/golang/protobuf/proto"
	"github.com/klauspost/reedsolomon"
)

// received message shard (RS code) in RBC
type m_received struct {
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
	h_local := sha256.New()
	var M1 = make([][]byte, p.N) //  M' in the RBC paper (line 9, Algo 4). Must assign length (or copy will fail)
	var mlen int                 // the length of M_i
	//here we ignore P(.)

	//handle RBCPropose message
	go func() {
		m := <-p.GetMessage("RBCPropose", ID)
		M := m.Data
		mlen = len(M) // the length of M is used to remove the padding zeros after RS decoding
		h_local.Write(M)

		//TODO: Check if the usage of RS code is correct
		//encode
		RSEncoder, _ := reedsolomon.New(int(p.N-(p.F+1)), int(p.F+1))
		shards, _ := RSEncoder.Split(M)
		RSEncoder.Encode(shards)
		//copy, avoid "M1" becoming nullPointer when "shards" is released at the end of this goroutine
		copy(M1, shards)
		for j := uint32(0); j < p.N; j++ {
			//encapsulate, append the length of M at the end of hash
			EchoData, _ := proto.Marshal(&protobuf.RBCEcho{Hash: append(h_local.Sum(nil), utils.IntToBytes(mlen)...), M: shards[j]})
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
	var T = make(map[string][]m_received)
	var MaxReadyNumber = int(0)
	var MaxReadyHash []byte

	var isReadySent = false
	var mutex sync.Mutex // isReadySent will be written by two goroutines. (line 11 and 13, Algo 4)
	var mutex_EchoMap sync.Mutex
	var mutex_ReadyMap sync.Mutex

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
			mutex_EchoMap.Lock()
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
				ready_data, _ := proto.Marshal(&protobuf.RBCReady{Hash: []byte(hash), M: []byte(mi)})
				p.Broadcast(&protobuf.Message{Type: "RBCReady", Sender: p.PID, Id: ID, Data: ready_data})
			}
			mutex.Unlock()
			mutex_EchoMap.Unlock()

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
			hash_string := string(hash)
			m_j := payloadMessage.M
			j := m.Sender //sender's pid, i.e., the index of the sender

			mutex_ReadyMap.Lock()
			_, ok := T[hash_string]
			if ok {
				T[hash_string] = append(T[hash_string], m_received{int(j), m_j})
			} else {
				T[hash_string] = make([]m_received, 0)
				T[hash_string] = append(T[hash_string], m_received{int(j), m_j})
			}

			if len(T[hash_string]) > MaxReadyNumber {
				MaxReadyNumber = len(T[hash_string])
				MaxReadyHash = hash
			}

			//send RBCReady messages, line 13-15, Algo 4 in RBC paper
			mutex.Lock()
			if uint32(len(T[hash_string])) >= p.F+1 && !isReadySent {
				for {
					mutex_EchoMap.Lock()
					for m_i, count := range EchoMessageMap[hash_string] {
						if uint32(count) >= p.F+1 {
							isReadySent = true
							ready_data, _ := proto.Marshal(&protobuf.RBCReady{Hash: hash, M: []byte(m_i)})
							p.Broadcast(&protobuf.Message{Type: "RBCReady", Sender: p.PID, Id: ID, Data: ready_data})
							fmt.Printf("%v has broadcast RBCReady\n", p.PID)
							break
						}
					}
					mutex_EchoMap.Unlock()
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
			mutex_ReadyMap.Unlock()

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

		var m_received_temp = make([]m_received, p.N-p.F+r)
		mutex_ReadyMap.Lock()
		copy(m_received_temp, T[string(MaxReadyHash)])
		mutex_ReadyMap.Unlock()

		var M = make([][]byte, p.N)
		for i := uint32(0); i < p.N-p.F+r; i++ {
			M[m_received_temp[i].j] = m_received_temp[i].mj
		}

		RSEncoder, _ := reedsolomon.New(int(p.N-(p.F+1)), int(p.F+1))
		ok, _ := RSEncoder.Verify(M)
		if !ok {
			RSEncoder.Reconstruct(M)
		}

		//parse M and remove the padding zeros
		var m_reconstructed = make([]byte, 0)
		for i := uint32(0); i < p.N-(p.F+1); i++ {
			m_reconstructed = append(m_reconstructed, M[i]...)
		}

		//the last several bytes in MaxReadyHash are the lenth of M' (see line 9, Algo 4 in RBC paper)
		mlen_new := utils.BytesToInt(MaxReadyHash[256/8:])
		//the first 256/8 bytes in MaxReadyHash are the hash value
		MaxReadyHash = MaxReadyHash[:256/8]
		m_reconstructed = m_reconstructed[0:mlen_new]

		h_new := sha256.New()
		h_new.Write(m_reconstructed)

		if bytes.Compare(h_new.Sum(nil), MaxReadyHash) == 0 {
			var replyMessage protobuf.Message
			proto.Unmarshal(m_reconstructed, &replyMessage)
			return &replyMessage
		}
	}
	return nil
}
