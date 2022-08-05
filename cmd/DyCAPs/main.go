package main

import (
	"flag"
	"fmt"
	"github.com/DyCAPSTeam/DyCAPS/internal/party"
	"github.com/ncw/gmp"
	"log"
	"os"
	"strconv"
	"time"
)

func main() {
	metadataPath := "metadata"

	N := flag.Int("n", 4, "the size of the commitee")
	F := flag.Int("f", 4, "the maximum of faults")
	id := flag.Int("id", 0, "the id of the node")
	option1 := flag.String("op1", "2", "1 means generating the parameters while 2 means executing the protocol")
	option2 := flag.String("op2", "newCommitee", "choose one from client, currentCommitee, newCommitee, onlyOneCommitee")
	flag.Parse()
	if *option1 == "1" {
		party.GenCoefficientsFile(*N, 2**F+1)
		return
	} else if *option1 == "2" {
		ipList := []string{"127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1"}
		portList := []string{"18880", "18881", "18882", "18883", "18884", "18885", "18886", "18887", "18888", "18889", "18890", "18891", "18892"}
		ipListNext := []string{"127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1u", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1"}
		portListNext := []string{"18893", "18894", "18895", "18896", "18897", "18898", "18899", "18900", "18901", "18902", "18903", "18904", "18905"}
		sk, pk := party.SigKeyGenFix(uint32(*N), uint32(2**F+1))
		skNew, pkNew := party.SigKeyGenFix_New(uint32(*N), uint32(2**F+1))
		switch *option2 {
		case "currentCommitee":
			p := new(party.HonestParty)
			p = party.NewHonestParty(0, uint32(*N), uint32(*F), uint32(*id), ipList, portList, ipListNext, portListNext, pk, sk[*id])
			p.InitReceiveChannel()

			time.Sleep(1000000000) //waiting for all nodes to initialize their ReceiveChannel

			p.InitSendChannel()
			p.InitSendToNextChannel()
			log.Printf("[VSS] Party %v starting...\n", id)
			p.VSSShareReceive([]byte("vssshare"))
			log.Printf("[VSS] VSS finished\n")
			p.PrepareSend([]byte("shareReduce"))
			p.ShareReduceSend([]byte("shareReduce"))
			log.Printf("[ShareReduce] ShareReduce done\n")
			time.Sleep(200000000000) //FIXME:temp solution
		case "newCommitee":
			p := new(party.HonestParty)
			p = party.NewHonestParty(1, uint32(*N), uint32(*F), uint32(*id), ipListNext, portListNext, nil, nil, pkNew, skNew[*id])
			p.InitReceiveChannel()

			time.Sleep(1000000000) //waiting for all nodes to initialize their ReceiveChannel

			p.InitSendChannel()
			log.Printf("[ShareReduce] ShareReduce starting...\n")
			p.PrepareReceive([]byte("shareReduce"))
			p.ShareReduceReceive([]byte("shareReduce"))
			log.Printf("[ShareReduce] ShareReduce finished\n")
			log.Printf("[Proactivize] Proactivize starting\n")
			p.ProactivizeAndShareDist([]byte("ProactivizeAndShareDist"))
			log.Printf("[ShareDist] ShareDist finished\n")
			time.Sleep(200000000000) //FIXME:temp solution
		case "onlyOneCommitee":
			p := new(party.HonestParty)
			p = party.NewHonestParty(1, uint32(*N), uint32(*F), uint32(*id), ipList, portList, ipList, portList, pk, sk[*id])
			p.InitReceiveChannel()

			time.Sleep(10000000000) //waiting for all nodes to initialize their ReceiveChannel

			p.InitSendChannel()
			p.InitSendToNextChannel()
			log.Printf("[VSS] Party %v starting...\n", id)
			p.VSSShareReceive([]byte("vssshare"))
			log.Printf("[VSS] VSS finished\n")
			p.PrepareSend([]byte("shareReduce"))
			p.ShareReduceSend([]byte("shareReduce"))
			log.Printf("[ShareReduce] ShareReduce done\n")
			p.PrepareReceive([]byte("shareReduce"))
			p.ShareReduceReceive([]byte("shareReduce"))
			log.Printf("[ShareReduce] ShareReduce finished\n")
			log.Printf("[Proactivize] Proactivize starting\n")
			p.ProactivizeAndShareDist([]byte("ProactivizeAndShareDist"))
			log.Printf("[ShareDist] ShareDist finished\n")

			f, _ := os.OpenFile(metadataPath+"/log"+strconv.Itoa(int(p.PID)), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			defer f.Close()
			fmt.Fprintf(f, "VSSLatency,%d\n", p.VSSEnd.Sub(p.VSSStart).Nanoseconds())
			fmt.Fprintf(f, "ShareReduceLatency,%d\n", p.ShareReduceEnd.Sub(p.ShareReduceStart).Nanoseconds())
			fmt.Fprintf(f, "ProactivizeLatency,%d\n", p.ProactivizeEnd.Sub(p.ProactivizeStart).Nanoseconds())
			fmt.Fprintf(f, "ShareDistLatency,%d\n", p.ShareDistEnd.Sub(p.ShareDistStart).Nanoseconds())

			time.Sleep(200000000000) //FIXME:temp solution

		case "client":
			var client party.Client
			s := new(gmp.Int)
			s.SetInt64(int64(111111111111111))
			client.SetSecret(s)
			client.HonestParty = party.NewHonestParty(0, uint32(*N), uint32(*F), 0x7fffffff, ipList, portList, ipListNext, portListNext, nil, nil)

			time.Sleep(2000000000) //waiting for all nodes to initialize their ReceiveChannel.The Client starts at last.

			err := client.InitSendChannel()
			if err != nil {
				log.Printf("[VSS] Client InitSendChannel err: %v\n", err)
			}
			client.Share([]byte("vssshare"))
			log.Printf("[VSS] VSSshare done\n")
			time.Sleep(200000000000) //FIXME:temp solution
		}
	}

}
