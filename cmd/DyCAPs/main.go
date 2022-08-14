package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/DyCAPSTeam/DyCAPS/internal/party"
	"github.com/ncw/gmp"
)

//把client生成的秘密多项式换成0多项式，试图减少计算开销
//VSS里直接接受Share，规避之前VSS卡住的问题

func main() {
	//metadataPath := "metadata"
	//ListPath := "list"

	N := flag.Int("n", 4, "the size of the commitee")
	F := flag.Int("f", 4, "the maximum of faults")
	id := flag.Int("id", 0, "the id of the node")
	metadataPath := flag.String("mp", "", "metadataPath")
	ListPath := flag.String("lp", "", "listPath")
	option1 := flag.String("op1", "2", "1 means generating the parameters while 2 means executing the protocol")
	option2 := flag.String("op2", "newCommitee", "choose one from client, currentCommitee, newCommitee, onlyOneCommitee")
	flag.Parse()
	if *option1 == "1" {
		party.GenCoefficientsFile(*N, 2**F+1)
		return
	} else if *option1 == "2" {
		ipList := ReadIpList(*ListPath)[0:*N]
		portList := ReadPortList(*ListPath)[0:*N]
		ipListNext := ReadIpList(*ListPath)[0:*N]
		portListNext := ReadPortList(*ListPath)[0:*N]

		sk, pk := party.SigKeyGenFix(uint32(*N), uint32(2**F+1))
		skNew, pkNew := party.SigKeyGenFix_New(uint32(*N), uint32(2**F+1))
		switch *option2 {
		case "currentCommitee":
			p := party.NewHonestParty(0, uint32(*N), uint32(*F), uint32(*id), ipList, portList, ipListNext, portListNext, pk, sk[*id])
			p.InitReceiveChannel()

			time.Sleep(30 * time.Second) //waiting for all nodes to initialize their ReceiveChannel

			p.InitSendChannel()
			p.InitSendToNextChannel()
			log.Printf("[VSS] Party %v starting...\n", id)
			p.VSSShareReceive([]byte("vssshare"))
			log.Printf("[VSS] VSS finished\n")
			p.PrepareSend([]byte("shareReduce"))
			p.ShareReduceSend([]byte("shareReduce"))
			log.Printf("[ShareReduce] ShareReduce done\n")
			time.Sleep(2000 * time.Second)
		case "newCommitee":
			p := party.NewHonestParty(1, uint32(*N), uint32(*F), uint32(*id), ipListNext, portListNext, nil, nil, pkNew, skNew[*id])
			p.InitReceiveChannel()

			time.Sleep(30 * time.Second) //waiting for all nodes to initialize their ReceiveChannel

			p.InitSendChannel()
			log.Printf("[ShareReduce] ShareReduce starting...\n")
			p.PrepareReceive([]byte("shareReduce"))
			p.ShareReduceReceive([]byte("shareReduce"))
			log.Printf("[ShareReduce] ShareReduce finished\n")
			log.Printf("[Proactivize] Proactivize starting\n")
			p.ProactivizeAndShareDist([]byte("ProactivizeAndShareDist"))
			log.Printf("[ShareDist] ShareDist finished\n")
			time.Sleep(2000 * time.Second)
		case "onlyOneCommitee":
			OutputLog, err := os.OpenFile(*metadataPath+"/executingLog"+strconv.Itoa(*id), os.O_RDWR|os.O_CREATE|os.O_APPEND, 0777)
			if err != nil {
				log.Fatalf("error opening file: %v", err)
			}
			defer OutputLog.Close()
			log.SetOutput(OutputLog)

			p := party.NewHonestParty(1, uint32(*N), uint32(*F), uint32(*id), ipList, portList, ipList, portList, pk, sk[*id])
			p.InitReceiveChannel()

			time.Sleep(30 * time.Second) //waiting for all nodes to initialize their ReceiveChannel

			p.InitSendChannel()
			p.InitSendToNextChannel()
			log.Printf("[VSS][Party %v] VSS starting...\n", *id)
			p.VSSShareReceive([]byte("vssshare"))
			log.Printf("[VSS][Party %v] VSS finished\n", *id)
			fmt.Printf("[VSS][Party %v] VSS finished\n", *id)

			p.PrepareSend([]byte("shareReduce"))
			p.ShareReduceSend([]byte("shareReduce"))
			log.Printf("[ShareReduce][Party %v] ShareReduce send done\n", *id)
			fmt.Printf("[ShareReduce][Party %v] ShareReduce send done\n", *id)

			p.PrepareReceive([]byte("shareReduce"))
			p.ShareReduceReceive([]byte("shareReduce"))
			log.Printf("[ShareReduce][Party %v] ShareReduce receive done\n", *id)
			fmt.Printf("[ShareReduce][Party %v] ShareReduce receive done\n", *id)

			log.Printf("[Proactivize][Party %v] Proactivize starting\n", *id)
			fmt.Printf("[Proactivize][Party %v] Proactivize starting\n", *id)
			p.ProactivizeAndShareDist([]byte("ProactivizeAndShareDist"))
			log.Printf("[ShareDist][Party %v] ShareDist done\n", *id)
			fmt.Printf("[ShareDist][Party %v] ShareDist done\n", *id)

			f, _ := os.OpenFile(*metadataPath+"/log"+strconv.Itoa(int(p.PID)), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0777)
			defer f.Close()
			fmt.Fprintf(f, "ShareReduceLatency, %d\n", p.ShareReduceEnd.Sub(p.ShareReduceStart).Nanoseconds())
			fmt.Fprintf(f, "ProactivizeLatency, %d\n", p.ProactivizeEnd.Sub(p.ProactivizeStart).Nanoseconds())
			fmt.Fprintf(f, "ShareDistLatency, %d\n", p.ShareDistEnd.Sub(p.ShareDistStart).Nanoseconds())

			time.Sleep(2000 * time.Second)

		case "client":
			OutputLog, err := os.OpenFile(*metadataPath+"/executingLog"+"Client", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0777)
			if err != nil {
				log.Fatalf("error opening file: %v", err)
			}
			defer OutputLog.Close()
			log.SetOutput(OutputLog)

			var client party.Client
			s := new(gmp.Int).SetInt64(int64(111111111111111))
			client.SetSecret(s)
			client.HonestParty = party.NewHonestParty(0, uint32(*N), uint32(*F), 0x7fffffff, ipList, portList, ipListNext, portListNext, nil, nil)

			time.Sleep(50 * time.Second) //waiting for all nodes to initialize their ReceiveChannel. The Client starts at last.

			err2 := client.InitSendChannel()
			if err2 != nil {
				log.Printf("[VSS] Client InitSendChannel err: %v\n", err)
			}
			client.Share([]byte("vssshare"))
			log.Printf("[VSS] VSSshare done\n")
			time.Sleep(2000 * time.Second)
		}
	}
}

func ReadIpList(ListPath string) []string {
	ipData, err := ioutil.ReadFile(ListPath + "/ipList")
	if err != nil {
		fmt.Println(ListPath + "/ipList")
		log.Fatalf("node failed to read iplist %v\n", err)
	}
	return strings.Split(string(ipData), "\n")
}
func ReadPortList(ListPath string) []string {
	portData, err := ioutil.ReadFile(ListPath + "/portList")
	if err != nil {
		log.Fatalf("node failed to read portlist %v\n", err)
	}
	return strings.Split(string(portData), "\n")
}
