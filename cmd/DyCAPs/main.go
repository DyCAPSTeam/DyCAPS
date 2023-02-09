package main

import (
	"flag"
	"fmt"
	"github.com/DyCAPSTeam/DyCAPS/internal/bls"
	"github.com/DyCAPSTeam/DyCAPS/internal/party"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"strings"
	"time"
)

func main() {
	//metadataPath := "metadata"
	//ListPath := "list"

	N := flag.Int("n", 4, "the size of the commitee")
	F := flag.Int("f", 4, "the maximum of faults")
	id := flag.Int("id", 0, "the id of the node")
	metadataPath := flag.String("mp", "", "metadataPath")
	ListPath := flag.String("lp", "", "listPath")
	option1 := flag.String("op1", "2", "1 means generating the parameters while 2 means executing the protocol")
	option2 := flag.String("op2", "commitee", "choose one from client,currentCommitee,newCommitee,onlyOneCommitee")
	interval1 := flag.Int("t1", 10, "waiting for some time so that new parties get ready")
	interval2 := flag.Int("t2", 15, "waiting for some time so that old parties get ready")
	interval3 := flag.Int("t3", 20, "the interval for startSig")
	messageLength := flag.Int64("ml", 0, "the size of payload message.")
	flag.Parse()

	if *option1 == "1" {
		party.GenCoefficientsFile(*N, 2**F+1)
		return
	} else if *option1 == "2" {

		sk, pk := party.SigKeyGenFix(uint32(*N), uint32(2**F+1))
		skNew, pkNew := party.SigKeyGenFix_New(uint32(*N), uint32(2**F+1))
		switch *option2 {
		case "currentCommitee":
			OutputLog, err := os.OpenFile(*metadataPath+"/executingLogOld"+strconv.Itoa(*id), os.O_RDWR|os.O_CREATE|os.O_APPEND, 0777)
			if err != nil {
				log.Fatalf("error opening file: %v", err)
			}
			defer OutputLog.Close()
			log.SetOutput(OutputLog)

			ipList := ReadIpList(*ListPath, "")[0:*N]
			portList := ReadPortList(*ListPath, "")[0:*N]
			ipListNext := ReadIpList(*ListPath, "Next")[0:*N]
			portListNext := ReadPortList(*ListPath, "Next")[0:*N]
			p := party.NewHonestParty(0, uint32(*N), uint32(*F), uint32(*id), ipList, portList, ipListNext, portListNext, pk, sk[*id], int64(*messageLength))
			p.InitReceiveChannel()

			time.Sleep(time.Duration(*interval2) * time.Second) //waiting for all nodes to initialize their ReceiveChannel

			p.InitSendChannel()
			p.InitSendToNextChannel()
			log.Printf("[VSS] OldParty %v starting...\n", id)
			fmt.Printf("[VSS] OldParty %v starting...\n", id)
			p.VSSShareReceive([]byte("vssshare"))
			log.Printf("[VSS][OldParty %v] VSS finished\n", id)
			fmt.Printf("[VSS] [OldParty %v]VSS finished\n", id)
			p.PrepareSend([]byte("shareReduce"))
			p.ShareReduceSend([]byte("shareReduce"))
			log.Printf("[ShareReduce] [OldParty %v]ShareReduce done\n", id)
			fmt.Printf("[ShareReduce][OldParty %v] ShareReduce done\n", id)

			f, _ := os.OpenFile(*metadataPath+"/logold"+strconv.Itoa(int(p.PID)), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0777)
			defer f.Close()
			fmt.Fprintf(f, "PrepareLatenncyOld,%d\n", p.PrepareEnd_old.Sub(p.PrepareStart_old).Nanoseconds())
			fmt.Fprintf(f, "ShareReduceLatencyOld, %d\n", p.ShareReduceEnd_old.Sub(p.ShareReduceStart_old).Nanoseconds())

			time.Sleep(20000 * time.Second)
		case "newCommitee":
			OutputLog, err := os.OpenFile(*metadataPath+"/executingLogNew"+strconv.Itoa(*id), os.O_RDWR|os.O_CREATE|os.O_APPEND, 0777)
			if err != nil {
				log.Fatalf("error opening file: %v", err)
			}
			defer OutputLog.Close()
			log.SetOutput(OutputLog)

			ipListNext := ReadIpList(*ListPath, "Next")[0:*N]
			portListNext := ReadPortList(*ListPath, "Next")[0:*N]
			p := party.NewHonestParty(1, uint32(*N), uint32(*F), uint32(*id), ipListNext, portListNext, nil, nil, pkNew, skNew[*id], int64(*messageLength))
			p.InitReceiveChannel()

			time.Sleep(time.Duration(*interval1) * time.Second) //waiting for all nodes to initialize their ReceiveChannel

			p.InitSendChannel()
			log.Printf("[ShareReduce][NewParty %v] ShareReduce starting...\n", p.PID)
			fmt.Printf("[ShareReduce][NewParty %v] ShareReduce starting...\n", p.PID)
			p.PrepareReceive([]byte("shareReduce"))
			p.ShareReduceReceive([]byte("shareReduce"))
			log.Printf("[ShareReduce][NewParty %v] ShareReduce finished\n", p.PID)
			fmt.Printf("[ShareReduce][NewParty %v] ShareReduce finished\n", p.PID)
			log.Printf("[Proactivize][NewParty %v] Proactivize starting\n", p.PID)
			fmt.Printf("[Proactivize][NewParty %v] Proactivize starting\n", p.PID)
			p.ProactivizeAndShareDist([]byte("ProactivizeAndShareDist"))
			log.Printf("[ShareDist] [NewParty %v]ShareDist finished\n", p.PID)
			fmt.Printf("[ShareDist][NewParty %v] ShareDist finished\n", p.PID)

			f, _ := os.OpenFile(*metadataPath+"/lognew"+strconv.Itoa(int(p.PID)), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0777)
			defer f.Close()
			fmt.Fprintf(f, "PrepareLatenncyNew,%d\n", p.PrepareEnd_new.Sub(p.PrepareStart_new).Nanoseconds())
			fmt.Fprintf(f, "ShareReduceLatencyNew, %d\n", p.ShareReduceEnd_new.Sub(p.ShareReduceStart_new).Nanoseconds())
			fmt.Fprintf(f, "ProactivizeLatency, %d\n", p.ProactivizeEnd.Sub(p.ProactivizeStart).Nanoseconds())
			fmt.Fprintf(f, "ShareDistLatency, %d\n", p.ShareDistEnd.Sub(p.ShareDistStart).Nanoseconds())

			time.Sleep(20000 * time.Second)

		case "onlyOneCommitee":
			ipList := ReadIpList(*ListPath, "")[0:*N]
			portList := ReadPortList(*ListPath, "")[0:*N]
			OutputLog, err := os.OpenFile(*metadataPath+"/executingLog"+strconv.Itoa(*id), os.O_RDWR|os.O_CREATE|os.O_APPEND, 0777)
			if err != nil {
				log.Fatalf("error opening file: %v", err)
			}
			defer OutputLog.Close()
			log.SetOutput(OutputLog)

			p := party.NewHonestParty(1, uint32(*N), uint32(*F), uint32(*id), ipList, portList, ipList, portList, pk, sk[*id], int64(*messageLength))
			p.InitReceiveChannel()

			time.Sleep(time.Duration(*interval1) * time.Second) //waiting for all nodes to initialize their ReceiveChannel

			p.InitSendChannel()
			p.InitSendToNextChannel()
			log.Printf("[VSS][Party %v] VSS starting...\n", *id)
			p.VSSShareReceive([]byte("vssshare"))
			log.Printf("[VSS][Party %v] VSS finished\n", *id)
			fmt.Printf("[VSS][Party %v] VSS finished\n", *id)

			log.Printf("[Prepare][Party %v] Prepare starting...\n")
			fmt.Printf("[Prepare][Party %v] Prepare starting...\n")
			p.PrepareSend([]byte("shareReduce"))
			p.PrepareReceive([]byte("shareReduce"))
			log.Printf("\"[Prepare][Party %v] Prepare finished\\n\"")
			fmt.Printf("\"[Prepare][Party %v] Prepare finished\\n\"")

			p.ShareReduceSend([]byte("shareReduce"))
			log.Printf("[ShareReduce][Party %v] ShareReduce send done\n", *id)
			fmt.Printf("[ShareReduce][Party %v] ShareReduce send done\n", *id)

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
			fmt.Fprintf(f, "PrepareLatenncy,%d\n", p.PrepareEnd_new.Sub(p.PrepareStart_old).Nanoseconds())
			fmt.Fprintf(f, "ShareReduceLatency, %d\n", p.ShareReduceEnd_new.Sub(p.ShareReduceStart_old).Nanoseconds())
			fmt.Fprintf(f, "ProactivizeLatency, %d\n", p.ProactivizeEnd.Sub(p.ProactivizeStart).Nanoseconds())
			fmt.Fprintf(f, "ShareDistLatency, %d\n", p.ShareDistEnd.Sub(p.ShareDistStart).Nanoseconds())

			time.Sleep(20000 * time.Second)

		case "client":
			ipList := ReadIpList(*ListPath, "")[0:*N]
			portList := ReadPortList(*ListPath, "")[0:*N]

			OutputLog, err := os.OpenFile(*metadataPath+"/executingLog"+"Client", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0777)
			if err != nil {
				log.Fatalf("error opening file: %v", err)
			}
			defer OutputLog.Close()
			log.SetOutput(OutputLog)

			var client party.Client
			var secret bls.Fr
			bls.AsFr(&secret, uint64(111111111111111))
			client.SetSecret(secret)
			client.HonestParty = party.NewHonestParty(0, uint32(*N), uint32(*F), 0x7fffffff, ipList, portList, ipList, portList, nil, nil, int64(*messageLength))

			time.Sleep(time.Duration(*interval3) * time.Second) //waiting for all nodes to initialize their ReceiveChannel. The Client starts at last.

			err2 := client.InitSendChannel()
			if err2 != nil {
				log.Printf("[VSS] Client InitSendChannel err: %v\n", err)
			}
			client.Share([]byte("vssshare"))
			log.Printf("[VSS] VSSshare done\n")
			time.Sleep(20000 * time.Second)
		}
	}
}

func ReadIpList(ListPath string, option string) []string {
	ipData, err := ioutil.ReadFile(ListPath + "/ipList" + option)
	if err != nil {
		log.Println(ListPath + "/ipList" + option)
		log.Fatalf("node failed to read iplist %v\n", err)
	}
	return strings.Split(string(ipData), "\n")
}

func ReadPortList(ListPath string, option string) []string {
	portData, err := ioutil.ReadFile(ListPath + "/portList" + option)
	if err != nil {
		log.Println(ListPath + "/portList" + option)
		log.Fatalf("node failed to read portlist %v\n", err)
	}
	return strings.Split(string(portData), "\n")
}
