package main

import (
	"fmt"
	"github.com/DyCAPSTeam/DyCAPS/internal/party"
	"github.com/ncw/gmp"
)

func main() {
	N := uint32(4)
	F := uint32(1)
	var option1 string
	fmt.Println("enter 1 to execute keyGen, enter 2 to execute the complete protocol")
	fmt.Scanln(&option1)
	if option1 == "1" {
		party.GenCoefficientsFile(int(N), int(2*F+1))
		return
	} else if option1 == "2" {
		ipList := []string{"127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1"}
		portList := []string{"18880", "18881", "18882", "18883", "18884", "18885", "18886", "18887", "18888", "18889"}
		ipListNext := []string{"127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1"}
		portListNext := []string{"18890", "18891", "18892", "18893", "18894", "18895", "18896", "18897", "18898", "18899"}
		sk, pk := party.SigKeyGenFix(N, 2*F+1)
		skNew, pkNew := party.SigKeyGenFix_New(N, 2*F+1)
		var option2 string
		fmt.Println("choose which the node belongs to : currentCommitee, newCommitee, client")
		fmt.Scanln(&option2)
		switch option2 {
		case "currentCommitee":
			p := new(party.HonestParty)
			fmt.Println("the id of the node")
			var id int //id of nodes starts from 0
			fmt.Scanf("%d", &id)
			p = party.NewHonestParty(0, N, F, uint32(id), ipList, portList, ipListNext, portListNext, pk, sk[id])
			p.InitReceiveChannel()
			fmt.Println("enter any number to get started")
			var startNum int //the signal
			fmt.Scanf("%d", &startNum)
			p.InitSendChannel()
			p.InitSendToNextChannel()
			fmt.Printf("[VSS] Party %v starting...\n", id)
			p.VSSShareReceive([]byte("vssshare"))
			fmt.Printf("[VSS] VSS finished\n")
			p.PrepareSend([]byte("shareReduce"))
			p.ShareReduceSend([]byte("shareReduce"))
			fmt.Printf("[ShareReduce] ShareReduce done\n")
			fmt.Println("enter any number to finish")
			var finishNum int // the finishing signal
			fmt.Scanf("%d", &finishNum)
		case "newCommitee":
			p := new(party.HonestParty)
			fmt.Println("the id of the node")
			var id int //id of nodes starts from 0
			fmt.Scanf("%d", &id)
			p = party.NewHonestParty(1, N, F, uint32(id), ipListNext, portListNext, nil, nil, pkNew, skNew[id])
			p.InitReceiveChannel()
			fmt.Println("enter any number to get started")
			var startNum int //the signal
			fmt.Scanf("%d", &startNum)
			p.InitSendChannel()
			fmt.Printf("[ShstreReduce] ShareReduce starting...\n")
			p.PrepareReceive([]byte("shareReduce"))
			p.ShareReduceReceive([]byte("shareReduce"))
			fmt.Printf("[ShstreReduce] ShareReduce finished\n")
			fmt.Printf("[Proactivize] Proactivize starting\n")
			p.ProactivizeAndShareDist([]byte("ProactivizeAndShareDist"))
			fmt.Printf("[ShareDist] ShareDist finished\n")
			fmt.Println("enter any number to finish")
			var finishNum int // the finishing signal
			fmt.Scanf("%d", &finishNum)
		case "client":
			var client party.Client
			s := new(gmp.Int)
			s.SetInt64(int64(111111111111111))
			client.SetSecret(s)
			client.HonestParty = party.NewHonestParty(0, N, F, 0x7fffffff, ipList, portList, ipListNext, portListNext, nil, nil)
			fmt.Println("enter any number to get started")
			var startNum int //the signal
			fmt.Scanf("%d", &startNum)
			err := client.InitSendChannel()
			if err != nil {
				fmt.Printf("[VSS] Client InitSendChannel err: %v\n", err)
			}
			client.Share([]byte("vssshare"))
			fmt.Printf("[VSS] VSSshare done\n")
			fmt.Println("enter any number to finish")
			var finishNum int // the finishing signal
			fmt.Scanf("%d", &finishNum)
		}
	}

}
