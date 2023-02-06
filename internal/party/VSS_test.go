package party

import (
	"github.com/DyCAPSTeam/DyCAPS/internal/bls"
	"github.com/DyCAPSTeam/DyCAPS/pkg/protobuf"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"
	"log"
	"sync"
	"testing"
)

func TestDealer(t *testing.T) {

	ipList := []string{"127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1"}
	portList := []string{"8880", "8881", "8882", "8883", "8884", "8885", "8886", "8887", "8888", "8889"}
	ipListNext := []string{"127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1"}
	portListNext := []string{"8890", "8891", "8892", "8893", "8894", "8895", "8896", "8897", "8898", "8899"}
	N := uint32(4)
	F := uint32(1)
	sk, pk := SigKeyGen(N, 2*F+2) // wrong usage, but it doesn't matter here

	//KZG.SetupFix(2 * int(F))

	var p []*HonestParty = make([]*HonestParty, N)
	for i := uint32(0); i < N; i++ {
		p[i] = NewHonestParty(0, N, F, i, ipList, portList, ipListNext, portListNext, pk, sk[i])
	}

	for i := uint32(0); i < N; i++ {
		err := p[i].InitReceiveChannel()
		if err != nil {
			log.Printf("[VSS TestDealer] Party %v initReceiveChannel err: %v\n", i, err)
		}
	}

	// send channels are initiated after all receive channels are initiated
	for i := uint32(0); i < N; i++ {
		err := p[i].InitSendChannel()
		if err != nil {
			log.Printf("[VSS TestDealer] Party %v InitSendChannel err: %v\n", i, err)
		}
	}

	var client Client
	bls.AsFr(&client.s, uint64(1111111111111112222))

	clientID := uint32(0x7fffffff)

	client.HonestParty = NewHonestParty(0, N, F, clientID, ipList, portList, ipListNext, portListNext, pk, sk[2*F+1])
	err := client.InitSendChannel()
	if err != nil {
		log.Printf("[VSS TestDealer] Client InitSendChannel err: %v\n", err)
	}

	client.Share([]byte("vssshare"))

	for i := 0; uint32(i) < N; i++ {
		m := <-p[i].GetMessage("VSSSend", []byte("vssshare"))
		var content protobuf.VSSSend
		err := proto.Unmarshal(m.Data, &content)
		if err != nil {
			return
		}

		gs, err2 := bls.FromCompressedG1(content.Pi.Gs)
		if err2 != nil {
			panic(err2)
		}
		piTest := new(Pi)
		bls.CopyG1(&piTest.Gs, gs)

		piTest.PiContents = make([]PiContent, 2*F+2)

		// index starts from 1 here
		for j := 1; uint32(j) <= 2*F+1; j++ {

			CBj_raw, _ := bls.FromCompressedG1(content.Pi.PiContents[j].CBj)
			CZj_raw, _ := bls.FromCompressedG1(content.Pi.PiContents[j].CZj)
			WZ0_raw, _ := bls.FromCompressedG1(content.Pi.PiContents[j].WZ0)
			gFj_raw, _ := bls.FromCompressedG1(content.Pi.PiContents[j].GFj)

			bls.CopyG1(&piTest.PiContents[j].CBj, CBj_raw)
			bls.CopyG1(&piTest.PiContents[j].CZj, CZj_raw)
			bls.CopyG1(&piTest.PiContents[j].WZ0, WZ0_raw)
			bls.CopyG1(&piTest.PiContents[j].gFj, gFj_raw)

			// verify CBj=CZj*gFj
			tmp := bls.ZeroG1
			bls.AddG1(&tmp, &piTest.PiContents[j].CZj, &piTest.PiContents[j].gFj)
			assert.True(t, bls.EqualG1(&tmp, &piTest.PiContents[j].CBj), "verify CBj = CZj * gFj")
			assert.True(t, p[i].KZG.CheckProofSingle(&piTest.PiContents[j].CZj, &piTest.PiContents[j].WZ0, &p[i].FS.ExpandedRootsOfUnity[0], &bls.ZERO), "verify CZj and WZ0j")

		}

		//verify g^s = \prod g^{lambda[index]*F(index)} = \prod (g^F(index))^lambda[index]

		gFjList := make([]bls.G1Point, 2*F+2)
		for j := uint32(1); j < 2*F+2; j++ {
			bls.CopyG1(&gFjList[j], &piTest.PiContents[j].gFj)
		}

		tmpGs := *bls.LinCombG1(gFjList[1:], p[i].LagrangeCoefficients[0])

		assert.True(t, bls.EqualG1(&piTest.Gs, &tmpGs), "[VSSReceive] Verify g^s = \\prod g^{lambda[index]*F(index)} = \\prod (g^F(index))^lambda[index]")

		//KZG verification
		//for j := 1; uint32(j) <= 2*F+1; j++ {
		//	Bij := gmp.NewInt(0)
		//	WBij := p[i].KZG.NewG1()
		//	Bij.SetBytes(content.BijList[j])
		//	WBij.SetCompressedBytes(content.WBijList[j])
		//	assert.True(t, p[i].KZG.VerifyEval(piTest.PiContents[j].CBj, gmp.NewInt(int64((i+1))), Bij, WBij), "[VSSReceive] KZG verification")
		//}
	}
}

func TestVSS(t *testing.T) {
	ipList := []string{"127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1"}
	portList := []string{"10080", "10081", "10082", "10083", "10084", "10085", "10086", "10087", "10088", "10089", "10090", "10091", "10092"}
	ipListNext := []string{"127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1"}
	portListNext := []string{"10190", "10191", "10192", "10193", "10194", "10195", "10196", "10197", "10198", "10199", "10200", "10201", "10202"}
	N := uint32(4)
	F := uint32(1)
	sk, pk := SigKeyGen(N, 2*F+2) // wrong usage, but it doesn't matter here

	//KZG.SetupFix(2 * int(F))

	var p []*HonestParty = make([]*HonestParty, N)
	for i := uint32(0); i < N; i++ {
		p[i] = NewHonestParty(0, N, F, i, ipList, portList, ipListNext, portListNext, pk, sk[i])
	}

	for i := uint32(0); i < N; i++ {
		err := p[i].InitReceiveChannel()
		if err != nil {
			log.Printf("[VSS] Party %v initReceiveChannel err: %v\n", i, err)
		}
	}

	// send channels are initiated after all receive channels are initiated
	for i := uint32(0); i < N; i++ {
		err := p[i].InitSendChannel()
		if err != nil {
			log.Printf("[VSS] Party %v InitSendChannel err: %v\n", i, err)
		}
	}

	var client Client
	bls.AsFr(&client.s, uint64(1111111111111112222))

	clientID := uint32(0x7fffffff)

	client.HonestParty = NewHonestParty(0, N, F, clientID, ipList, portList, ipListNext, portListNext, pk, sk[2*F+1])
	err := client.InitSendChannel()
	if err != nil {
		log.Printf("[VSS] Client InitSendChannel err: %v\n", err)
	}

	client.Share([]byte("VSSshare"))
	log.Printf("[VSS] VSSshare done\n")

	var wg sync.WaitGroup

	wg.Add(int(N))
	for i := uint32(0); i < N; i++ {
		go func(i uint32) {
			log.Printf("[VSS] Party %v starting...\n", i)
			p[i].VSSShareReceive([]byte("VSSshare"))
			wg.Done()
			log.Printf("[VSS] Party %v done\n", i)
		}(i)
	}

	wg.Wait()

	log.Println("[VSS] VSS Finish")
}
