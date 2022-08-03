package party

import (
	"log"
	"sync"
	"testing"

	"github.com/DyCAPSTeam/DyCAPS/internal/conv"
	"github.com/DyCAPSTeam/DyCAPS/internal/ecparam"
	"github.com/DyCAPSTeam/DyCAPS/internal/polyring"
	"github.com/DyCAPSTeam/DyCAPS/pkg/protobuf"
	"github.com/ncw/gmp"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"
)

func TestDealer(t *testing.T) {

	ipList := []string{"127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1"}
	portList := []string{"8880", "8881", "8882", "8883", "8884", "8885", "8886", "8887", "8888", "8889"}
	ipListNext := []string{"127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1"}
	portListNext := []string{"8890", "8891", "8892", "8893", "8894", "8895", "8896", "8897", "8898", "8899"}
	N := uint32(10)
	F := uint32(3)
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
	client.s = new(gmp.Int).SetInt64(int64(1111111111111112222))
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
		gs := p[i].KZG.NewG1()
		gs.SetCompressedBytes(content.Pi.Gs)

		piTest := new(Pi)
		piTest.Gs = p[i].KZG.NewG1()
		piTest.Gs.Set(gs)
		piTest.PiContents = make([]PiContent, 2*F+2)
		for j := 0; uint32(j) <= 2*F+1; j++ {
			piTest.PiContents[j].CBj = p[i].KZG.NewG1()
			piTest.PiContents[j].CZj = p[i].KZG.NewG1()
			piTest.PiContents[j].WZ0 = p[i].KZG.NewG1()
			piTest.PiContents[j].gFj = p[i].KZG.NewG1()
		}

		// index starts from 1 here
		for j := 1; uint32(j) <= 2*F+1; j++ {
			piTest.PiContents[j].CBj.SetCompressedBytes(content.Pi.PiContents[j].CBj)
			piTest.PiContents[j].CZj.SetCompressedBytes(content.Pi.PiContents[j].CZj)
			piTest.PiContents[j].WZ0.SetCompressedBytes(content.Pi.PiContents[j].WZ0)
			piTest.PiContents[j].gFj.SetCompressedBytes(content.Pi.PiContents[j].GFj)

			// verify CBj=CZj*gFj
			tmp := p[i].KZG.NewG1()
			tmp.Set0()
			tmp.Add(piTest.PiContents[j].CZj, piTest.PiContents[j].gFj)
			assert.True(t, tmp.Equals(piTest.PiContents[j].CBj), "verify CBj = CZj * gFj")

		}

		//verify g^s = \prod g^{lambda[index]*F(index)} = \prod (g^F(index))^lambda[index]
		lambda := make([]*gmp.Int, 2*F+1)
		knownIndexes := make([]*gmp.Int, 2*F+1)
		for j := 0; uint32(j) < 2*F+1; j++ {
			lambda[j] = gmp.NewInt(int64(j + 1))
			knownIndexes[j] = gmp.NewInt(int64(j + 1))
		}

		polyring.GetLagrangeCoefficients(2*F, knownIndexes, ecparam.PBC256.Ngmp, gmp.NewInt(0), lambda)
		tmp := p[i].KZG.NewG1()
		tmp.Set0()
		for j := 1; uint32(j) <= 2*F+1; j++ {
			tmp2 := p[i].KZG.NewG1()
			// tmp2.Set1()
			tmp2.MulBig(piTest.PiContents[j].gFj, conv.GmpInt2BigInt(lambda[j-1])) // the x value of index index-1 is index
			// tmp2.PowBig(pi_test.Pi_contents[index].gFj, conv.GmpInt2BigInt(lambda[index-1])) // the x value of index index-1 is index
			tmp.ThenAdd(tmp2)
		}
		assert.True(t, tmp.Equals(piTest.Gs), "[VSSReceive] Verify g^s = \\prod g^{lambda[index]*F(index)} = \\prod (g^F(index))^lambda[index]")

		//KZG verification
		for j := 1; uint32(j) <= 2*F+1; j++ {
			Bij := gmp.NewInt(0)
			WBij := p[i].KZG.NewG1()
			Bij.SetBytes(content.BijList[j])
			WBij.SetCompressedBytes(content.WBijList[j])
			assert.True(t, p[i].KZG.VerifyEval(piTest.PiContents[j].CBj, gmp.NewInt(int64((i+1))), Bij, WBij), "[VSSReceive] KZG verification")
		}
	}
}

func TestVSS(t *testing.T) {
	//This test sometimes crashes, possibly related to InterpolateComOrWit() and KZG.VerifyEval()
	ipList := []string{"127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1"}
	portList := []string{"10080", "10081", "10082", "10083", "10084", "10085", "10086", "10087", "10088", "10089", "10090", "10091", "10092"}
	ipListNext := []string{"127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1"}
	portListNext := []string{"10190", "10191", "10192", "10193", "10194", "10195", "10196", "10197", "10198", "10199", "10200", "10201", "10202"}
	N := uint32(13)
	F := uint32(4)
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
	client.s = new(gmp.Int).SetBytes([]byte("11111111111111111111111112"))
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
