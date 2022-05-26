package party

import (
	"fmt"
	"github.com/DyCAPSTeam/DyCAPS/internal/conv"
	"github.com/DyCAPSTeam/DyCAPS/internal/ecparam"
	"github.com/DyCAPSTeam/DyCAPS/internal/polyring"
	"github.com/DyCAPSTeam/DyCAPS/pkg/protobuf"
	"github.com/Nik-U/pbc"
	"github.com/golang/protobuf/proto"
	"github.com/ncw/gmp"
	"os"
	"sync"
	"testing"
)

func TestDealer(t *testing.T) {

	ipList := []string{"127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1"}
	portList := []string{"8880", "8881", "8882", "8883", "8884", "8885", "8886"}
	ipList_next := []string{"127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1"}
	portList_next := []string{"8887", "8888", "8889", "8890", "8891", "8892", "8893"}
	N := uint32(7)
	F := uint32(2)
	sk, pk := SigKeyGen(N, 2*F+2) // wrong usage, but it doesn't matter here

	KZG.SetupFix(int(2 * F))

	pi_init := new(Pi)
	pi_init.Init(F)
	witness_init := make([]*pbc.Element, 2*F+1)
	witness_init_indexes := make([]*gmp.Int, 2*F+1)
	for i := 0; uint32(i) < 2*F+1; i++ {
		witness_init[i] = KZG.NewG1()
		witness_init_indexes[i] = gmp.NewInt(0)
	}
	var p []*HonestParty = make([]*HonestParty, N)
	for i := uint32(0); i < N; i++ {
		p[i] = NewHonestParty(N, F, i, ipList, portList, ipList_next, portList_next, pk, sk[i], pi_init, witness_init, witness_init_indexes)
	}

	for i := uint32(0); i < N; i++ {
		p[i].InitReceiveChannel()
	}

	for i := uint32(0); i < N; i++ {
		p[i].InitSendChannel()
	}

	var client Client
	client.s = new(gmp.Int)
	client.s.SetInt64(int64(111111111111111))
	client.HonestParty = NewHonestParty(N, F, 0x7fffffff, ipList, portList, ipList_next, portList_next, pk, sk[2*F+1], pi_init, witness_init, witness_init_indexes)
	client.InitSendChannel()

	primitive := ecparam.PBC256.Ngmp

	client.Share([]byte("vssshare"))
	//note that here i start from 0, j start from 1
	for i := 0; uint32(i) < N; i++ {
		m := <-p[i].GetMessage("VSSSend", []byte("vssshare"))
		data := m.Data
		var content protobuf.VSSSend
		proto.Unmarshal(data, &content)
		gs := new(pbc.Element)
		gs = KZG.NewG1()
		gs.SetCompressedBytes(content.Pi.Gs)

		fmt.Println("node", i+1, "receive", m.Sender, m.Id, m.Type, m.Data)
		fmt.Println("the gs received is", gs.String())
		var pi_test = new(Pi)
		pi_test.G_s = KZG.NewG1()
		pi_test.Pi_contents = make([]Pi_Content, 2*F+2)
		for j := 0; uint32(j) <= 2*F+1; j++ {
			pi_test.Pi_contents[j].CR_j = KZG.NewG1()
			pi_test.Pi_contents[j].CZ_j = KZG.NewG1()
			pi_test.Pi_contents[j].WZ_0 = KZG.NewG1()
			pi_test.Pi_contents[j].g_Fj = KZG.NewG1()
		}
		pi_test.G_s.Set(gs)
		for j := 1; uint32(j) <= 2*F+1; j++ {
			pi_test.Pi_contents[j].CR_j.SetCompressedBytes(content.Pi.PiContents[j].CRJ)
			pi_test.Pi_contents[j].CZ_j.SetCompressedBytes(content.Pi.PiContents[j].CZJ)
			pi_test.Pi_contents[j].WZ_0.SetCompressedBytes(content.Pi.PiContents[j].WZ_0)
			pi_test.Pi_contents[j].g_Fj.SetCompressedBytes(content.Pi.PiContents[j].G_Fj)
			fmt.Println("j= ", j, "; CRj= ", pi_test.Pi_contents[j].CR_j.String(), "; CZj= ", pi_test.Pi_contents[j].CZ_j.String(), "; WZj_0= ", pi_test.Pi_contents[j].WZ_0.String(), "; g_Fj= ", pi_test.Pi_contents[j].g_Fj.String())
		}
		//Verification Start
		lambda := make([]*gmp.Int, 2*F+1)
		knownIndexes := make([]*gmp.Int, 2*F+1)
		for j := 0; uint32(j) < 2*F+1; j++ {
			lambda[j] = gmp.NewInt(int64(j + 1))
		}
		for j := 0; uint32(j) < 2*F+1; j++ {
			knownIndexes[j] = gmp.NewInt(int64(j + 1))
		}
		polyring.GetLagrangeCoefficients(int(2*F), knownIndexes, primitive, gmp.NewInt(0), lambda)
		tmp := KZG.NewG1()
		tmp.Set1()
		for j := 1; uint32(j) <= 2*F+1; j++ {
			tmp2 := KZG.NewG1()
			tmp2.Set1()
			tmp2.PowBig(pi_test.Pi_contents[j].g_Fj, conv.GmpInt2BigInt(lambda[j-1])) // the x value of index j-1 is j
			tmp.Mul(tmp, tmp2)
		}
		if tmp.Equals(pi_test.G_s) {
			fmt.Println("g_s == multiply(lambda_i,g_F(i)),gs = ", gs.String(), "multiply(lambda_i,g_F(i))= ", tmp.String())
		} else {
			fmt.Println("g_s != multiply(lambda_i,g_F(i)),gs = ", gs.String(), "multiply(lambda_i,g_F(i))= ", tmp.String())
			os.Exit(1)
		}
		//KZG end
		for j := 1; uint32(j) <= 2*F+1; j++ {
			Rji := new(gmp.Int)
			WRji := new(pbc.Element)
			Rji = gmp.NewInt(0)
			WRji = KZG.NewG1()
			Rji.SetBytes(content.RjiList[j])
			WRji.SetCompressedBytes(content.WRjiList[j])
			//KZG Verify
			fmt.Println("KZG commitment: ", KZG.VerifyEval(pi_test.Pi_contents[j].CR_j, gmp.NewInt(int64((i+1))), Rji, WRji))
			fmt.Println("i= ", i+1, " j = ", j, " Rji = ", Rji, "WRji = ", WRji.String())
		}
	}
}

func TestVSS(t *testing.T) {

	ipList := []string{"127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1"}
	portList := []string{"8880", "8881", "8882", "8883", "8884", "8885", "8886"}
	ipList_next := []string{"127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1"}
	portList_next := []string{"8887", "8888", "8889", "8890", "8891", "8892", "8893"}
	N := uint32(7)
	F := uint32(2)
	sk, pk := SigKeyGen(N, 2*F+2) // wrong usage, but it doesn't matter here

	KZG.SetupFix(int(2 * F))

	pi_init := new(Pi)
	pi_init.Init(F)
	witness_init := make([]*pbc.Element, 2*F+1)
	witness_init_indexes := make([]*gmp.Int, 2*F+1)
	for i := 0; uint32(i) < 2*F+1; i++ {
		witness_init[i] = KZG.NewG1()
		witness_init_indexes[i] = gmp.NewInt(0)
	}
	var p []*HonestParty = make([]*HonestParty, N)
	for i := uint32(0); i < N; i++ {
		p[i] = NewHonestParty(N, F, i, ipList, portList, ipList_next, portList_next, pk, sk[i], pi_init, witness_init, witness_init_indexes)
	}

	for i := uint32(0); i < N; i++ {
		p[i].InitReceiveChannel()
	}

	for i := uint32(0); i < N; i++ {
		p[i].InitSendChannel()
	}

	var client Client
	client.s = new(gmp.Int)
	client.s.SetInt64(int64(111111111111111))
	client.HonestParty = NewHonestParty(N, F, 0x7fffffff, ipList, portList, ipList_next, portList_next, pk, sk[2*F+1], pi_init, witness_init, witness_init_indexes)
	client.InitSendChannel()

	client.Share([]byte("vssshare"))

	var wg sync.WaitGroup

	wg.Add(int(3*F + 1))
	for i := uint32(0); i < N; i++ {
		go func(i uint32) {
			p[i].InitShareReceiver([]byte("vssshare"))
			wg.Done()
		}(i)
	}

	wg.Wait()

	fmt.Println("VSS Finish")
}
