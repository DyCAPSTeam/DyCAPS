package party

import (
	"fmt"
	"github.com/DyCAPSTeam/DyCAPS/pkg/protobuf"
	"github.com/Nik-U/pbc"
	"github.com/ncw/gmp"
	"google.golang.org/protobuf/proto"
	"testing"
)

func TestDealer(t *testing.T) {

	ipList := []string{"127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1"}
	portList := []string{"8880", "8881", "8882", "8883", "8884", "8885", "8886"}

	N := uint32(7)
	F := uint32(2)
	sk, pk := SigKeyGen(N, 2*F+2)

	var p []*HonestParty = make([]*HonestParty, N)
	for i := uint32(0); i < N; i++ {
		p[i] = NewHonestParty(N, F, i, ipList, portList, pk, sk[i])
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
	client.HonestParty = NewHonestParty(N, F, 0x7fffffff, ipList, portList, pk, sk[2*F+1])
	client.InitSendChannel()

	KZG.SetupFix(int(F))

	client.Share([]byte("vssshare"))

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
		pi_test.Pi_contents = make([]Pi_Content, 2*F+2)
		for j := 0; uint32(j) <= 2*F+1; j++ {
			pi_test.Pi_contents[j].CR_j = KZG.NewG1()
			pi_test.Pi_contents[j].CZ_j = KZG.NewG1()
			pi_test.Pi_contents[j].WZ_0 = KZG.NewG1()
			pi_test.Pi_contents[j].g_Fj = KZG.NewG1()
		}
		for j := 1; uint32(j) <= 2*F+1; j++ {
			pi_test.Pi_contents[j].CR_j.SetCompressedBytes(content.Pi.PiContents[j].CRJ)
			pi_test.Pi_contents[j].CZ_j.SetCompressedBytes(content.Pi.PiContents[j].CZJ)
			pi_test.Pi_contents[j].WZ_0.SetCompressedBytes(content.Pi.PiContents[j].WZ_0)
			pi_test.Pi_contents[j].g_Fj.SetCompressedBytes(content.Pi.PiContents[j].G_Fj)
			fmt.Println("j= ", j, "; CRj= ", pi_test.Pi_contents[j].CR_j.String(), "; CZj= ", pi_test.Pi_contents[j].CZ_j.String(), "; WZj_0= ", pi_test.Pi_contents[j].WZ_0.String(), "; g_Fj= ", pi_test.Pi_contents[j].g_Fj.String())
		}
		for j := 1; uint32(j) <= 2*F+1; j++ {
			Rji := new(gmp.Int)
			WRji := new(pbc.Element)
			Rji = gmp.NewInt(0)
			WRji = KZG.NewG1()
			Rji.SetBytes(content.RjiList[j])
			WRji.SetCompressedBytes(content.WRjiList[j])
			fmt.Println("i= ", i+1, " j = ", j, " Rji = ", Rji, "WRji = ", WRji.String())
		}
	}

}
