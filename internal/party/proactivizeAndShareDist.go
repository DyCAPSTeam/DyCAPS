package party

import (
	"fmt"
	"math/rand"
	"strconv"
	"sync"
	"time"

	"github.com/DyCAPSTeam/DyCAPS/internal/conv"
	"github.com/DyCAPSTeam/DyCAPS/internal/ecparam"
	"github.com/DyCAPSTeam/DyCAPS/internal/interpolation"
	"github.com/DyCAPSTeam/DyCAPS/internal/polyring"
	"github.com/DyCAPSTeam/DyCAPS/pkg/protobuf"
	"github.com/Nik-U/pbc"
	"github.com/ncw/gmp"
	"go.dedis.ch/kyber/v3/sign/tbls"
	"google.golang.org/protobuf/proto"
)

func (p *HonestParty) ProactivizeAndShareDist(ID []byte) {
	ecparamN := ecparam.PBC256.Ngmp
	var startComChan = make(chan bool, 1)
	var startReshareChan = make(chan bool, 1)
	var flgCom = make([]bool, p.N+1)
	var flgRec = make([]bool, p.N+1)
	var startVoteChan = make([]chan bool, p.N+1)
	var startRecoverChan = make([]chan bool, p.N+1)
	var startRefreshChan = make([]chan bool, p.N+1)
	for i := uint32(0); i <= p.N; i++ {
		flgCom[i] = false
		flgRec[i] = false
		startVoteChan[i] = make(chan bool, 1)
		startRecoverChan[i] = make(chan bool, 1)
		startRefreshChan[i] = make(chan bool, 1)
	}
	var piI = make([]PiContent, 0)

	var Z = make([]polyring.Polynomial, p.N+1) //Z_ij(x)=Q_i(x,index)-F_j(index), which means Z_ij(0)=0
	var Fj = gmp.NewInt(0)                     //F_i(index)
	var gFj = KZG.NewG1()                      //g^F_i(index)
	var CQ = make([][]*pbc.Element, p.N+1)     //CQ[*][0] is not used
	var CZ = make([]*pbc.Element, p.N+1)       //commitment of Zj(x)
	var wZ = make([]*pbc.Element, p.N+1)       //witness of Zj(0)=0
	var vQ = make([][][]*gmp.Int, p.N+1)       //vQ[i][index][k] denotes the value of Qi(x,index), where x=k
	var wQ = make([][][]*pbc.Element, p.N+1)   //wQ[i][index][k] denotes the witness of Qi(x,index), where x=k

	for i := uint32(0); i <= p.N; i++ {
		vQ[i] = make([][]*gmp.Int, p.N+1)
		wQ[i] = make([][]*pbc.Element, p.N+1)

		for j := uint32(0); j <= p.N; j++ {
			vQ[i][j] = make([]*gmp.Int, p.N+1)
			wQ[i][j] = make([]*pbc.Element, p.N+1)

			for k := uint32(0); k <= p.N; k++ {
				vQ[i][j][k] = gmp.NewInt(0)
				wQ[i][j][k] = KZG.NewG1()
			}
		}
	}

	for j := uint32(0); j <= p.N; j++ {
		Z[j] = polyring.NewEmpty()
		CQ[j] = make([]*pbc.Element, p.N+1)

		for k := uint32(0); k <= p.N; k++ {
			CQ[j][k] = KZG.NewG1()
		}
		CZ[j] = KZG.NewG1()
		wZ[j] = KZG.NewG1()
	}

	//TODO: use crypto/rand instead
	var rnd = rand.New(rand.NewSource(time.Now().UTC().UnixNano()))
	var polyF, _ = polyring.NewRand(int(2*p.F), rnd, ecparamN)
	polyF.SetCoefficientBig(0, gmp.NewInt(0))

	//Q keeps the polynomials generates by all parties.
	//Q[p.PID+1][] denotes the 2t+1 polynomials generated by itself.
	//i and index in Q[i][index] start from 1
	var Q = make([][]polyring.Polynomial, p.N+1)
	for j := uint32(0); j <= p.N; j++ {
		Q[j] = make([]polyring.Polynomial, p.N+1)

		for k := uint32(0); k <= p.N; k++ {
			Q[j][k] = polyring.NewEmpty()
		}
	}

	//generate the 2t+1 t-degree random polynomials
	for j := uint32(1); j <= 2*p.F+1; j++ {
		polyF.EvalMod(gmp.NewInt(int64(j)), ecparamN, Fj)
		rnd = rand.New(rand.NewSource(time.Now().UTC().UnixNano()))
		Q[p.PID+1][j], _ = polyring.NewRand(int(p.F), rnd, ecparamN)
		Q[p.PID+1][j].SetCoefficientBig(0, Fj) // Q_i(0,index)=F_i(index)
	}

	startComChan <- true
	startReshareChan <- true

	//Commit
	go func() {
		<-startComChan

		for j := uint32(1); j <= 2*p.F+1; j++ {
			var tmpPoly = polyring.NewEmpty()
			Fj, _ := Q[p.PID+1][j].GetCoefficient(0)
			tmpPoly.SetCoefficientBig(0, &Fj)
			KZG.Commit(gFj, tmpPoly)

			Z[j].Sub(Q[p.PID+1][j], tmpPoly) //Z_ij(x)=Q_i(x,index)-F_j(index), which means Z_ij(0)=0
			KZG.Commit(CQ[p.PID+1][j], Q[p.PID+1][j])
			KZG.Commit(CZ[j], Z[j])
			KZG.CreateWitness(wZ[j], Z[j], gmp.NewInt(0))

			piI = append(piI, PiContent{
				j,
				KZG.NewG1().Set(CQ[p.PID+1][j]),
				KZG.NewG1().Set(CZ[j]),
				KZG.NewG1().Set(wZ[j]),
				KZG.NewG1().Set(gFj)})
		}

		var CommitMessage = new(protobuf.Commit)
		CommitMessage.Pi = make([]*protobuf.PiContent, 2*p.F+1)
		for j := uint32(0); j < 2*p.F+1; j++ {
			CommitMessage.Pi[j] = new(protobuf.PiContent)
			CommitMessage.Pi[j].J = piI[j].j
			CommitMessage.Pi[j].WZ0 = piI[j].WZ0.CompressedBytes()
			CommitMessage.Pi[j].CBj = piI[j].CBj.CompressedBytes()
			CommitMessage.Pi[j].CZj = piI[j].CZj.CompressedBytes()
			CommitMessage.Pi[j].GFj = piI[j].gFj.CompressedBytes()
		}
		CommitMessageData, _ := proto.Marshal(CommitMessage)
		RBCID := string(ID) + strconv.FormatUint(uint64(p.PID+1), 10)
		p.RBCSend(&protobuf.Message{Type: "Commit", Sender: p.PID, Id: ID, Data: CommitMessageData}, []byte(RBCID))
		fmt.Printf("[Proactivize Commit][New party %v] Have broadcasted the COM message, RBCID: %s \n", p.PID, RBCID)
	}()

	//Verify
	for j := uint32(1); j <= p.N; j++ {
		go func(j uint32) {
			m := p.RBCReceive([]byte(string(ID) + strconv.FormatUint(uint64(j), 10)))
			fmt.Printf("[Proactivize Verify][New party %v] Have received the COM message from new party %v, RBCID: %s\n", p.PID, m.Sender, string(ID)+strconv.FormatUint(uint64(j), 10))
			var ReceivedData protobuf.Commit
			proto.Unmarshal(m.Data, &ReceivedData)

			cmpOne := KZG.NewG1().Set0()
			interRes := KZG.NewG1()
			GFjList := make([]*pbc.Element, 2*p.F+1)
			for i := uint32(0); i < 2*p.F+1; i++ {
				GFjList[i] = KZG.NewG1()
				GFjList[i].SetCompressedBytes(ReceivedData.Pi[i].GFj)
			}

			mutexKZG.Lock()
			mutexPolyring.Lock()
			interRes = InterpolateComOrWit(2*p.F, 0, GFjList)
			mutexPolyring.Unlock()
			mutexKZG.Unlock()

			if !interRes.Equals(cmpOne) {
				fmt.Printf("[Proactivize Verify][New party %v] Verify \\prod {gFj}=1 FAIL, sender: %v interRes=%s\n", p.PID, m.Sender, interRes.String())
			} else {
				fmt.Printf("[Proactivize Verify][New party %v] Verify \\prod {gFj}=1 SUCCESS, sender: %v\n", p.PID, m.Sender)
			}

			var revertFlag = false

			//parse piJ from RBC1J
			for k := uint32(0); k < 2*p.F+1; k++ {
				mutexKZG.Lock()
				CQk := KZG.NewG1().SetCompressedBytes(ReceivedData.Pi[k].CBj)
				CZk := KZG.NewG1().SetCompressedBytes(ReceivedData.Pi[k].CZj)
				wZk := KZG.NewG1().SetCompressedBytes(ReceivedData.Pi[k].WZ0)
				GFk := KZG.NewG1().SetCompressedBytes(ReceivedData.Pi[k].GFj)
				mulRes := KZG.NewG1()
				mulRes.Add(CZk, GFk)
				verifyKZGOk := KZG.VerifyEval(CZk, gmp.NewInt(0), gmp.NewInt(0), wZk)
				mutexKZG.Unlock()

				if !CQk.Equals(mulRes) || !verifyKZGOk {
					fmt.Printf("[Proactivize Verify][New party %v] Verify Zj[%v](0)=0 FAIL, j=%v\n", p.PID, k, j)
					revertFlag = true
					break
				} else {
					fmt.Printf("[Proactivize Verify][New party %v] Verify Zj[%v](0)=0 SUCCESS, j=%v\n", p.PID, k, j)
					//store the CQjk, where index=m.Sender+1, k=1,...,2t+1
					CQ[j][k+1].Set(CQk)
				}
			}

			if revertFlag {
				//discard the previously stored CQjk
				for k := 0; uint32(k) < 2*p.F+1; k++ {
					CQ[j][k] = KZG.NewG1()
				}
			} else {
				fmt.Printf("[Proactivize Verfiy][New party %v] Verify pi_j from RBC_1j SUCCESS, j = %v\n", p.PID, j)
			}

			//Interpolate and set the remaining CQjk
			for k := 2*p.F + 2; k <= p.N; k++ {
				CQ[j][k] = InterpolateComOrWit(2*p.F, k, CQ[j][1:])
			}
			flgCom[j] = true
			startVoteChan[j] <- true
			startRecoverChan[j] <- true
			startRefreshChan[j] <- true
		}(j)
	}

	//Reshare
	go func() {
		<-startReshareChan
		fmt.Printf("[Proactivize Reshare][New party %v] Reshare starts\n", p.PID)

		// var wQ = make([][]*pbc.Element, p.N+1)
		for k := uint32(1); k <= p.N; k++ {
			var reshareMessage protobuf.Reshare
			//in reshareMessage, index 0 is used (unlike the other slices)
			reshareMessage.Qk = make([][]byte, 2*p.F+1)
			reshareMessage.WQk = make([][]byte, 2*p.F+1)

			for j := uint32(1); j <= 2*p.F+1; j++ {
				var tmpQkj = gmp.NewInt(0)
				var tmpwQ = KZG.NewG1()
				Q[p.PID+1][j].EvalMod(gmp.NewInt(int64(k)), ecparamN, tmpQkj)
				KZG.CreateWitness(tmpwQ, Q[p.PID+1][j], gmp.NewInt(int64(k))) // changed.

				reshareMessage.WQk[j-1] = tmpwQ.CompressedBytes()
				reshareMessage.Qk[j-1] = tmpQkj.Bytes()
				vQ[p.PID+1][j][k].Set(tmpQkj)
				wQ[p.PID+1][j][k].Set(tmpwQ)
			}

			reshareData, _ := proto.Marshal(&reshareMessage)
			p.Send(&protobuf.Message{Type: "Reshare", Id: ID, Sender: p.PID, Data: reshareData}, k-1)
		}
		fmt.Printf("[Proactivize Reshare][New party %v] Have sent the Reshare messages\n", p.PID)
	}()

	//Vote
	var SigShare = make(map[uint32]map[uint32][]byte)
	for i := uint32(1); i <= p.N; i++ {
		SigShare[i] = make(map[uint32][]byte)
	}

	for ctr := uint32(1); ctr <= p.N; ctr++ {
		//j is not used here
		go func(ctr uint32) {
			m := <-p.GetMessage("Reshare", ID)
			var ReceivedReshareData protobuf.Reshare
			proto.Unmarshal(m.Data, &ReceivedReshareData)
			fmt.Printf("[Proactivize Vote][New party %v] Have received Reshare message from party %v\n", p.PID, m.Sender)

			indexJ := m.Sender + 1
			//wait until flgCom[indexJ]=1
			if !flgCom[indexJ] {
				// fmt.Printf("[Proactivize Vote][New party %v] Waiting for flgCom[%v]=1\n", p.PID, indexJ)
				<-startVoteChan[indexJ]
			}

			vjki := gmp.NewInt(0)
			wjki := KZG.NewG1()
			var verifyReshareOK = true

			for k := uint32(1); k <= 2*p.F+1; k++ {
				vjki.SetBytes(ReceivedReshareData.Qk[k-1])
				wjki.SetCompressedBytes(ReceivedReshareData.WQk[k-1])
				C := CQ[indexJ][k]
				mutexKZG.Lock()
				verifyReshareOK = KZG.VerifyEval(C, gmp.NewInt(int64(p.PID+1)), vjki, wjki)
				mutexKZG.Unlock()

				if !verifyReshareOK {
					fmt.Printf("[Proactivize Vote][New party %v] Verify Reshare message from party %v FAIL, CQ[%v][%v]: %s, vjki:%v, wjki:%s\n", p.PID, m.Sender, indexJ, k, CQ[indexJ][k].String(), vjki, wjki.String())
					break
				}
			}
			if verifyReshareOK {
				fmt.Printf("[Proactivize Vote][New party %v] Verify Reshare message from party %v ok\n", p.PID, m.Sender)

				//sign sig share for indexJ (index 0 is not used)
				SigShare[indexJ][p.PID+1], _ = tbls.Sign(SysSuite, p.SigSK, []byte(strconv.FormatUint(uint64(indexJ), 10)))

				//interpolate Qj(i,l) and wQj(i,l)
				lambda := make([]*gmp.Int, 2*p.F+1)
				knownIndexes := make([]*gmp.Int, 2*p.F+1)
				for k := 0; uint32(k) < 2*p.F+1; k++ {
					knownIndexes[k] = gmp.NewInt(int64(k + 1))
					lambda[k] = gmp.NewInt(int64(k + 1))
				}
				for l := uint32(1); l <= p.N; l++ {
					polyring.GetLagrangeCoefficients(2*p.F, knownIndexes, ecparamN, gmp.NewInt(int64(l)), lambda)
					vQ[indexJ][l][p.PID+1].SetInt64(int64(0))
					wQ[indexJ][l][p.PID+1].Set1()
					for k := uint32(1); k <= 2*p.F+1; k++ {
						vjki.SetBytes(ReceivedReshareData.Qk[k-1])
						wjki.SetCompressedBytes(ReceivedReshareData.WQk[k-1])
						var copyFijl = gmp.NewInt(0)
						var copyWijl = KZG.NewG1()
						var tt1 = gmp.NewInt(0) // temp mul result
						var tt2 = KZG.NewG1()   // temp mul result

						copyFijl.Set(vQ[indexJ][l][p.PID+1])
						copyWijl.Set(wQ[indexJ][l][p.PID+1])
						tt1.Mul(lambda[k-1], vjki)
						vQ[indexJ][l][p.PID+1].Add(copyFijl, tt1)
						tt2.MulBig(wjki, conv.GmpInt2BigInt(lambda[k-1]))
						wQ[indexJ][l][p.PID+1].Mul(copyWijl, tt2)
					}
					// send Recover
					var RecoverMessage protobuf.Recover
					RecoverMessage.Index = indexJ
					RecoverMessage.V = vQ[indexJ][l][p.PID+1].Bytes()
					RecoverMessage.W = wQ[indexJ][l][p.PID+1].CompressedBytes()
					RecoverMessage.SigShare = SigShare[indexJ][p.PID+1]
					RecoverMessageData, _ := proto.Marshal(&RecoverMessage)
					p.Send(&protobuf.Message{Type: "Recover", Id: ID, Sender: p.PID, Data: RecoverMessageData}, l-1)
				}
				fmt.Printf("[Proactivize Vote][New party %v] Have sent the Recover message, derived from Reshare from party %v\n", p.PID, m.Sender)

			}
		}(ctr)
	}

	//Recover
	var SRec = make([][]SRecElement, p.N+1) // start from 1
	var SSig = make([][]SSigElement, p.N+1) // start from 1
	var mutexSRec sync.Mutex
	for i := uint32(0); i <= p.N; i++ {
		SRec[i] = make([]SRecElement, 0)
		SSig[i] = make([]SSigElement, 0)
	}
	var InterpolatePolyX = make([]*gmp.Int, p.N+1)
	var InterpolatePolyY = make([]*gmp.Int, p.N+1)
	var CombinedSig = make([][]byte, p.N+1) // start from 1
	var CombinedFlag = make([]bool, p.N+1)  //start from 1
	var MVBAIn = new(protobuf.MVBAIN)
	MVBAIn.J = make([]uint32, 0)
	MVBAIn.Sig = make([][]byte, 0)
	var mutexMVBAIn sync.Mutex
	for i := uint32(0); i <= p.N; i++ {
		CombinedFlag[i] = false
	}
	var MVBASent = false
	MVBAResChan := make(chan []byte, 1)

	RecoverMsgChan := make([]chan RecoverMsg, p.N+1) // index 0 is not used
	for i := uint32(0); i <= p.N; i++ {
		RecoverMsgChan[i] = make(chan RecoverMsg)
	}

	//Recover - receiving messages
	go func() {
		for {
			m := <-p.GetMessage("Recover", ID)

			var ReceivedRecoverData protobuf.Recover
			proto.Unmarshal(m.Data, &ReceivedRecoverData)
			k := ReceivedRecoverData.Index
			fmt.Printf("[Proactivize Recover][New party %v] Have received Recover message from party %v, k=%v\n", p.PID, m.Sender, k)
			v := gmp.NewInt(0).SetBytes(ReceivedRecoverData.V)
			w := KZG.NewG1().SetCompressedBytes(ReceivedRecoverData.W)
			RecoverMsgChan[k] <- RecoverMsg{m.Sender, k, v, w, ReceivedRecoverData.SigShare}
		}
	}()

	//Recover - handling messages
	for k := uint32(1); k <= p.N; k++ {
		go func(k uint32) {
			if !flgCom[k] {
				//wait until flgCom[k]=1
				fmt.Printf("[Proactivize Recover][New party %v] Waiting for flgCom[%v]=1\n", p.PID, k)
				<-startRecoverChan[k]
			}
			for {
				ReceivedRecoverMsg := <-RecoverMsgChan[k]
				var mSender = ReceivedRecoverMsg.sender
				var wkij = KZG.NewG1().Set(ReceivedRecoverMsg.w)
				var vkij = gmp.NewInt(0).Set(ReceivedRecoverMsg.v)
				var ReceivedSigShare = ReceivedRecoverMsg.sigShare
				var C = CQ[k][p.PID+1]

				mutexKZG.Lock()
				KZGVerifyOk := KZG.VerifyEval(C, gmp.NewInt(int64(mSender+1)), vkij, wkij)
				mutexKZG.Unlock()
				SigShareVerifyOk := tbls.Verify(SysSuite, p.SigPK, []byte(strconv.FormatUint(uint64(k), 10)), ReceivedSigShare)

				if KZGVerifyOk && (SigShareVerifyOk == nil) {
					mutexSRec.Lock()
					SRec[k] = append(SRec[k], SRecElement{mSender + 1, vkij})
					fmt.Printf("[Proactivize Recover][New party %v] Verify Recover message from party %v SUCCESS, k=%v. Current Srec[%v] lenth: %v\n", p.PID, mSender, k, k, len(SRec[k]))
					if !flgRec[k] && uint32(len(SRec[k])) >= p.F+1 {
						for i := 0; i < len(SRec[k]); i++ {
							InterpolatePolyX[i] = gmp.NewInt(int64(SRec[k][i].index))
							InterpolatePolyY[i] = SRec[k][i].v
						}

						Q[k][p.PID+1], _ = interpolation.LagrangeInterpolate(int(p.F), InterpolatePolyX[:p.F+1], InterpolatePolyY[:p.F+1], ecparamN)
						flgRec[k] = true
					}

					SSig[k] = append(SSig[k], SSigElement{mSender + 1, ReceivedSigShare})
					if !CombinedFlag[k] && uint32(len(SSig[k])) >= 2*p.F+1 {
						var tmpSig = make([][]byte, len(SSig))
						for i := 0; i < len(SSig[k]); i++ {
							tmpSig[i] = SSig[k][i].Sig
						}
						//converting uint32 to int is dangerous
						CombinedSig[k], _ = tbls.Recover(SysSuite, p.SigPK, []byte(strconv.FormatUint(uint64(k), 10)), tmpSig, int(2*p.F), int(p.N))
						CombinedFlag[k] = true
						fmt.Printf("[Proactivize Recover][New party %v] Have combined a full signature for party %v, holding %v signatures now\n", p.PID, k, len(MVBAIn.Sig)+1)

						//MVBA
						mutexMVBAIn.Lock()
						MVBAIn.J = append(MVBAIn.J, k)
						MVBAIn.Sig = append(MVBAIn.Sig, CombinedSig[k])
						if !MVBASent && uint32(len(MVBAIn.J)) >= p.F+1 {
							fmt.Printf("[Proactivize MVBA][New party %v] Call MVBA with input length %v\n", p.PID, len(MVBAIn.J))
							MVBAInData, _ := proto.Marshal(MVBAIn)
							MVBAResChan <- MainProcess(p, ID, MVBAInData, []byte{}) //temporary solution (MainProcess means smvba.MainProcess)
							MVBASent = true
						}
						mutexMVBAIn.Unlock()
					}
					mutexSRec.Unlock()
				}
				if MVBASent {
					break
				}
			}
		}(k)
	}

	//Refresh
	//TODO: implement MVBA's verification
	MVBAResData := <-MVBAResChan
	var MVBARes protobuf.MVBAIN
	proto.Unmarshal(MVBAResData, &MVBARes)
	fmt.Printf("[Proactivize MVBA][New party %v] Output MBVA result: %v\n", p.PID, MVBARes.J)

	var CQsum = make([]*pbc.Element, p.N+1)
	var Qsum = polyring.NewEmpty()

	for i := uint32(0); i <= p.N; i++ {
		CQsum[i] = KZG.NewG1()
	}

	for _, j := range MVBARes.J {

		//wait until all related flaCom = 1
		if !flgCom[j] {
			<-startRefreshChan[j]
		}

		mutexPolyring.Lock()
		copyedQ := polyring.NewEmpty()
		copyedQ.ResetTo(Qsum)
		Qsum.Add(copyedQ, Q[j][p.PID+1])
		Qsum.Mod(ecparamN)
		mutexPolyring.Unlock()

		for i := uint32(1); i <= p.N; i++ {
			CQsum[i].ThenAdd(CQ[j][i])
		}
	}

	fmt.Printf("[Proactivize Refresh][New party %v] Have recovered Qsum:\n", p.PID)
	Qsum.Print("Qsum(x)")
	// fmt.Printf("[Proactivize Refresh][New party %v] Previous reducedShare B(x,i):\n", p.PID)
	// p.reducedShare.Print(fmt.Sprintf("B(x,%v)", p.PID+1))
	copyedHalfShare := polyring.NewEmpty()
	copyedHalfShare.ResetTo(p.reducedShare)
	p.reducedShare.Add(Qsum, copyedHalfShare)
	p.reducedShare.Mod(ecparamN)
	fmt.Printf("[Proactivize Refresh][New party %v] New reducedShare B'(x,i):\n", p.PID)
	p.reducedShare.Print(fmt.Sprintf("B'(x,%v)", p.PID+1))

	//-------------------------------------ShareDist-------------------------------------
	//Init
	fmt.Printf("[ShareDist][New party %v] Start ShareDist\n", p.PID)
	var startCommitChan = make(chan bool, 1)
	var startDistributeChan = make(chan bool, 1)
	var SCom = make(map[uint32]SComElement)
	var SComChan = make([]chan bool, p.N+1)
	for i := uint32(0); i < p.N+1; i++ {
		SComChan[i] = make(chan bool, 1)
	}
	var SB = make([]SBElement, 0)
	var SComMutex sync.Mutex
	startCommitChan <- true
	startDistributeChan <- true

	//Distribute
	go func() {
		<-startDistributeChan
		var wBij = KZG.NewG1()
		var Bij = gmp.NewInt(0)

		for j := uint32(1); j <= p.N; j++ {
			p.reducedShare.EvalMod(gmp.NewInt(int64(j)), ecparamN, Bij)
			KZG.CreateWitness(wBij, p.reducedShare, gmp.NewInt(int64(j)))
			var ShareDistMessage protobuf.ShareDist
			ShareDistMessage.B = Bij.Bytes()
			ShareDistMessage.WB = wBij.CompressedBytes()
			ShareDistMessageData, _ := proto.Marshal(&ShareDistMessage)
			p.Send(&protobuf.Message{Type: "ShareDist", Id: ID, Sender: p.PID, Data: ShareDistMessageData}, j-1)
		}
		fmt.Printf("[ShareDist][New party %v] Have sent the ShareDist messages\n", p.PID)
	}()

	//Commit
	go func() {
		CB := KZG.NewG1()
		KZG.Commit(CB, p.reducedShare)
		var NewcommitMessage protobuf.NewCommit
		NewcommitMessage.CB = CB.CompressedBytes()
		p.RBCSend(&protobuf.Message{Type: "NewCommit", Id: ID, Sender: p.PID, Data: NewcommitMessage.CB}, []byte(string(ID)+"ShareDist"+strconv.FormatUint(uint64(p.PID+1), 10)))
		// fmt.Printf("[ShareDist][New party %v] Have broadcasted NewCommit, CB: %s\n", p.PID, CB.String())
	}()

	//Verify
	for j := uint32(1); j <= p.N; j++ {
		go func(j uint32) {
			m := p.RBCReceive([]byte(string(ID) + "ShareDist" + strconv.FormatUint(uint64(j), 10)))
			NewCommitData := m.Data
			var ReceivedCB = KZG.NewG1().SetCompressedBytes(NewCommitData)
			oldCB := KZG.NewG1()
			if j <= 2*p.F+1 {
				oldCB.Set(p.Proof.PiContents[j].CBj)
			} else {
				CBList := make([]*pbc.Element, 2*p.F+2)
				for i := uint32(1); i <= 2*p.F+1; i++ {
					CBList[i] = KZG.NewG1().Set(p.Proof.PiContents[i].CBj)
				}
				mutexKZG.Lock()
				oldCB = InterpolateComOrWit(2*p.F, j, CBList[1:])
				mutexKZG.Unlock()
			}

			addResult := KZG.NewG1()
			addResult.Add(oldCB, CQsum[j])
			if ReceivedCB.Equals(addResult) {
				fmt.Printf("[ShareDist][New party %v] Verify NEWCOM from RBC_2j SUCCESS, j=%v\n", p.PID, j)
				SComMutex.Lock()
				SCom[j] = SComElement{
					index: j,
					CB:    KZG.NewG1().Set(ReceivedCB),
				}
				SComMutex.Unlock()
				SComChan[j] <- true
			} else {
				fmt.Printf("[ShareDist][New party %v] Verify NEWCOM from RBC_2j FAIL, j=%v, receivedCB:%s, addResult:%s\n", p.PID, j, ReceivedCB.String(), addResult.String())
			}
		}(j)
	}

	//Interpolate
	var SuccessSent = false
	var SuccessSentChan = make(chan bool, 1)

	for index := uint32(0); index < p.N; index++ {
		//index is not used here
		go func(index uint32) {
			m := <-p.GetMessage("ShareDist", ID)

			var ReceivedShareDistData protobuf.ShareDist
			proto.Unmarshal(m.Data, &ReceivedShareDistData)
			// fmt.Printf("[ShareDist][New party %v] Have received ShareDist message from party %v\n", p.PID, m.Sender)

			j := m.Sender + 1
			//wait until the commitment of B'(x,j) is included in SCom
			<-SComChan[j]

			currentCB := SCom[j].CB
			var vjShareDist = gmp.NewInt(0).SetBytes(ReceivedShareDistData.B)
			var wjShareDist = KZG.NewG1().SetCompressedBytes(ReceivedShareDistData.WB)

			mutexKZG.Lock()
			verifyKZGOk := KZG.VerifyEval(currentCB, gmp.NewInt(int64(p.PID+1)), vjShareDist, wjShareDist)
			mutexKZG.Unlock()
			if verifyKZGOk {
				fmt.Printf("[ShareDist][New party %v] Verify ShareDist message from new party %v SUCCESS\n", p.PID, j)
				SB = append(SB, SBElement{
					index: j,
					CB:    KZG.NewG1().Set(currentCB),
					v:     gmp.NewInt(0).Set(vjShareDist),
					w:     KZG.NewG1().Set(wjShareDist),
				})

				if !SuccessSent && uint32(len(SB)) >= 2*p.F+1 {
					var DistX = make([]*gmp.Int, 2*p.F+1)
					var DistY = make([]*gmp.Int, 2*p.F+1)
					//interpolate from the first 2t+1 items in SB
					for t := uint32(0); t < 2*p.F+1; t++ {
						DistX[t] = gmp.NewInt(int64(SB[t].index))
						DistY[t] = gmp.NewInt(0).Set(SB[t].v)
					}

					p.fullShare, _ = interpolation.LagrangeInterpolate(2*int(p.F), DistX, DistY, ecparamN)
					fmt.Printf("[ShareDist][New party %v] Recover the fullShare B'(i,y):\n", p.PID)
					p.fullShare.Print(fmt.Sprintf("B'(%v,y)", p.PID+1))
					var SuccessMessage protobuf.Success
					SuccessMessage.Nothing = []byte("s") // Send whatever you want
					SuccessData, _ := proto.Marshal(&SuccessMessage)
					p.Broadcast(&protobuf.Message{Type: "Success", Id: ID, Sender: p.PID, Data: SuccessData})
					SuccessSent = true
					SuccessSentChan <- true
				}
			} else {
				fmt.Printf("[ShareDist][New party %v] Verify ShareDist message from new party %v FAIL\n", p.PID, j)
			}
		}(index)
	}

	// Receive Success Message
	// var ReceivedSuccessData protobuf.Success
	var SuccessCount = uint32(0)
	var EnterNormalChan = make(chan bool, 1)

	go func() {
		<-SuccessSentChan
		for {
			<-p.GetMessage("Success", ID)
			// the content is useless here
			// proto.Unmarshal(m.Data, &ReceivedSuccessData)
			SuccessCount++

			if SuccessCount >= 2*p.F+1 {
				fmt.Printf("[ShareDist][New party %v] Have collected %v SUCCESS messages, entering the normal state\n", p.PID, SuccessCount)
				EnterNormalChan <- true
				break
			}
		}
	}()
	<-EnterNormalChan
}
