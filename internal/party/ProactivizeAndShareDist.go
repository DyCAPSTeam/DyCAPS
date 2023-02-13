package party

import (
	"github.com/DyCAPSTeam/DyCAPS/internal/bls"
	"github.com/DyCAPSTeam/DyCAPS/internal/polyring"
	"github.com/DyCAPSTeam/DyCAPS/pkg/protobuf"
	"google.golang.org/protobuf/proto"
	"log"
	"strconv"
	"sync"
	"time"
)

func (p *HonestParty) ProactivizeAndShareDist(ID []byte) {

	p.ProactivizeStart = time.Now()

	var flgCom = make([]bool, p.N+1)
	var flgRec = make([]bool, p.N+1)

	var startCom = make(chan bool, 1)
	var ComSent = make(chan bool, 1)

	var startReshare = make(chan bool, 1)
	var ReshareSent = make(chan bool, 1)

	var startVote = make([]chan bool, p.N+1)
	var VoteSent = make([]chan bool, p.N+1)

	var RecDone = make([]chan bool, p.N+1)

	var startRecover = make([]chan bool, p.N+1)
	for i := uint32(0); i <= p.N; i++ {
		flgCom[i] = false
		flgRec[i] = false
		startVote[i] = make(chan bool, 1)
		VoteSent[i] = make(chan bool, 1)
		RecDone[i] = make(chan bool, 1)
		startRecover[i] = make(chan bool, 1)
	}
	var ProactivizeDone = make(chan bool, 1)

	var piI = make([]PiContent, 0)

	var Z = make([][]bls.Fr, p.N+1)         //Z_ij(x)=Q_i(x,index)-F_j(index), which means Z_ij(0)=0
	var Fj = bls.ZERO                       //F_i(index)
	var gFj bls.G1Point                     //g^F_i(index)
	var CQ = make([][]bls.G1Point, p.N+1)   //CQ[*][0] is not used
	var CZ = make([]bls.G1Point, p.N+1)     //commitment of Zj(x)
	var wZ = make([]bls.G1Point, p.N+1)     //witness of Zj(0)=0
	var vQ = make([][][]bls.Fr, p.N+1)      //vQ[i][index][k] denotes the value of Qi(x,index), where x=k
	var wQ = make([][][]bls.G1Point, p.N+1) //wQ[i][index][k] denotes the witness of Qi(x,index), where x=k

	for i := uint32(0); i <= p.N; i++ {
		vQ[i] = make([][]bls.Fr, p.N+1)
		wQ[i] = make([][]bls.G1Point, p.N+1)

		for j := uint32(0); j <= p.N; j++ {
			vQ[i][j] = make([]bls.Fr, p.N+1)
			wQ[i][j] = make([]bls.G1Point, p.N+1)
		}
	}

	for j := uint32(0); j <= p.N; j++ {
		Z[j] = make([]bls.Fr, p.F+1)
		CQ[j] = make([]bls.G1Point, p.N+1)
	}

	polyF := polyring.NewRandPoly(int(2 * p.F))
	bls.CopyFr(&polyF[0], &bls.ZERO)

	//Q keeps the polynomials generates by all parties.
	//Q[p.PID+1][] denotes the 2t+1 polynomials generated by itself.
	//i and index in Q[i][index] start from 1
	var Q = make([][][]bls.Fr, p.N+1)

	for j := uint32(0); j <= p.N; j++ {
		Q[j] = make([][]bls.Fr, p.N+1)

		for k := uint32(0); k <= p.N; k++ {
			Q[j][k] = make([]bls.Fr, p.F+1)
		}
	}

	//generate the 2t+1 t-degree random polynomials
	for j := uint32(1); j <= 2*p.F+1; j++ {
		var positionJ bls.Fr
		bls.AsFr(&positionJ, uint64(j))
		bls.EvalPolyAt(&Fj, polyF, &positionJ)
		Q[p.PID+1][j] = polyring.NewRandPoly(int(p.F))
		bls.CopyFr(&Q[p.PID+1][j][0], &Fj) // Q_i(0,index)=F_i(index)
	}

	startCom <- true
	startReshare <- true

	//Commit
	go func() {
		<-startCom

		for j := uint32(1); j <= 2*p.F+1; j++ {
			p.mutexKZG.Lock()
			bls.MulG1(&gFj, &bls.GenG1, &Q[p.PID+1][j][0])
			p.mutexKZG.Unlock()
			copy(Z[j], Q[p.PID+1][j])
			bls.CopyFr(&Z[j][0], &bls.ZERO) //Z_ij(x)=Q_i(x,index)-F_j(index), which means Z_ij(0)=0

			p.mutexKZG.Lock()
			CQ[p.PID+1][j] = *p.KZG.CommitToPoly(Q[p.PID+1][j])
			CZ[j] = *p.KZG.CommitToPoly(Z[j])
			wZ[j] = *p.KZG.ComputeProofSingle(Z[j], bls.ZERO)
			p.mutexKZG.Unlock()

			piI = append(piI, PiContent{
				j,
				CQ[p.PID+1][j],
				CZ[j],
				wZ[j],
				gFj})
		}

		var CommitMessage = new(protobuf.Commit)
		CommitMessage.Pi = make([]*protobuf.PiContent, 2*p.F+1)
		CommitMessage.PayloadMsg = p.Value
		for j := uint32(0); j < 2*p.F+1; j++ {
			CommitMessage.Pi[j] = new(protobuf.PiContent)
			CommitMessage.Pi[j].J = piI[j].j
			CommitMessage.Pi[j].WZ0 = bls.ToCompressedG1(&piI[j].WZ0)
			CommitMessage.Pi[j].CBj = bls.ToCompressedG1(&piI[j].CBj)
			CommitMessage.Pi[j].CZj = bls.ToCompressedG1(&piI[j].CZj)
			CommitMessage.Pi[j].GFj = bls.ToCompressedG1(&piI[j].gFj)
		}
		CommitMessageData, _ := proto.Marshal(CommitMessage)

		RBCID := string(ID) + "_1," + strconv.FormatUint(uint64(p.PID+1), 10)
		p.RBCSend(&protobuf.Message{Type: "Commit", Sender: p.PID, Id: ID, Data: CommitMessageData}, []byte(RBCID))
		ComSent <- true
		//log.Printf("[Proactivize Commit][New party %v] Have broadcasted the COM message, RBCID: %s \n", p.PID, RBCID)
		//log.Printf("[Proactivize Commit][New party %v] Commit done\n", p.PID)
	}()

	//Verify
	for j := uint32(1); j <= p.N; j++ {
		go func(j uint32) {
			m := p.RBCReceive([]byte(string(ID) + "_1," + strconv.FormatUint(uint64(j), 10)))
			//log.Printf("[Proactivize Verify][New party %v] Have received the COM message from new party %v, RBCID: %s\n", p.PID, m.Sender, string(ID)+strconv.FormatUint(uint64(j), 10))
			var ReceivedData protobuf.Commit
			proto.Unmarshal(m.Data, &ReceivedData)

			GFjList := make([]bls.G1Point, 2*p.F+1)
			for i := uint32(0); i < 2*p.F+1; i++ {
				tmpGFj, _ := bls.FromCompressedG1(ReceivedData.Pi[i].GFj)
				bls.CopyG1(&GFjList[i], tmpGFj)
			}

			interRes := p.InterpolateComOrWit(2*p.F, 0, GFjList)

			var revertFlag = false
			if !bls.EqualG1(&interRes, &bls.ZeroG1) {
				revertFlag = true
				log.Printf("[Proactivize Verify][New party %v] Verify \\prod {gFj}=1 FAIL, sender: %v interRes=%s\n", p.PID, m.Sender, interRes.String())
			}
			// else {
			// log.Printf("[Proactivize Verify][New party %v] Verify \\prod {gFj}=1 SUCCESS, sender: %v\n", p.PID, m.Sender)
			// }

			//parse piJ from RBC1J
			for k := uint32(0); k < 2*p.F+1; k++ {
				CQk, _ := bls.FromCompressedG1(ReceivedData.Pi[k].CBj)
				CZk, _ := bls.FromCompressedG1(ReceivedData.Pi[k].CZj)
				wZk, _ := bls.FromCompressedG1(ReceivedData.Pi[k].WZ0)
				GFk, _ := bls.FromCompressedG1(ReceivedData.Pi[k].GFj)

				var mulRes bls.G1Point
				p.mutexKZG.Lock()
				bls.AddG1(&mulRes, CZk, GFk)

				verifyKZGOk := p.KZG.CheckProofSingle(CZk, wZk, &bls.ZERO, &bls.ZERO)
				p.mutexKZG.Unlock()

				if !bls.EqualG1(CQk, &mulRes) || !verifyKZGOk {
					log.Printf("[Proactivize Verify][New party %v] Verify Zj[%v](0)=0 FAIL, j=%v\n", p.PID, k, j)
					revertFlag = true
					// break
				} else {
					// log.Printf("[Proactivize Verify][New party %v] Verify Zj[%v](0)=0 SUCCESS, j=%v\n", p.PID, k, j)
					//store the CQjk, where index=m.Sender+1, k=1,...,2t+1
					bls.CopyG1(&CQ[j][k+1], CQk)
				}
			}

			if revertFlag {
				//discard the previously stored CQjk
				for k := 0; uint32(k) < 2*p.F+1; k++ {
					CQ[j][k] = bls.ZeroG1
					//startRecover[j] <- true
				}
			} else {
				// fmt.Printf("[Proactivize Verfiy][New party %v] Verify pi_j from RBC_1j SUCCESS, j = %v\n", p.PID, j)
				//Interpolate and set the remaining CQjk
				for k := 2*p.F + 2; k <= p.N; k++ {

					CQ[j][k] = p.InterpolateComOrWit(2*p.F, k, CQ[j][1:2*p.F+2])

				}
				flgCom[j] = true
				startVote[j] <- true
				startRecover[j] <- true
				//log.Printf("[Proactivize Verify][New party %v] Verify Com message from RBC_1,%v done\n", p.PID, j)
			}
		}(j)
	}

	//Reshare
	go func() {
		<-startReshare
		//log.Printf("[Proactivize Reshare][New party %v] Reshare starts\n", p.PID)

		// var wQ = make([][]*pbc.Element, p.N+1)
		for k := uint32(1); k <= p.N; k++ {
			var reshareMessage protobuf.Reshare
			//in reshareMessage, index 0 is used (unlike the other slices)
			reshareMessage.Qk = make([][]byte, 2*p.F+1)
			reshareMessage.WQk = make([][]byte, 2*p.F+1)

			for j := uint32(1); j <= 2*p.F+1; j++ {
				var tmpQkj bls.Fr
				var tmpwQ bls.G1Point
				var positionQ bls.Fr
				bls.AsFr(&positionQ, uint64(k))
				bls.EvalPolyAt(&tmpQkj, Q[p.PID+1][j], &positionQ)

				p.mutexKZG.Lock()
				tmpwQ = *p.KZG.ComputeProofSingle(Q[p.PID+1][j], positionQ)
				p.mutexKZG.Unlock()

				reshareMessage.WQk[j-1] = bls.ToCompressedG1(&tmpwQ)
				tmpQkj_Bytes_Array := bls.FrTo32(&tmpQkj)
				tmpQkj_Bytes_Slice := make([]byte, 32)
				copy(tmpQkj_Bytes_Slice, tmpQkj_Bytes_Array[:])
				reshareMessage.Qk[j-1] = tmpQkj_Bytes_Slice

				bls.CopyFr(&vQ[p.PID+1][j][k], &tmpQkj)
				bls.CopyG1(&wQ[p.PID+1][j][k], &tmpwQ)
			}

			reshareData, _ := proto.Marshal(&reshareMessage)
			p.Send(&protobuf.Message{Type: "Reshare", Id: ID, Sender: p.PID, Data: reshareData}, k-1)
		}
		ReshareSent <- true
		//log.Printf("[Proactivize Reshare][New party %v] Reshare done\n", p.PID)
	}()

	//Vote
	// var SigShare = make(map[uint32]map[uint32][]byte)
	// for i := uint32(1); i <= p.N; i++ {
	// 	SigShare[i] = make(map[uint32][]byte)
	// }

	for ctr := uint32(1); ctr <= p.N; ctr++ {
		//ctr is not used here
		go func(ctr uint32) {
			m := <-p.GetMessage("Reshare", ID)
			var ReceivedReshareData protobuf.Reshare
			proto.Unmarshal(m.Data, &ReceivedReshareData)
			// fmt.Printf("[Proactivize Vote][New party %v] Have received Reshare message from party %v\n", p.PID, m.Sender)

			indexJ := m.Sender + 1
			//wait until flgCom[indexJ]=1
			if !flgCom[indexJ] {
				// fmt.Printf("[Proactivize Vote][New party %v] Waiting for flgCom[%v]=1\n", p.PID, indexJ)
				<-startVote[indexJ]
			}

			var vjki = make([]bls.Fr, 2*p.F+2)
			var wjki = make([]bls.G1Point, 2*p.F+2)
			var verifyReshareOK = false

			for k := uint32(1); k <= 2*p.F+1; k++ {
				vjki_bytes := [32]byte{}
				copy(vjki_bytes[:], ReceivedReshareData.Qk[k-1])
				bls.FrFrom32(&vjki[k], vjki_bytes)
				tmpWjki, _ := bls.FromCompressedG1(ReceivedReshareData.WQk[k-1])
				wjki[k] = *tmpWjki

				C := CQ[indexJ][k]
				var position_vjki bls.Fr
				bls.AsFr(&position_vjki, uint64(p.PID+1))
				p.mutexKZG.Lock()
				verifyReshareOK = p.KZG.CheckProofSingle(&C, &wjki[k], &position_vjki, &vjki[k])
				p.mutexKZG.Unlock()
				if !verifyReshareOK {
					log.Printf("[Proactivize Vote][New party %v] Verify Reshare message from party %v FAIL, CQ[%v][%v]: %s, vjki:%v, wjki:%s\n", p.PID, m.Sender, indexJ, k, CQ[indexJ][k].String(), vjki[k].String(), wjki[k].String())
					// break
				}
			}
			if verifyReshareOK {
				//log.Printf("[Proactivize Vote][New party %v] Verify Reshare message from party %v ok\n", p.PID, m.Sender)

				//sign sig share for indexJ (index 0 is not used)
				SigShare, _ := p.tblsScheme.Sign(p.SigSK, []byte(strconv.FormatUint(uint64(indexJ), 10)))
				//prepare the Recover message
				var RecoverMessage protobuf.Recover
				RecoverMessage.Index = indexJ
				RecoverMessage.SigShare = SigShare

				for l := uint32(1); l <= p.N; l++ {
					if l <= 2*p.F+1 {
						vQ[indexJ][l][p.PID+1] = vjki[l]
						wQ[indexJ][l][p.PID+1] = wjki[l]
					} else {
						vQ[indexJ][l][p.PID+1] = bls.LinCombFr(vjki[1:], p.LagrangeCoefficients[l])
						p.mutexKZG.Lock()
						wQ[indexJ][l][p.PID+1] = *bls.LinCombG1(wjki[1:], p.LagrangeCoefficients[l])
						p.mutexKZG.Unlock()
					}
					// send Recover

					tmpVQ_Array := bls.FrTo32(&vQ[indexJ][l][p.PID+1])
					tmpVQ_Slice := make([]byte, 32)
					copy(tmpVQ_Slice, tmpVQ_Array[:])
					RecoverMessage.V = tmpVQ_Slice
					RecoverMessage.W = bls.ToCompressedG1(&wQ[indexJ][l][p.PID+1])
					RecoverMessageData, _ := proto.Marshal(&RecoverMessage)
					p.Send(&protobuf.Message{Type: "Recover", Id: ID, Sender: p.PID, Data: RecoverMessageData}, l-1)
				}
				VoteSent[indexJ] <- true
				//log.Printf("[Proactivize Vote][New party %v] Have sent the Recover message, derived from Reshare from party %v\n", p.PID, m.Sender)
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
	var InterpolatePolyX = make([]bls.Fr, p.N+1)
	var InterpolatePolyY = make([]bls.Fr, p.N+1)
	var CombinedSig = make([][]byte, p.N+1) // start from 1
	var CombinedFlag = make([]bool, p.N+1)  //start from 1
	for i := uint32(0); i <= p.N; i++ {
		CombinedFlag[i] = false
	}

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
			//log.Printf("[Proactivize Recover][New party %v] Have received Recover message from party %v, k=%v\n", p.PID, m.Sender, k)
			var tmpV_Array [32]byte
			copy(tmpV_Array[:], ReceivedRecoverData.V)
			var v bls.Fr
			bls.FrFrom32(&v, tmpV_Array)
			w, _ := bls.FromCompressedG1(ReceivedRecoverData.W)
			RecoverMsgChan[k] <- RecoverMsg{m.Sender, k, v, *w, ReceivedRecoverData.SigShare}
		}
	}()

	//Recover - handling messages
	var mutexMVBAIn sync.Mutex
	var MVBAIn = new(protobuf.MVBAIN)
	MVBAIn.J = make([]uint32, 0)
	MVBAIn.Sig = make([][]byte, 0)
	var MVBASent = false
	MVBAResChan := make(chan []byte, 1)
	for k := uint32(1); k <= p.N; k++ {
		go func(k uint32) {
			if !flgCom[k] {
				//wait until flgCom[k]=1
				// log.Printf("[Proactivize Recover][New party %v] Waiting for flgCom[%v]=1\n", p.PID, k)
				<-startRecover[k]
			}
			for {
				ReceivedRecoverMsg := <-RecoverMsgChan[k]
				var mSender = ReceivedRecoverMsg.sender
				wkij := ReceivedRecoverMsg.w
				vkij := ReceivedRecoverMsg.v
				ReceivedSigShare := ReceivedRecoverMsg.sigShare
				C := CQ[k][p.PID+1]
				var index bls.Fr
				bls.AsFr(&index, uint64(mSender+1))

				p.mutexKZG.Lock()
				KZGVerifyOk := p.KZG.CheckProofSingle(&C, &wkij, &index, &vkij)
				p.mutexKZG.Unlock()

				SigShareVerifyOk := p.tblsScheme.VerifyPartial(p.SigPK, []byte(strconv.FormatUint(uint64(k), 10)), ReceivedSigShare)

				if KZGVerifyOk && (SigShareVerifyOk == nil) {
					mutexSRec.Lock()
					SRec[k] = append(SRec[k], SRecElement{mSender + 1, vkij})
					//log.Printf("[Proactivize Recover][New party %v] Verify Recover message from party %v SUCCESS, k=%v. Current Srec[%v] lenth: %v\n", p.PID, mSender, k, k, len(SRec[k]))
					if !flgRec[k] && uint32(len(SRec[k])) >= p.F+1 {
						for i := 0; i < len(SRec[k]); i++ {
							bls.AsFr(&InterpolatePolyX[i], uint64(SRec[k][i].index))
							bls.CopyFr(&InterpolatePolyY[i], &SRec[k][i].v)
						}

						Q[k][p.PID+1] = polyring.LagrangeInterpolate(int(p.F), InterpolatePolyX[:p.F+1], InterpolatePolyY[:p.F+1])
						flgRec[k] = true
						RecDone[k] <- true
					}

					SSig[k] = append(SSig[k], SSigElement{mSender + 1, ReceivedSigShare})
					if !CombinedFlag[k] && uint32(len(SSig[k])) >= 2*p.F+1 {
						var tmpSig = make([][]byte, len(SSig))
						for i := 0; i < len(SSig[k]); i++ {
							tmpSig[i] = SSig[k][i].Sig
						}
						//converting uint32 to int is dangerous
						CombinedSig[k], _ = p.tblsScheme.Recover(p.SigPK, []byte(strconv.FormatUint(uint64(k), 10)), tmpSig, int(2*p.F), int(p.N))
						CombinedFlag[k] = true
						//log.Printf("[Proactivize Recover][New party %v] Have combined a full signature for party %v, holding %v signatures now\n", p.PID, k, len(MVBAIn.Sig)+1)

						//MVBA
						mutexMVBAIn.Lock()
						MVBAIn.J = append(MVBAIn.J, k)
						MVBAIn.Sig = append(MVBAIn.Sig, CombinedSig[k])
						if !MVBASent && uint32(len(MVBAIn.J)) >= p.F+1 {
							log.Printf("[Proactivize MVBA][New party %v] Call MVBA with input length %v\n", p.PID, len(MVBAIn.J))
							MVBAInData, _ := proto.Marshal(MVBAIn)
							MVBASent = true
							MVBAResChan <- MainProcess(p, ID, MVBAInData, []byte{}) //temporary solution (MainProcess means smvba.MainProcess)
						}
						mutexMVBAIn.Unlock()
					}
					mutexSRec.Unlock()
				} else {
					log.Printf("[Proactivize Recover][New party %v] Verify Recover message from party %v FAIL, k=%v. Current Srec[%v] lenth: %v\\n", p.PID, mSender, k, k, len(SRec[k]))
				}
				if MVBASent {
					//log.Printf("[Proactivize Recover][New party %v] Recover done\n", p.PID)
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
	log.Printf("[Proactivize MVBA][New party %v] MBVA done\n", p.PID)
	// log.Printf("[Proactivize MVBA][New party %v] Output MBVA result: %v\n", p.PID, MVBARes.J)

	var CQsum = make([]bls.G1Point, p.N+1)
	var Qsum = make([]bls.Fr, p.F+1)

	for _, j := range MVBARes.J {

		//wait until all related flgCom = 1
		if !flgCom[j] {
			<-RecDone[j]
			p.mutexKZG.Lock()
			CQ[j][p.PID+1] = *p.KZG.CommitToPoly(Q[j][p.PID+1])
			p.mutexKZG.Unlock()
		}

		for i := 0; uint32(i) < p.F+1; i++ {
			var tmpCoeff bls.Fr
			bls.AddModFr(&tmpCoeff, &Qsum[i], &Q[j][p.PID+1][i])
			bls.CopyFr(&Qsum[i], &tmpCoeff)
		}

		for i := uint32(1); i <= p.N; i++ {
			tmpCQ := CQsum[i]
			p.mutexKZG.Lock()
			bls.AddG1(&CQsum[i], &tmpCQ, &CQ[j][i])
			p.mutexKZG.Unlock()
		}
	}

	//log.Printf("[Proactivize Refresh][New party %v] Have recovered Qsum:\n", p.PID)
	//log.Println("Qsum(x):",PolyToString(Qsum))
	//log.Printf("[Proactivize Refresh][New party %v] Previous reducedShare B(x,i):\n", p.PID)
	//log.Printf("B(x,%v):%s",p.PID+1,PolyToString(p.reducedShare))
	copyedHalfShare := make([]bls.Fr, p.F+1)
	copy(copyedHalfShare, p.reducedShare)

	for i := 0; uint32(i) < p.F+1; i++ {
		var tmpCoeff bls.Fr
		bls.AddModFr(&tmpCoeff, &Qsum[i], &p.reducedShare[i])
		bls.CopyFr(&p.reducedShare[i], &tmpCoeff)
	}
	//log.Printf("[Proactivize Refresh][New party %v] New reducedShare B'(x,i):\n", p.PID)
	//log.Printf("B'(x,%v):%s",p.PID+1,PolyToString(p.reducedShare))
	//log.Printf("[Proactivize Refresh][New party %v] Refresh done\n", p.PID)
	p.ProactivizeEnd = time.Now()
	ProactivizeDone <- true

	//-------------------------------------ShareDist-------------------------------------
	//Init
	// log.Printf("[ShareDist][New party %v] Start ShareDist\n", p.PID)
	<-ProactivizeDone
	p.ShareDistStart = time.Now()

	var SCom = make(map[uint32]SComElement)
	var SComChan = make([]chan bool, p.N+1)
	for i := uint32(0); i < p.N+1; i++ {
		SComChan[i] = make(chan bool, 1)
	}
	var SB = make([]SBElement, 0)
	var SComMutex sync.Mutex

	var startCommitChan = make(chan bool, 1)
	startCommitChan <- true

	var startDistributeChan = make(chan bool, 1)
	startDistributeChan <- true

	var CommitSent = make(chan bool, 1)
	var DistributeSent = make(chan bool, 1)

	//Distribute
	go func() {
		<-startDistributeChan
		var wBij bls.G1Point
		var Bij bls.Fr

		for j := uint32(1); j <= p.N; j++ {
			var positionJ bls.Fr
			bls.AsFr(&positionJ, uint64(j))
			bls.EvalPolyAt(&Bij, p.reducedShare, &positionJ)
			p.mutexKZG.Lock()
			wBij = *p.KZG.ComputeProofSingle(p.reducedShare, positionJ)
			p.mutexKZG.Unlock()

			var ShareDistMessage protobuf.ShareDist
			tmpBij_Array := bls.FrTo32(&Bij)
			tmpBij_Slice := make([]byte, 32)
			copy(tmpBij_Slice, tmpBij_Array[:])
			ShareDistMessage.B = tmpBij_Slice
			ShareDistMessage.WB = bls.ToCompressedG1(&wBij)
			ShareDistMessageData, _ := proto.Marshal(&ShareDistMessage)
			p.Send(&protobuf.Message{Type: "ShareDist", Id: ID, Sender: p.PID, Data: ShareDistMessageData}, j-1)
		}
		DistributeSent <- true
		//log.Printf("[ShareDist Distribute][New party %v] Distribute done\n", p.PID)
	}()

	//Commit
	go func() {
		var CB bls.G1Point
		p.mutexKZG.Lock()
		CB = *p.KZG.CommitToPoly(p.reducedShare)
		p.mutexKZG.Unlock()
		var NewcommitMessage protobuf.NewCommit
		NewcommitMessage.CB = bls.ToCompressedG1(&CB)
		p.RBCSend(&protobuf.Message{Type: "NewCommit", Id: ID, Sender: p.PID, Data: NewcommitMessage.CB}, []byte(string(ID)+"_2,"+strconv.FormatUint(uint64(p.PID+1), 10)))
		CommitSent <- true
		//log.Printf("[ShareDist Commit][New party %v] Commit done\n", p.PID)
	}()

	//Verify
	for j := uint32(1); j <= p.N; j++ {
		go func(j uint32) {
			m := p.RBCReceive([]byte(string(ID) + "_2," + strconv.FormatUint(uint64(j), 10)))
			NewCommitData := m.Data
			ReceivedCB, _ := bls.FromCompressedG1(NewCommitData)
			var oldCB bls.G1Point
			if j <= 2*p.F+1 {
				bls.CopyG1(&oldCB, &p.Proof.PiContents[j].CBj)
			} else {
				CBList := make([]bls.G1Point, 2*p.F+2)
				for i := uint32(1); i <= 2*p.F+1; i++ {
					bls.CopyG1(&CBList[i], &p.Proof.PiContents[i].CBj)
				}
				oldCB = p.InterpolateComOrWit(2*p.F, j, CBList[1:])
			}

			var addResult bls.G1Point
			p.mutexKZG.Lock()
			bls.AddG1(&addResult, &oldCB, &CQsum[j])
			p.mutexKZG.Unlock()

			if bls.EqualG1(ReceivedCB, &addResult) {
				// log.Printf("[ShareDist][New party %v] Verify NEWCOM from RBC_2j SUCCESS, j=%v\n", p.PID, j)
				SComMutex.Lock()
				SCom[j] = SComElement{
					index: j,
					CB:    *ReceivedCB,
				}
				SComMutex.Unlock()
				SComChan[j] <- true
				//log.Printf("[ShareDist Verify][New party %v] %v-th Verify NewCom done\n", p.PID, j)
			} else {
				log.Printf("[ShareDist Verify][New party %v] Verify NewCom from RBC_2j FAIL, j=%v, receivedCB:%s, addResult:%s\n", p.PID, j, ReceivedCB.String(), addResult.String())
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
			var vjShareDist bls.Fr
			var wjShareDist *bls.G1Point
			var i bls.Fr

			var vjShareDist_Array [32]byte
			copy(vjShareDist_Array[:], ReceivedShareDistData.B)
			bls.FrFrom32(&vjShareDist, vjShareDist_Array)
			wjShareDist, _ = bls.FromCompressedG1(ReceivedShareDistData.WB)
			bls.AsFr(&i, uint64(p.PID+1))

			p.mutexKZG.Lock()
			verifyKZGOk := p.KZG.CheckProofSingle(&currentCB, wjShareDist, &i, &vjShareDist)
			p.mutexKZG.Unlock()

			if verifyKZGOk {
				//log.Printf("[ShareDist Interpolate][New party %v] Verify ShareDist message from new party %v SUCCESS\n", p.PID, j)
				SB = append(SB, SBElement{
					index: j,
					CB:    currentCB,
					v:     vjShareDist,
					w:     *wjShareDist,
				})

				if !SuccessSent && uint32(len(SB)) >= 2*p.F+1 {
					var DistX = make([]bls.Fr, 2*p.F+1)
					var DistY = make([]bls.Fr, 2*p.F+1)
					//interpolate from the first 2t+1 items in SB
					for t := uint32(0); t < 2*p.F+1; t++ {
						bls.AsFr(&DistX[t], uint64(SB[t].index))
						bls.CopyFr(&DistY[t], &SB[t].v)
					}

					p.fullShare = polyring.LagrangeInterpolate(2*int(p.F), DistX, DistY)
					//log.Printf("[ShareDist Interpolate][New party %v] Recover the fullShare B'(i,y):\n", p.PID)
					//log.Printf("(B'(%v,y)):%s",p.PID+1,PolyToString(p.fullShare))

					var SuccessMessage protobuf.Success
					SuccessMessage.Nothing = []byte("s") // Send whatever you want
					SuccessData, _ := proto.Marshal(&SuccessMessage)
					p.Broadcast(&protobuf.Message{Type: "Success", Id: ID, Sender: p.PID, Data: SuccessData})
					SuccessSent = true
					SuccessSentChan <- true
					//log.Printf("[ShareDist Interpolate][New party %v] Interpolate done\n", p.PID)
				}
			} else {
				log.Printf("[ShareDist Interpolate][New party %v] Verify ShareDist message from new party %v FAIL\n", p.PID, j)
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
				break
			}
		}
		p.ShareDistEnd = time.Now()
		log.Printf("[ShareDist][New party %v] Enter the normal state\n", p.PID)
		EnterNormalChan <- true
	}()
	// log.Printf("[New party %v] Waiting for ComSent", p.PID)
	// <-ComSent
	// log.Printf("[New party %v] Waiting for ReshareSent", p.PID)
	// <-ReshareSent
	// for i := uint32(1); i < p.N+1; i++ {
	// 	log.Printf("[New party %v] Waiting for VoteSent[%v]", p.PID, i)
	// 	<-VoteSent[i]
	// }

	// log.Printf("[New party %v] Waiting for CommitSent", p.PID)
	// <-CommitSent
	// log.Printf("[New party %v] Waiting for DistributeSent", p.PID)
	// <-DistributeSent
	<-EnterNormalChan
	log.Printf("[ShareDist][New party %v] Exit Handoff\n", p.PID)
}
