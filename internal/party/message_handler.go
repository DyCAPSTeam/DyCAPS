package party

/*
forked from https://github.com/xygdys/Buada_BFT
*/

import (
	"bytes"
	"context"
	"sync"

	"github.com/DyCAPSTeam/DyCAPS/pkg/core"
	"github.com/DyCAPSTeam/DyCAPS/pkg/protobuf"
	"github.com/DyCAPSTeam/DyCAPS/pkg/utils"

	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/sign/bls"
	"go.dedis.ch/kyber/v3/sign/tbls"
	"golang.org/x/crypto/sha3"
)

func messageHandler(ctx context.Context, p *HonestParty, IDr []byte, IDrj [][]byte, Fr *sync.Map,
	doneFlagChannel chan bool,
	preVoteFlagChannel chan bool, preVoteYesChannel chan []byte, preVoteNoChannel chan []byte,
	voteFlagChannel chan byte, voteYesChannel chan []byte, voteNoChannel chan []byte, voteOtherChannel chan []byte,
	leaderChannel chan uint32, haltChannel chan []byte, r uint32) {

	//FinishMessage Handler
	go func() {
		FrLength := 0
		for {
			select {
			case <-ctx.Done():
				return
			case m := <-p.GetMessage("Finish", IDr):
				payload := core.Decapsulation("Finish", m).(*protobuf.Finish)
				h := sha3.Sum512(payload.Value)
				var buf bytes.Buffer
				buf.Write([]byte("Echo"))
				buf.Write(IDrj[m.Sender])
				buf.WriteByte(2)
				buf.Write(h[:])
				sm := buf.Bytes()
				err := bls.Verify(pairing.NewSuiteBn256(), p.SigPK.Commit(), sm, payload.Sig) //verify("Echo"||ID||r||index||2||h)
				if err == nil {
					Fr.Store(m.Sender, payload)
					FrLength++
					if FrLength == int(2*p.F+1) {
						doneFlagChannel <- true
					}
				}
			}
		}
	}()

	thisRoundLeader := make(chan uint32, 1)

	go func() {
		var buf bytes.Buffer
		buf.Write([]byte("Done"))
		buf.Write(IDr)
		coinName := buf.Bytes()
		coins := [][]byte{}
		for {
			select {
			case <-ctx.Done():
				return
			case m := <-p.GetMessage("Done", IDr):
				payload := core.Decapsulation("Done", m).(*protobuf.Done)
				err := tbls.Verify(pairing.NewSuiteBn256(), p.SigPK, coinName, payload.CoinShare) //verifyshare("Done"||ID||r)

				if err == nil {
					coins = append(coins, payload.CoinShare)
					if len(coins) == int(p.F+1) {

						doneFlagChannel <- true
						//fmt.Println("party", p.PID, "received f+1 doneMessage")
					}
					if len(coins) > int(2*p.F) {
						coin, _ := tbls.Recover(pairing.NewSuiteBn256(), p.SigPK, coinName, coins, int(2*p.F+1), int(p.N))
						l := utils.BytesToUint32(coin) % p.N //leader of round r
						thisRoundLeader <- l                 //for message handler
						leaderChannel <- l                   //for main process

						return
					}
				}
			}

		}
	}()

	l := <-thisRoundLeader

	//HaltMessage Handler
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case m := <-p.GetMessage("Halt", IDr):
				payload := core.Decapsulation("Halt", m).(*protobuf.Halt)

				h := sha3.Sum512(payload.Value)
				var buf bytes.Buffer
				buf.Write([]byte("Echo"))
				buf.Write(IDrj[l])
				buf.WriteByte(2)
				buf.Write(h[:])
				sm := buf.Bytes()
				err := bls.Verify(pairing.NewSuiteBn256(), p.SigPK.Commit(), sm, payload.Sig) //verify("Echo"||ID||r||l||2||h)
				if err == nil {
					haltChannel <- payload.Value
					return
				}
			}
		}

	}()

	//PreVoteMessage Handler
	go func() {
		PNr := [][]byte{}
		for {
			select {
			case <-ctx.Done():
				return
			case m := <-p.GetMessage("PreVote", IDr):
				payload := core.Decapsulation("PreVote", m).(*protobuf.PreVote)
				if payload.Vote {
					// if p.PID == 3 {
					// 	fmt.Println("party", p.PID, "received a prevotemessage")
					// }
					h := sha3.Sum512(payload.Value)
					var buf bytes.Buffer
					buf.Write([]byte("Echo"))
					buf.Write(IDrj[l])
					buf.WriteByte(1)
					buf.Write(h[:])
					sm := buf.Bytes()
					err := bls.Verify(pairing.NewSuiteBn256(), p.SigPK.Commit(), sm, payload.Sig) //verify("Echo"||ID||r||l||1||h)

					if err == nil {
						sm[len([]byte("Echo"))+len(IDrj[l])] = 2
						sigShare, _ := tbls.Sign(pairing.NewSuiteBn256(), p.SigSK, sm) //sign("Echo"||ID||r||l||2||h)
						preVoteFlagChannel <- true
						preVoteYesChannel <- payload.Value
						preVoteYesChannel <- payload.Sig
						preVoteYesChannel <- sigShare
					}
				} else {
					var buf bytes.Buffer
					buf.WriteByte(byte(0)) //false
					buf.Write(IDr)
					sm := buf.Bytes()
					err := tbls.Verify(pairing.NewSuiteBn256(), p.SigPK, sm, payload.Sig) //verifyShare(false||ID||r)
					if err == nil {
						PNr = append(PNr, payload.Sig)
						if len(PNr) > int(2*p.F) {
							noSignature, _ := tbls.Recover(pairing.NewSuiteBn256(), p.SigPK, sm, PNr, int(2*p.F+1), int(p.N))
							var buf bytes.Buffer
							buf.Write([]byte("Unlock"))
							buf.Write(IDr)
							sm := buf.Bytes()
							sigShare, _ := tbls.Sign(pairing.NewSuiteBn256(), p.SigSK, sm) //sign("Unlock"||ID||r)
							preVoteFlagChannel <- false
							preVoteNoChannel <- noSignature
							preVoteNoChannel <- sigShare
						}
					}
				}
			}
		}
	}()

	//VoteMessage Handler
	go func() {
		VYr := [][]byte{}
		VNr := [][]byte{}
		for {
			select {
			case <-ctx.Done():
				return
			case m := <-p.GetMessage("Vote", IDr):

				payload := core.Decapsulation("Vote", m).(*protobuf.Vote)
				if payload.Vote {
					h := sha3.Sum512(payload.Value)
					var buf bytes.Buffer
					buf.Write([]byte("Echo"))
					buf.Write(IDrj[l])
					buf.WriteByte(1)
					buf.Write(h[:])
					sm := buf.Bytes()
					err1 := bls.Verify(pairing.NewSuiteBn256(), p.SigPK.Commit(), sm, payload.Sig) //verify("Echo"||ID||r||l||1||h)
					sm[len([]byte("Echo"))+len(IDrj[l])] = 2
					err2 := tbls.Verify(pairing.NewSuiteBn256(), p.SigPK, sm, payload.Sigshare) //verifyShare("Echo"||ID||r||l||2||h)
					if err1 == nil && err2 == nil {
						VYr = append(VYr, payload.Sigshare)
						if len(VYr) > int(2*p.F) {
							sig, _ := tbls.Recover(pairing.NewSuiteBn256(), p.SigPK, sm, VYr, int(2*p.F+1), int(p.N))
							voteFlagChannel <- 0
							voteYesChannel <- payload.Value
							voteYesChannel <- sig
						} else if len(VYr)+len(VNr) > int(2*p.F) {
							voteFlagChannel <- 2
							voteOtherChannel <- payload.Value
							voteOtherChannel <- payload.Sig
						}
					}
				} else {
					var buf1 bytes.Buffer
					buf1.WriteByte(byte(0)) //false
					buf1.Write(IDr)
					sm1 := buf1.Bytes()
					err1 := bls.Verify(pairing.NewSuiteBn256(), p.SigPK.Commit(), sm1, payload.Sig) //verify(false||ID||r)

					var buf2 bytes.Buffer
					buf2.Reset()
					buf2.Write([]byte("Unlock"))
					buf2.Write(IDr)
					sm2 := buf2.Bytes()
					err2 := tbls.Verify(pairing.NewSuiteBn256(), p.SigPK, sm2, payload.Sigshare) //verifyShare("Unlock"||ID||r)
					if err1 == nil && err2 == nil {
						VNr = append(VNr, payload.Sigshare)
						if len(VNr) > int(2*p.F) {
							sig, _ := tbls.Recover(pairing.NewSuiteBn256(), p.SigPK, sm2, VYr, int(2*p.F+1), int(p.N))
							voteFlagChannel <- 1
							voteNoChannel <- sig
						}
					}
				}

			}
		}

	}()
}
