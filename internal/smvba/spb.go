package smvba //strong provable broadcPBt

/*
forked from https://github.com/xygdys/Buada_BFT
*/

import (
	"bytes"
	"context"

	"github.com/DyCAPSTeam/DyCAPS/internal/party"
	"github.com/DyCAPSTeam/DyCAPS/internal/pb"

	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/sign/bls"
	"golang.org/x/crypto/sha3"
)

//SPBSender is run by the sender of a instance of strong provable broadcast
func SPBSender(ctx context.Context, p *party.HonestParty, ID []byte, value []byte, validation []byte) ([]byte, []byte, bool) {
	var buf1, buf2 bytes.Buffer
	buf1.Write(ID)
	buf1.WriteByte(1)
	buf2.Write(ID)
	buf2.WriteByte(2)
	ID1 := buf1.Bytes()
	ID2 := buf2.Bytes()

	sig1, ok1 := pb.Sender(ctx, p, ID1, value, validation)
	if ok1 {
		sig2, ok2 := pb.Sender(ctx, p, ID2, value, sig1)
		if ok2 {
			return value, sig2, true //FINISH
		}
	}

	return nil, nil, false

}

//SPBReceiver is run by the receiver of a instance of strong provable broadcast
func SPBReceiver(ctx context.Context, p *party.HonestParty, sender uint32, ID []byte) ([]byte, []byte, bool) {
	var buf1, buf2 bytes.Buffer
	buf1.Write(ID)
	buf1.WriteByte(1)
	buf2.Write(ID)
	buf2.WriteByte(2)
	ID1 := buf1.Bytes()
	ID2 := buf2.Bytes()

	pb.Receiver(ctx, p, sender, ID1, nil)
	value, sig, ok := pb.Receiver(ctx, p, sender, ID2, validator)
	if !ok {
		return nil, nil, false
	}

	return value, sig, true //LOCK
}

func validator(p *party.HonestParty, ID []byte, sender uint32, value []byte, validation []byte) error {
	h := sha3.Sum512(value)
	var buf bytes.Buffer
	buf.Write([]byte("Echo"))
	buf.Write(ID[:len(ID)-1])
	buf.WriteByte(1)
	buf.Write(h[:])
	sm := buf.Bytes()
	err := bls.Verify(pairing.NewSuiteBn256(), p.SigPK.Commit(), sm, validation)
	return err
}
