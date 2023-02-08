package party

/*
forked from https://github.com/xygdys/Buada_BFT
*/

import (
	"bytes"
	"context"
	kyberbls "github.com/drand/kyber-bls12381"
	"github.com/drand/kyber/sign/bls"
	"golang.org/x/crypto/sha3"
)

//SPBSender is run by the sender of a instance of strong provable broadcast
func SPBSender(ctx context.Context, p *HonestParty, ID []byte, value []byte, validation []byte) ([]byte, []byte, bool) {
	var buf1, buf2 bytes.Buffer
	buf1.Write(ID)
	buf1.WriteByte(1)
	buf2.Write(ID)
	buf2.WriteByte(2)
	ID1 := buf1.Bytes()
	ID2 := buf2.Bytes()

	sig1, ok1 := Sender(ctx, p, ID1, value, validation)
	if ok1 {
		sig2, ok2 := Sender(ctx, p, ID2, value, sig1)
		if ok2 {
			return value, sig2, true //FINISH
		}
	}

	return nil, nil, false

}

//SPBReceiver is run by the receiver of a instance of strong provable broadcast
func SPBReceiver(ctx context.Context, p *HonestParty, sender uint32, ID []byte) ([]byte, []byte, bool) {
	var buf1, buf2 bytes.Buffer
	buf1.Write(ID)
	buf1.WriteByte(1)
	buf2.Write(ID)
	buf2.WriteByte(2)
	ID1 := buf1.Bytes()
	ID2 := buf2.Bytes()

	Receiver(ctx, p, sender, ID1, nil)
	value, sig, ok := Receiver(ctx, p, sender, ID2, validator)
	if !ok {
		return nil, nil, false
	}

	return value, sig, true //LOCK
}

func validator(p *HonestParty, ID []byte, sender uint32, value []byte, validation []byte) error {
	h := sha3.Sum512(value)
	var buf bytes.Buffer
	buf.Write([]byte("Echo"))
	buf.Write(ID[:len(ID)-1])
	buf.WriteByte(1)
	buf.Write(h[:])
	sm := buf.Bytes()
	err := bls.NewSchemeOnG1(kyberbls.NewBLS12381Suite()).Verify(p.SigPK.Commit(), sm, validation)
	return err
}
