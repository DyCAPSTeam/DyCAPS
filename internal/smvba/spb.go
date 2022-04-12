package smvba //strong provable broadcast

import (
	"Buada_BFT/internal/party"
	"Buada_BFT/internal/pb"
	"bytes"

	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/sign/bls"
	"golang.org/x/crypto/sha3"
)

//SPBSender is run by the sender of a instance of strong provable broadcast
func SPBSender(p *party.HonestParty, ID []byte, value []byte, validation []byte) ([]byte, []byte) {
	var buf1, buf2 bytes.Buffer
	buf1.Write(ID)
	buf1.WriteByte(1)
	buf2.Write(ID)
	buf2.WriteByte(2)
	ID1 := buf1.Bytes()
	ID2 := buf2.Bytes()

	sig1 := pb.AsSender(p, ID1, value, validation)
	sig2 := pb.AsSender(p, ID2, value, sig1)

	return value, sig2 //FINISH

}

//SPBReceiver is run by the receiver of a instance of strong provable broadcast
func SPBReceiver(p *party.HonestParty, sender uint32, ID []byte) ([]byte, []byte, error) {
	var buf1, buf2 bytes.Buffer
	buf1.Write(ID)
	buf1.WriteByte(1)
	buf2.Write(ID)
	buf2.WriteByte(2)
	ID1 := buf1.Bytes()
	ID2 := buf2.Bytes()

	pb.AsReceiver(p, sender, ID1, nil)
	value, sig, err := pb.AsReceiver(p, sender, ID2, validator)
	if err != nil {
		return nil, nil, err
	}

	return value, sig, nil //LOCK
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
