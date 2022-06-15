package utils

import (
	"bytes"
	"encoding/binary"
)

//Uint32ToBytes convert uint32 to bytes
func Uint32ToBytes(n uint32) []byte {
	bytebuf := bytes.NewBuffer([]byte{})
	binary.Write(bytebuf, binary.BigEndian, n)
	return bytebuf.Bytes()
}

//BytesToUint32 convert bytes to uint32
func BytesToUint32(byt []byte) uint32 {
	bytebuff := bytes.NewBuffer(byt)
	var data uint32
	binary.Read(bytebuff, binary.BigEndian, &data)
	return data
}

//BytesToInt convert bytes to int
func BytesToInt(byt []byte) int {
	bytebuff := bytes.NewBuffer(byt)
	var data uint32
	binary.Read(bytebuff, binary.BigEndian, &data)
	return int(data)
}

//IntToBytes convert int to bytes
func IntToBytes(n int) []byte {
	data := uint32(n)
	bytebuf := bytes.NewBuffer([]byte{})
	binary.Write(bytebuf, binary.BigEndian, data)
	return bytebuf.Bytes()
}

func DeleteZero(src []byte) []byte {
	length := len(src)
	for i := length - 1; i >= 0; i-- {
		if src[i] == byte(0) {
			src = src[0:i] // delete the last element
		} else {
			break
		}
	}
	return src
}

func DeleteZeroWithLen(src []byte, len int) []byte {
	return src[0:len]
}
