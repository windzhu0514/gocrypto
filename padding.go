package gocrypto

import "bytes"

type Padding interface {
	Padding(plainTxt []byte, blockSize int) []byte
	UnPadding(cipherTxt []byte) []byte
}

type PKCS5Padding struct {
}

func (PKCS5Padding) Padding(plainTxt []byte, blockSize int) []byte {
	paddingBytes := blockSize - len(plainTxt)%blockSize
	paddingTxt := bytes.Repeat([]byte{byte(paddingBytes)}, paddingBytes)
	return append(plainTxt, paddingTxt...)
}
func (PKCS5Padding) UnPadding(cipherTxt []byte) []byte {
	length := len(cipherTxt)
	unpaddingBytes := int(cipherTxt[length-1])
	return cipherTxt[:(length - unpaddingBytes)]
}

type ZerosPadding struct {
}

func (ZerosPadding) Padding(plainTxt []byte, blockSize int) []byte {
	paddingBytes := blockSize - len(plainTxt)%blockSize
	paddingTxt := bytes.Repeat([]byte{byte(0)}, paddingBytes)
	return append(plainTxt, paddingTxt...)
}
func (ZerosPadding) UnPadding(cipherTxt []byte) []byte {
	for i := len(cipherTxt) - 1; ; i-- {
		if cipherTxt[i] != 0 {
			return cipherTxt[:i+1]
		}
	}
	return cipherTxt
}
