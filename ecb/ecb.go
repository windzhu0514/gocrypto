package ecb

import (
	"crypto/cipher"
)

type ecb struct {
	block     cipher.Block
	blockSize int
}

type ecbEncrypter ecb

func (this *ecbEncrypter) BlockSize() int {
	return this.blockSize
}

func (this *ecbEncrypter) CryptBlocks(dst, src []byte) {
	if len(src)%this.blockSize != 0 {
		panic("gocrypto/aes: input not full block")
	}
	for len(src) > 0 {
		this.block.Encrypt(dst, src[:this.blockSize])
		src = src[this.blockSize:]
		dst = dst[this.blockSize:]
	}
}

type ecbDecrypter ecb

func (this *ecbDecrypter) BlockSize() int {
	return this.blockSize
}

func (this *ecbDecrypter) CryptBlocks(dst, src []byte) {
	if len(src)%this.blockSize != 0 {
		panic("gocrypto/cipher: input not full blocks")
	}
	for len(src) > 0 {
		this.block.Decrypt(dst, src[:this.blockSize])
		src = src[this.blockSize:]
		dst = dst[this.blockSize:]
	}
}

func NewECBEncrypter(block cipher.Block) cipher.BlockMode {
	return &ecbEncrypter{block: block, blockSize: block.BlockSize()}
}

func NewECBDecrypter(block cipher.Block) cipher.BlockMode {
	return &ecbDecrypter{block: block, blockSize: block.BlockSize()}
}
