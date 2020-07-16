package gocrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"errors"
	"io"
	"strings"

	"github.com/windzhu0514/gocrypto/ecb"
)

// PKCS5等同于PKCS7

const (
	AESCBCNoPadding                    = "AES/CBC/NoPadding"
	AESCBCPKCS5Padding                 = "AES/CBC/PKCS5Padding"
	AESCBCZeroPadding                  = "AES/CBC/ZeroPadding"
	AESECBNoPadding                    = "AES/ECB/NoPadding"
	AESECBPKCS5Padding                 = "AES/ECB/PKCS5Padding"
	AESECBPZeroPaddin                  = "AES/ECB/ZeroPadding"
	DESCBCNoPadding                    = "DES/CBC/NoPadding"
	DESCBCPKCS5Padding                 = "DES/CBC/PKCS5Padding"
	DESCBCZeroPadding                  = "DES/CBC/ZeroPadding"
	DESECBNoPadding                    = "DES/ECB/NoPadding"
	DESECBPKCS5Padding                 = "DES/ECB/PKCS5Padding"
	DESECBZeroPadding                  = "DES/ECB/ZeroPadding"
	TripleDESCBCNoPadding              = "TripleDES/CBC/NoPadding"    // DESede
	TripleDESCBCPKCS5Padding           = "TripleDES/CBC/PKCS5Padding" // DESede
	TripleDESCBCZeroPadding            = "TripleDES/CBC/ZeroPadding"  // DESede
	TripleDESECBNoPadding              = "TripleDES/ECB/NoPadding"    // DESede
	TripleDESECBPKCS5Padding           = "TripleDES/ECB/PKCS5Padding" // DESede
	TripleDESECBZeroPadding            = "TripleDES/ECB/ZeroPadding"  // DESede
	RSAECBPKCS1Padding                 = "RSA/ECB/PKCS1Padding"
	RSAECBOAEPWithSHA1AndMGF1Padding   = "RSA/ECB/OAEPWithSHA-1AndMGF1Padding"
	RSAECBOAEPWithSHA256AndMGF1Padding = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"
)

type Cipher struct {
	Cipher    string
	BlockMode string
	Padding   string
}

func NewCipher(transformation string) (e Cipher) {
	fields := strings.Split(transformation, "/")
	if len(fields) >= 3 {
		e = Cipher{
			Cipher:    fields[0],
			BlockMode: fields[1],
			Padding:   fields[2],
		}
	}

	return e
}

func (e *Cipher) Encrypt(key, plainTxt []byte) ([]byte, error) {
	var block cipher.Block
	var err error

	switch e.Cipher {
	case "AES":
		block, err = aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
	case "DES":
		block, err = des.NewCipher(key)
		if err != nil {
			return nil, err
		}
	case "TripleDES":
		block, err = des.NewTripleDESCipher(key)
		if err != nil {
			return nil, err
		}
	case "RSA":
	default:
		return nil, errors.New("invalid cipher type")
	}

	dst := make([]byte, block.BlockSize()+len(plainTxt))
	iv := dst[:block.BlockSize()]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	var blockMode cipher.BlockMode
	switch e.BlockMode {
	case "CBC":
		blockMode = cipher.NewCBCEncrypter(block, iv)
	case "ECB":
		blockMode = ecb.NewECBEncrypter(block)
	default:
		return nil, errors.New("invalid block mode type")
	}

	blockMode.CryptBlocks(dst, plainTxt)
	return dst, nil
}

func (e *Cipher) DecryptWithIV(key, iv, cipherTxt []byte) ([]byte, error) {
	return e.decrypt(key, iv, cipherTxt)
}

func (e *Cipher) Decrypt(key, cipherTxt []byte) ([]byte, error) {
	return e.decrypt(key, nil, cipherTxt)
}

func (e *Cipher) decrypt(key, iv, cipherTxt []byte) ([]byte, error) {
	var block cipher.Block
	var err error

	switch e.Cipher {
	case "AES":
		block, err = aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
	case "DES":
		block, err = des.NewCipher(key)
		if err != nil {
			return nil, err
		}
	case "TripleDES":
		block, err = des.NewTripleDESCipher(key)
		if err != nil {
			return nil, err
		}
	case "RSA":
	default:
		return nil, errors.New("invalid cipher type")
	}

	if iv == nil {
		iv = cipherTxt[:block.BlockSize()]
		cipherTxt = cipherTxt[block.BlockSize():]
	}

	if len(cipherTxt) < block.BlockSize() {
		return nil, errors.New("ciphertext too short")
	}

	if len(cipherTxt)%block.BlockSize() != 0 {
		return nil, errors.New("gocrypto/cipher: input not full blocks")
	}

	var blockMode cipher.BlockMode
	switch e.BlockMode {
	case "CBC":
		blockMode = cipher.NewCBCDecrypter(block, iv)
	case "ECB":
		blockMode = ecb.NewECBDecrypter(block)
	default:
		return nil, errors.New("invalid block mode type")
	}

	dst := make([]byte, len(cipherTxt))
	blockMode.CryptBlocks(dst, cipherTxt)

	switch e.Padding {
	case "PKCS5Padding", "PKCS7Padding":
		dst = PKCS5Padding{}.UnPadding(dst)
	case "ZeroPadding":
		dst = ZerosPadding{}.UnPadding(dst)
	default:
		return nil, errors.New("invalid padding type")
	}

	return dst, nil
}
