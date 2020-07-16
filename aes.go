package gocrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"

	"github.com/windzhu0514/gocrypto/ecb"
)

func AESCBCEncrypt(plainTxt, key []byte, padding Padding) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if padding != nil {
		plainTxt = padding.Padding(plainTxt, block.BlockSize())
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	dst := make([]byte, block.BlockSize()+len(plainTxt))
	iv := dst[:block.BlockSize()]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	blockMode := cipher.NewCBCEncrypter(block, iv)
	blockMode.CryptBlocks(dst[block.BlockSize():], plainTxt)

	return dst, nil
}

func AESCBCDecrypt(cipherTxt, key []byte, padding Padding) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(cipherTxt) < block.BlockSize() {
		return nil, errors.New("ciphertext too short")
	}

	if len(cipherTxt)%block.BlockSize() != 0 {
		return nil, errors.New("gocrypto/cipher: input not full blocks")
	}

	iv := cipherTxt[:block.BlockSize()]
	cipherTxt = cipherTxt[block.BlockSize():]

	blockMode := cipher.NewCBCDecrypter(block, iv)

	dst := make([]byte, len(cipherTxt))
	blockMode.CryptBlocks(dst, cipherTxt)

	if padding != nil {
		dst = padding.UnPadding(dst)
	}

	return dst, nil
}

func AESECBEncrypt(plainTxt, key []byte, padding Padding) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if padding != nil {
		plainTxt = padding.Padding(plainTxt, block.BlockSize())
	}

	dst := make([]byte, len(plainTxt))
	blockMode := ecb.NewECBEncrypter(block)
	blockMode.CryptBlocks(dst, plainTxt)

	return dst, nil
}

func AESECBDecrypt(cipherTxt, key []byte, padding Padding) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(cipherTxt)%block.BlockSize() != 0 {
		return nil, errors.New("gocrypto/cipher: input not full blocks")
	}

	dst := make([]byte, len(cipherTxt))
	blockMode := ecb.NewECBDecrypter(block)
	blockMode.CryptBlocks(dst, cipherTxt)

	if padding != nil {
		dst = padding.UnPadding(dst)
	}

	return dst, nil
}

func AESCFBEncrypt(plainTxt, key []byte, padding Padding) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if padding != nil {
		plainTxt = padding.Padding(plainTxt, block.BlockSize())
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	dst := make([]byte, block.BlockSize()+len(plainTxt))
	iv := dst[:block.BlockSize()]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(dst, plainTxt)

	return dst, nil
}

func AESCFBDecrypt(cipherTxt, key []byte, padding Padding) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(cipherTxt) < block.BlockSize() {
		return nil, errors.New("ciphertext too short")
	}

	if len(cipherTxt)%block.BlockSize() != 0 {
		return nil, errors.New("gocrypto/cipher: input not full blocks")
	}

	iv := cipherTxt[:block.BlockSize()]
	cipherTxt = cipherTxt[block.BlockSize():]

	cfb := cipher.NewCFBDecrypter(block, iv)

	dst := make([]byte, len(cipherTxt))
	cfb.XORKeyStream(dst, cipherTxt)

	if padding != nil {
		dst = padding.UnPadding(dst)
	}

	return dst, nil
}

func AESCTREncrypt(plainTxt, key []byte, padding Padding) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if padding != nil {
		plainTxt = padding.Padding(plainTxt, block.BlockSize())
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	dst := make([]byte, block.BlockSize()+len(plainTxt))
	iv := dst[:block.BlockSize()]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	ctr := cipher.NewCTR(block, iv)
	ctr.XORKeyStream(dst, plainTxt)

	return dst, nil
}

func AESCTRDecrypt(cipherTxt, key []byte, padding Padding) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(cipherTxt) < block.BlockSize() {
		return nil, errors.New("ciphertext too short")
	}

	if len(cipherTxt)%block.BlockSize() != 0 {
		return nil, errors.New("gocrypto/cipher: input not full blocks")
	}

	iv := cipherTxt[:block.BlockSize()]
	cipherTxt = cipherTxt[block.BlockSize():]

	ctr := cipher.NewCTR(block, iv)

	dst := make([]byte, len(cipherTxt))
	ctr.XORKeyStream(dst, cipherTxt)

	if padding != nil {
		dst = padding.UnPadding(dst)
	}

	return dst, nil
}

func AESGCMEncrypt(plainTxt, key []byte, padding Padding) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if padding != nil {
		plainTxt = padding.Padding(plainTxt, block.BlockSize())
	}

	dst := make([]byte, len(plainTxt))
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}

	dst = aesgcm.Seal(nil, nonce, plainTxt, nil)

	return dst, nil
}

func AESGCMDecrypt(cipherTxt, key, nonce []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(nonce) != 12 {
		return nil, errors.New("incorrect nonce length given to GCM")
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := aesgcm.Open(nil, nonce, cipherTxt, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func AESOFBEncrypt(plainTxt, key []byte, padding Padding) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if padding != nil {
		plainTxt = padding.Padding(plainTxt, block.BlockSize())
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, block.BlockSize()+len(plainTxt))
	iv := ciphertext[:block.BlockSize()]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	ofb := cipher.NewOFB(block, iv)
	ofb.XORKeyStream(ciphertext[block.BlockSize():], plainTxt)

	return ciphertext, nil
}

func AESOFBDecrypt(cipherTxt, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(cipherTxt) < block.BlockSize() {
		return nil, errors.New("ciphertext too short")
	}

	if len(cipherTxt)%block.BlockSize() != 0 {
		return nil, errors.New("gocrypto/cipher: input not full blocks")
	}

	iv := cipherTxt[:block.BlockSize()]
	cipherTxt = cipherTxt[block.BlockSize():]

	ofb := cipher.NewOFB(block, iv)

	dst := make([]byte, len(cipherTxt))
	ofb.XORKeyStream(dst, cipherTxt)

	return dst, nil
}
