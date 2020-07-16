package gocrypto

import (
	"crypto/aes"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"testing"
)

// https://blog.csdn.net/xiaohu50/article/details/51682849
func TestCBCEncrypt(t *testing.T) {
	key := []byte("df8dfs4dfs7e1231")
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}
	iv = []byte("1234567891234567")

	cipherTxt, err := AESCBCEncrypt([]byte("fsdf"), key, iv)
	fmt.Println(base64.StdEncoding.EncodeToString(cipherTxt), err)
}

func TestCBCDecrypt(t *testing.T) {
	key := []byte("df8dfs4dfs7e1231")
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}
	iv = []byte("1234567891234567")

	cipherTxt := "1+s5RyBQ91oAb5Q8dAB7rA=="
	data, _ := base64.StdEncoding.DecodeString(cipherTxt)

	plainTxt, err := AESCBCDecrypt(data, key, iv)
	fmt.Println(string(plainTxt), err)
}
