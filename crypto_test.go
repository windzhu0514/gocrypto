package gocrypto

import (
	"encoding/hex"
	"fmt"
)

func ExampleGCMEncrypt() {
	key := []byte("dfsz323gd7656jhg")
	plaintext := []byte("gh2222222222222222222222222222")
	additionalData := []byte("2")

	cipherTxt, nonce, err := AESGCMEncrypter(key, plaintext, additionalData)
	fmt.Printf("%x %x %v\n", cipherTxt, nonce, err)
}

func ExampleGCMDecrypt() {
	key := []byte("dfsz323gd7656jhg")
	cipherTxt, _ := hex.DecodeString("20c648ac8b2085283fcc1fe5e5d519d76daa9955cc0a6f39af5f140a94a9f0816305a775fb7901d28c0e1057cc73")
	nonce, _ := hex.DecodeString("da119c4501a042f01cf78a4f")
	additionalData := []byte("2")

	plainTxt, err := AESGCMDecrypter(key, nonce, cipherTxt, additionalData)

	fmt.Printf("%s %v\n", plainTxt, err)
}
