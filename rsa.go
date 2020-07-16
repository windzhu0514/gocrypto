package gocrypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"

	"github.com/windzhu0514/gocrypto/rsa_ex"
)

// RSAEncrypt RSA公钥加密
func RSAEncrypt(plainText, publicKey []byte) ([]byte, error) {
	pub, err := ParsePublicKey(publicKey)
	if err != nil {
		return nil, err
	}

	return rsa.EncryptPKCS1v15(rand.Reader, pub, plainText)
}

// RSADecrypt RSA私钥解密
func RSADecrypt(cipherText, privateKey []byte) ([]byte, error) {
	priv, err := ParsePrivateKey(privateKey)
	if err != nil {
		return nil, err
	}

	return rsa.DecryptPKCS1v15(rand.Reader, priv, cipherText)
}

// RSAPrivateEncrypt RSA私钥加密
func RSAPrivateEncrypt(plainText, privateKey []byte) ([]byte, error) {
	priv, err := ParsePrivateKey(privateKey)
	if err != nil {
		return nil, err
	}

	return rsa_ex.PrivateKeyEncrypt(rand.Reader, priv, plainText)
}

// RSAPublicDecrypt RSA公钥解密
func RSAPublicDecrypt(cipherText, publicKey []byte) ([]byte, error) {
	pub, err := ParsePublicKey(publicKey)
	if err != nil {
		return nil, err
	}

	return rsa_ex.PublicKeyDecrypt(pub, cipherText)
}

func ParsePublicKey(publickey []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(publickey)
	if block == nil {
		return nil, errors.New("public key error")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return pub.(*rsa.PublicKey), err
}

func ParsePublicKeyFromCert(certPEM []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, errors.New("certPEM error")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, errors.New("failed to parse certificate: " + err.Error())
	}

	pub := cert.PublicKey.(*rsa.PublicKey)
	return pub, nil
}

func ParsePrivateKey(privatekey []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(privatekey)
	if block == nil {
		return nil, errors.New("private key error")
	}

	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err == nil {
		return priv, nil
	}

	keyPKCS8, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return keyPKCS8.(*rsa.PrivateKey), nil
}
