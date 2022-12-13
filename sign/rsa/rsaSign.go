/**
    @author: potten
    @since: 2022/12/12
    @desc: //TODO
**/
package rsa

import (
	"authentication/sign/hash"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"log"
	"runtime"
)

type RsaSign struct {
	PublicKey  string
	PrivateKey string
}

// rsa 签名
func rsaSign(msg, priKey []byte) (sign []byte, err error) {
	defer func() {
		if err := recover(); err != nil {
			switch err.(type) {
			case runtime.Error:
				log.Fatalf("runtime err=%v, check that the key or text is correct", err)
			default:
				log.Fatalf("error=%v, check the cipherText ", err)
			}
		}
	}()

	privateKey, err := x509.ParsePKCS1PrivateKey(priKey)
	hashed := hash.Sha256(msg)
	sign, err = rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed)
	if err != nil {
		return nil, err
	}
	return sign, err
}

// rsa 签名验证
func rsaVerifySign(msg []byte, sign []byte, pubKey []byte) bool {
	defer func() {
		if err := recover(); err != nil {
			switch err.(type) {
			case runtime.Error:
				log.Fatalf("runtime err=%v,Check that the key or text is correct", err)
			default:
				log.Fatalf("error=%v,check the cipherText ", err)
			}
		}
	}()

	publicKey, err := x509.ParsePKCS1PublicKey(pubKey)
	if err != nil {
		return false
	}
	hashed := hash.Sha256(msg)
	result := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed, sign)
	return result == nil
}

func (r *RsaSign) RsaSignBase64(msg []byte) (base64Sign string, err error) {
	priBytes, err := base64.StdEncoding.DecodeString(r.PrivateKey)
	if err != nil {
		return "", err
	}
	sign, err := rsaSign(msg, priBytes)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sign), nil
}

func (r *RsaSign) RsaVerifySignBase64(msg []byte, base64Sign string) bool {
	signBytes, err := base64.StdEncoding.DecodeString(base64Sign)
	if err != nil {
		return false
	}
	pubBytes, err := base64.StdEncoding.DecodeString(r.PublicKey)
	if err != nil {
		return false
	}
	return rsaVerifySign(msg, signBytes, pubBytes)
}

func (r *RsaSign) RsaSignHex(msg []byte) (hexSign string, err error) {
	priBytes, err := hex.DecodeString(r.PrivateKey)
	if err != nil {
		return "", err
	}
	sign, err := rsaSign(msg, priBytes)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(sign), nil
}

func (r *RsaSign) RsaVerifySignHex(msg []byte, hexSign string) bool {
	signBytes, err := hex.DecodeString(hexSign)
	if err != nil {
		return false
	}
	pubBytes, err := hex.DecodeString(r.PublicKey)
	if err != nil {
		return false
	}
	return rsaVerifySign(msg, signBytes, pubBytes)
}
