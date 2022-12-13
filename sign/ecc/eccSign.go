/**
    @author: potten
    @since: 2022/12/12
    @desc: //TODO
**/
package ecc

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/PBY-1998/authentication/sign/hash"
	"math/big"
	"runtime"
)

type EccSign struct {
	PublicKey  string
	PrivateKey string
}

func eccSign(msg []byte, priKey []byte) (rSign []byte, sSign []byte, err error) {
	defer func() {
		if err := recover(); err != nil {
			switch err.(type) {
			case runtime.Error:
				fmt.Errorf("runtime err=%v,Check that the key or text is correct", err)
			default:
				fmt.Errorf("error=%v,check the cipherText ", err)
			}
		}
	}()
	privateKey, err := x509.ParseECPrivateKey(priKey)
	if err != nil {
		return nil, nil, err
	}
	resultHash := hash.Sha256(msg)
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, resultHash)
	if err != nil {
		return nil, nil, err
	}

	rText, err := r.MarshalText()
	if err != nil {
		return nil, nil, err
	}
	sText, err := s.MarshalText()
	if err != nil {
		return nil, nil, err
	}
	return rText, sText, nil
}

func eccVerifySign(msg []byte, pubKey []byte, rText, sText []byte) bool {
	defer func() {
		if err := recover(); err != nil {
			switch err.(type) {
			case runtime.Error:
				fmt.Errorf("runtime err=%v,Check that the key or text is correct", err)
			default:
				fmt.Errorf("error=%v,check the cipherText ", err)
			}
		}
	}()
	publicKeyInterface, _ := x509.ParsePKIXPublicKey(pubKey)
	publicKey := publicKeyInterface.(*ecdsa.PublicKey)
	resultHash := hash.Sha256(msg)

	var r, s big.Int
	r.UnmarshalText(rText)
	s.UnmarshalText(sText)
	result := ecdsa.Verify(publicKey, resultHash, &r, &s)
	return result
}

func (e *EccSign) EccSignBase64(msg []byte) (base64rSign, base64sSign string, err error) {
	priBytes, err := base64.StdEncoding.DecodeString(e.PrivateKey)
	if err != nil {
		return "", "", err
	}
	rSign, sSign, err := eccSign(msg, priBytes)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(rSign), base64.StdEncoding.EncodeToString(sSign), nil
}

func (e *EccSign) EccVerifySignBase64(msg []byte, base64rSign, base64sSign string) bool {
	rSignBytes, err := base64.StdEncoding.DecodeString(base64rSign)
	if err != nil {
		return false
	}
	sSignBytes, err := base64.StdEncoding.DecodeString(base64sSign)
	if err != nil {
		return false
	}
	pubBytes, err := base64.StdEncoding.DecodeString(e.PublicKey)
	if err != nil {
		return false
	}
	return eccVerifySign(msg, pubBytes, rSignBytes, sSignBytes)
}

func (e *EccSign) EccSignHex(msg []byte) (hexrSign, hexsSign string, err error) {
	priBytes, err := hex.DecodeString(e.PrivateKey)
	if err != nil {
		return "", "", err
	}
	rSign, sSign, err := eccSign(msg, priBytes)
	if err != nil {
		return "", "", err
	}
	return hex.EncodeToString(rSign), hex.EncodeToString(sSign), nil
}

func (e *EccSign) EccVerifySignHex(msg []byte, hexrSign, hexsSign string) bool {
	rSignBytes, err := hex.DecodeString(hexrSign)
	if err != nil {
		return false
	}
	sSignBytes, err := hex.DecodeString(hexsSign)
	if err != nil {
		return false
	}
	pubBytes, err := hex.DecodeString(e.PublicKey)
	if err != nil {
		return false
	}
	return eccVerifySign(msg, pubBytes, rSignBytes, sSignBytes)
}
