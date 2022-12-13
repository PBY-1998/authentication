/**
    @author: potten
    @since: 2022/12/12
    @desc: //TODO
**/
package rsa

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"log"
	"runtime"
)

// rsa 加密
func rsaEncrypt(plain, publicKey []byte) (cipher []byte, err error) {
	defer func() {
		if err := recover(); err != nil {
			switch err.(type) {
			case runtime.Error:
				log.Fatalf("runtime err=%v, check that the key or text is correct", err)
			default:
				log.Fatalf("error=%v, check the cipher", err)
			}
		}
	}()

	pub, err := x509.ParsePKCS1PublicKey(publicKey)
	if err != nil {
		return nil, err
	}

	pubSize, plainSize := pub.Size(), len(plain)
	// EncryptPKCS1v15 encrypts the given message with RSA and the padding
	// scheme from PKCS #1 v1.5.  The message must be no longer than the
	// length of the public modulus minus 11 bytes.
	//
	// The rand parameter is used as a source of entropy to ensure that
	// encrypting the same message twice doesn't result in the same
	// ciphertext.
	//
	// WARNING: use of this function to encrypt plaintexts other than
	// session keys is dangerous. Use RSA OAEP in new protocols.
	offSet, once := 0, pubSize-11
	buffer := bytes.Buffer{}
	for offSet < plainSize {
		endIndex := offSet + once
		if endIndex > plainSize {
			endIndex = plainSize
		}
		bytesOnce, err := rsa.EncryptPKCS1v15(rand.Reader, pub, plain[offSet:endIndex])
		if err != nil {
			return nil, err
		}
		buffer.Write(bytesOnce)
		offSet = endIndex
	}
	cipher = buffer.Bytes()
	return cipher, nil
}

// rsa 解密
func rsaDecrypt(cipher, privateKey []byte) (plain []byte, err error) {
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

	pri, err := x509.ParsePKCS1PrivateKey(privateKey)
	if err != nil {
		return []byte{}, err
	}

	priSize, cipherSize := pri.Size(), len(cipher)
	var offSet = 0
	var buffer = bytes.Buffer{}
	for offSet < cipherSize {
		endIndex := offSet + priSize
		if endIndex > cipherSize {
			endIndex = cipherSize
		}
		bytesOnce, err := rsa.DecryptPKCS1v15(rand.Reader, pri, cipher[offSet:endIndex])
		if err != nil {
			return nil, err
		}
		buffer.Write(bytesOnce)
		offSet = endIndex
	}
	plain = buffer.Bytes()
	return plain, nil
}

// RsaEncryptToBase64 rsa 加密->base64
func (r *RsaSign) RsaEncryptToBase64(plain []byte) (base64Cipher string, err error) {
	pub, err := base64.StdEncoding.DecodeString(r.PublicKey)
	if err != nil {
		return "", err
	}
	cipherBytes, err := rsaEncrypt(plain, pub)
	if err != nil {
		return "", nil
	}
	return base64.StdEncoding.EncodeToString(cipherBytes), nil
}

// RsaDecryptByBase64 rsa 解密->base64
func (r *RsaSign) RsaDecryptByBase64(base64Cipher string) (plain []byte, err error) {
	privateBytes, err := base64.StdEncoding.DecodeString(r.PrivateKey)
	if err != nil {
		return nil, err
	}
	cipherBytes, err := base64.StdEncoding.DecodeString(base64Cipher)
	if err != nil {
		return nil, err
	}
	return rsaDecrypt(cipherBytes, privateBytes)
}

// RsaEncryptToHex rsa 加密->hex
func (r *RsaSign) RsaEncryptToHex(plain []byte) (hexCipher string, err error) {
	pub, err := hex.DecodeString(r.PublicKey)
	if err != nil {
		return "", err
	}
	cipherBytes, err := rsaEncrypt(plain, pub)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(cipherBytes), nil
}

// RsaDecryptByHex rsa 解密->hex
func (r *RsaSign) RsaDecryptByHex(hexCipher string) (plain []byte, err error) {
	privateBytes, err := hex.DecodeString(r.PrivateKey)
	if err != nil {
		return nil, err
	}
	cipherBytes, err := hex.DecodeString(hexCipher)
	if err != nil {
		return nil, err
	}
	return rsaDecrypt(cipherBytes, privateBytes)
}
