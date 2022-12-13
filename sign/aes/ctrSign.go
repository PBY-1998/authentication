/**
    @author: potten
    @since: 2022/12/13
    @desc: //TODO
**/
package aes

import (
	"authentication"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"runtime"
)

type CtrSign struct {
	SecretKey []byte
	IvAes     []byte
}

func (c *CtrSign) AesCtrEncrypt(plainText []byte) (cipherText []byte, err error) {
	if len(c.SecretKey) != 16 && len(c.SecretKey) != 24 && len(c.SecretKey) != 32 {
		return nil, authentication.ErrKeyLengthSixteen
	}
	block, err := aes.NewCipher(c.SecretKey)
	if err != nil {
		return nil, err
	}
	var iv []byte
	if len(c.IvAes) != 0 {
		if len(c.IvAes) != block.BlockSize() {
			return nil, authentication.ErrIvAes
		} else {
			iv = c.IvAes
		}
	} else {
		iv = []byte(authentication.Ivaes)
	}
	stream := cipher.NewCTR(block, iv)

	cipherText = make([]byte, len(plainText))
	stream.XORKeyStream(cipherText, plainText)

	return cipherText, nil
}

func (c *CtrSign) AesCtrEncryptBase64(plainText []byte) (cipherTextBase64 string, err error) {
	encryBytes, err := c.AesCtrEncrypt(plainText)
	return base64.StdEncoding.EncodeToString(encryBytes), err
}

func (c *CtrSign) AesCtrEncryptHex(plainText []byte) (cipherTextHex string, err error) {
	encryBytes, err := c.AesCtrEncrypt(plainText)
	return hex.EncodeToString(encryBytes), err
}

func (c *CtrSign) AesCtrDecrypt(cipherText []byte) (plainText []byte, err error) {
	if len(c.SecretKey) != 16 && len(c.SecretKey) != 24 && len(c.SecretKey) != 32 {
		return nil, authentication.ErrKeyLengthSixteen
	}
	block, err := aes.NewCipher(c.SecretKey)
	if err != nil {
		return nil, err
	}

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

	var iv []byte
	if len(c.IvAes) != 0 {
		if len(c.IvAes) != block.BlockSize() {
			return nil, authentication.ErrIvAes
		} else {
			iv = c.IvAes
		}
	} else {
		iv = []byte(authentication.Ivaes)
	}
	stream := cipher.NewCTR(block, iv)

	plainText = make([]byte, len(cipherText))
	stream.XORKeyStream(plainText, cipherText)

	return plainText, nil
}

func (c *CtrSign) AesCtrDecryptByBase64(cipherTextBase64 string) (plainText []byte, err error) {
	plainTextBytes, err := base64.StdEncoding.DecodeString(cipherTextBase64)
	if err != nil {
		return []byte{}, err
	}
	return c.AesCtrDecrypt(plainTextBytes)
}

func (c *CtrSign) AesCtrDecryptByHex(cipherTextHex string) (plainText []byte, err error) {
	plainTextBytes, err := hex.DecodeString(cipherTextHex)
	if err != nil {
		return []byte{}, err
	}
	return c.AesCtrDecrypt(plainTextBytes)
}
