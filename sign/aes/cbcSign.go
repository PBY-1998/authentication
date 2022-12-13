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

type CbcSign struct {
	SecretKey []byte
	IvAes     []byte
}

func (c *CbcSign) AesCbcEncrypt(plainText []byte) (cipherText []byte, err error) {
	if len(c.SecretKey) != 16 && len(c.SecretKey) != 24 && len(c.SecretKey) != 32 {
		return nil, authentication.ErrKeyLengthSixteen
	}
	block, err := aes.NewCipher([]byte(c.SecretKey))
	if err != nil {
		return nil, err
	}
	paddingText := authentication.PKCS5Padding(plainText, block.BlockSize())

	var iv []byte
	if len(c.IvAes) != 0 {
		if len(c.IvAes) != block.BlockSize() {
			return nil, authentication.ErrIvAes
		} else {
			iv = c.IvAes
		}
	} else {
		iv = []byte(authentication.Ivaes)
	} // To initialize the vector, it needs to be the same length as block.blocksize
	blockMode := cipher.NewCBCEncrypter(block, iv)
	cipherText = make([]byte, len(paddingText))
	blockMode.CryptBlocks(cipherText, paddingText)
	return cipherText, nil
}

func (c *CbcSign) AesCbcEncryptBase64(plainText []byte) (cipherTextBase64 string, err error) {
	encryBytes, err := c.AesCbcEncrypt(plainText)
	return base64.StdEncoding.EncodeToString(encryBytes), err
}

func (c *CbcSign) AesCbcEncryptHex(plainText []byte) (cipherTextHex string, err error) {
	encryBytes, err := c.AesCbcEncrypt(plainText)
	return hex.EncodeToString(encryBytes), err
}

func (c *CbcSign) AesCbcDecrypt(cipherText []byte) (plainText []byte, err error) {
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
	blockMode := cipher.NewCBCDecrypter(block, iv)
	paddingText := make([]byte, len(cipherText))
	blockMode.CryptBlocks(paddingText, cipherText)

	plainText, err = authentication.PKCS5UnPadding(paddingText, block.BlockSize())
	if err != nil {
		return nil, err
	}
	return plainText, nil
}

func (c *CbcSign) AesCbcDecryptByBase64(cipherTextBase64 string) (plainText []byte, err error) {
	plainTextBytes, err := base64.StdEncoding.DecodeString(cipherTextBase64)
	if err != nil {
		return []byte{}, err
	}
	return c.AesCbcDecrypt(plainTextBytes)
}

func (c CbcSign) AesCbcDecryptByHex(cipherTextHex string) (plainText []byte, err error) {
	plainTextBytes, err := hex.DecodeString(cipherTextHex)
	if err != nil {
		return []byte{}, err
	}
	return c.AesCbcDecrypt(plainTextBytes)
}
