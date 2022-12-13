/**
    @author: potten
    @since: 2022/12/12
    @desc: //TODO
**/
package sign

import (
	"authentication/sign/aes"
	"authentication/sign/ecc"
	"authentication/sign/hash"
	"authentication/sign/rsa"
)

//RsaSigner 非对称加密RSA
type RsaSigner interface {
	RsaSignBase64(msg []byte) (base64Sign string, err error)          // base64 签名
	RsaSignHex(msg []byte) (hexSign string, err error)                // hex 签名
	RsaEncryptToBase64(plain []byte) (base64Cipher string, err error) // base64 加密
	RsaEncryptToHex(plain []byte) (hexCipher string, err error)       // hex 加密

	RsaVerifySignBase64(msg []byte, base64Sign string) bool           // base64 验证
	RsaVerifySignHex(msg []byte, hexSign string) bool                 // hex 验证
	RsaDecryptByBase64(base64Cipher string) (plain []byte, err error) // base64 解密
	RsaDecryptByHex(hexCipher string) (plain []byte, err error)       // hex解密
}

//EccSigner ECC椭圆曲线加密使用了区块链以太坊中的相关接口,ECC一般只签名使用加密一般不使用
type EccSigner interface {
	EccSignBase64(msg []byte) (base64rSign, base64sSign string, err error)                         // base64 签名
	EccSignHex(msg []byte) (hexrSign, hexsSign string, err error)                                  // hex 签名
	EccEncryptToBase64(plainText []byte, base64PubKey string) (base64CipherText string, err error) // base64 加密
	EccEncryptToHex(plainText []byte, hexPubKey string) (hexCipherText string, err error)          // hex 加密

	EccVerifySignBase64(msg []byte, base64rSign, base64sSign string) bool                   // base64 验证
	EccVerifySignHex(msg []byte, hexrSign, hexsSign string) bool                            // hex 验证
	EccDecryptByBase64(base64CipherText, base64PriKey string) (plainText []byte, err error) // base64 解密
	EccDecryptByHex(hexCipherText, hexPriKey string) (plainText []byte, err error)          // hex 解密
}

type AesCbcSigner interface {
	AesCbcEncrypt(plainText []byte) (cipherText []byte, err error)
	AesCbcEncryptBase64(plainText []byte) (cipherTextBase64 string, err error)
	AesCbcEncryptHex(plainText []byte) (cipherTextHex string, err error)

	AesCbcDecrypt(cipherText []byte) (plainText []byte, err error)
	AesCbcDecryptByBase64(cipherTextBase64 string) (plainText []byte, err error)
	AesCbcDecryptByHex(cipherTextHex string) (plainText []byte, err error)
}

type AesCtrSigner interface {
	AesCtrEncrypt(plainText []byte) (cipherText []byte, err error)
	AesCtrEncryptBase64(plainText []byte) (cipherTextBase64 string, err error)
	AesCtrEncryptHex(plainText []byte) (cipherTextHex string, err error)

	AesCtrDecrypt(cipherText []byte) (plainText []byte, err error)
	AesCtrDecryptByBase64(cipherTextBase64 string) (plainText []byte, err error)
	AesCtrDecryptByHex(cipherTextHex string) (plainText []byte, err error)
}

type HashSigner interface {
	HmacSha256Hex(body string) string
	HmacSha512Hex(body string) string

	Sha1Hex(data []byte) string
	Sha256Hex(data []byte) string
	Sha512Hex(data []byte) string
}

func NewRsaSign(privateKey string, publicKey string) RsaSigner {
	return &rsa.RsaSign{
		PublicKey:  publicKey,
		PrivateKey: privateKey,
	}
}

func NewEccSign(privateKey string, publicKey string) EccSigner {
	return &ecc.EccSign{
		PublicKey:  publicKey,
		PrivateKey: privateKey,
	}
}

func NewAesCbcSign(secretKey string, ivAes string) AesCbcSigner {
	return &aes.CbcSign{
		SecretKey: []byte(secretKey),
		IvAes:     []byte(ivAes),
	}
}

func NewAesCtrSign(secretKey string, ivAes string) AesCtrSigner {
	return &aes.CtrSign{
		SecretKey: []byte(secretKey),
		IvAes:     []byte(ivAes),
	}
}

func NewHashSign(key string) HashSigner {
	return &hash.HashSign{
		Key: []byte(key),
	}
}
