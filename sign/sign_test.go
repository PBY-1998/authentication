/**
    @author: potten
    @since: 2022/12/12
    @desc: //TODO
**/
package sign

import (
	"fmt"
	"testing"
)

var (
	msg = "床前明月光，疑是地上霜，举头望明月，低头思故乡"

	rsaBase64PubKey1024 = "MIGJAoGBAMAPcQ6qkyMJ3IA/8yDmVOg+/oWH2MYwwLnMC1kuLLncMtfWZNjNGb5fOk3wMIZYU9oSI+y+IsMcGSNizU1KUPbdP3M0ExmCNCId3ygOGJLmYBsFUV+/mTNSQpjd7fqHeySyDFobXRMS1BB5wFGHpmzU1oZd8o1GLtiUVzi3Ppf3AgMBAAE="
	rsaBase64PriKey1024 = "MIICXgIBAAKBgQDAD3EOqpMjCdyAP/Mg5lToPv6Fh9jGMMC5zAtZLiy53DLX1mTYzRm+XzpN8DCGWFPaEiPsviLDHBkjYs1NSlD23T9zNBMZgjQiHd8oDhiS5mAbBVFfv5kzUkKY3e36h3sksgxaG10TEtQQecBRh6Zs1NaGXfKNRi7YlFc4tz6X9wIDAQABAoGALw2ZbTZtBdCMrP792bmUY7HLOXumqCeZj+tlfFvLqV1BN4/W9SaKgBFkf2Ow/7j0EiEPnBiY+6QOpJS4J49ldihgyHSpzPBIorDn1HANXQBw7Ao4CdzZdh3bCxDNYK7nupOXIK+pOefX+9uUnBkgcFXaYRWIwjAancMfiQK2F4ECQQDI65yiim3sbWV4XLfSJoMs7ZPzZOYSeAdn+bNx/8eQGrWeJF28w23X7Dgk6l+0nZswnjBjOPtsiv7S9VACviL5AkEA9LYKhgSgdGVduNuDXnvdwid0ZalRKfOWbuwFwkbz4vYofNsI45upS3UdiUC2Sv1xfksaactugQqQtAhM7SZebwJBALJQQIQUnPfuItbOWqmcWmCePOcPDg0oD1KczkAHQ+JFghfmqHZlbu/pie5hPyz5jwh36/OzV5f+R6eL5UV532kCQQCT8yfjpRJ5rPuAEz+WtV76zq3h9P98VKiEAbDtp8Y2V0tdSXRTYD53v6QO4pAUQK0IhVG/2t3BqOiZ4FbaHpODAkEAn/d4oMKBhWiZNYZxKAHdeOOEgymWtB1j1yF4onOxkfd9SUFbXmvKFADOmFrKxhOQ2Lwk+YkLMQmRecv20j019w=="

	rsaBase64PubKey2048 = "MIIBCgKCAQEAv2hP/h15ORmlusXUMP+q3ErGbnmVTHarKBee6Qoid4HRJZ2ZDClCcvEDYze1ZFJeWtLlV8riAewAln37fB7XHVSzo88jPa6ltEE2LRQtK4ozSHEBWr2Hhqay/ChO/jLYgu8PiKXf5fgh1mgM7RHZHa24K7oTtn01yGtgLyqwZ9La7+efG6VflLLopWXGIdYtoGy0LeiYbJ7Hm6mefAtPFmd84kC6sG+Y/vJPiZ46LOncasIK2BDGz+665s25VG0Bk7qmxkndlJf9tyrKBUx85m1Ty9TPH1AS+vrIUjToTh8s/wfcB1Mnlh7WE88O3MKCztAEwCqTxnApr+atBRI3aQIDAQAB"
	rsaBase64PriKey2048 = "MIIEpAIBAAKCAQEAv2hP/h15ORmlusXUMP+q3ErGbnmVTHarKBee6Qoid4HRJZ2ZDClCcvEDYze1ZFJeWtLlV8riAewAln37fB7XHVSzo88jPa6ltEE2LRQtK4ozSHEBWr2Hhqay/ChO/jLYgu8PiKXf5fgh1mgM7RHZHa24K7oTtn01yGtgLyqwZ9La7+efG6VflLLopWXGIdYtoGy0LeiYbJ7Hm6mefAtPFmd84kC6sG+Y/vJPiZ46LOncasIK2BDGz+665s25VG0Bk7qmxkndlJf9tyrKBUx85m1Ty9TPH1AS+vrIUjToTh8s/wfcB1Mnlh7WE88O3MKCztAEwCqTxnApr+atBRI3aQIDAQABAoIBAE7z3zMpwywbeTIukhVYEIlnyqwdOMlelcEm5SSpSohTIwtKE6xhhIhXBBe0Df2AwGzkWze4dztltuRcuRR8wCzYGHV0Zsv1s2JEF+3GSc+Q5RB3lKByV2nibyf2FIdkP8zagWTTTyTUElkXeGV9nDpSwwo+ag03Xqz6JaWvDS71oyf5AVprQlcDUuyVQGs3zrOy8+eetbyEdHHwfGibV8WaYbgGE38vfO45we0rZ9uehEq4Vn4T1lmTGrTctqrn9ddFuBMtov+3hbgZm9ywOzzdT6aZFXASocqbLGlprDKR8XIjKgY6B5vKOK8E9w5T7sFfIz/fLtDuwyIcIP4HNdECgYEA1sLM+RYypIawd27tyGhVQg5ojhDt9n92ZeOOO2c0FRlQZgmrDBKeqW3pCw0XgjsZKjEUhelmLvrLxS95uLuxDdRnbmirfu76Q005vgZ3B9pPO3Y9iLVKUrwocuT/3JEs/7sJ/PD33oeJY++z7gy404C/5IcQz0jbpd0U7OSk+mUCgYEA5CmBBkw9SOlOr1/GWFjhRvqFGEqK2xgVQLtT0J5zRwxTaNUolXZAQ0/IMsdE4iuxFiPaagFioJHDak9YNh/HUYQkb4Aex6yg3jkfATJqX0jaM04097VRKT7XRHEF1SRKLjY54+KG+yjCnOLLm9CC7V4psFErR8VRlLzsJGR+lrUCgYEAm8oCEOsWX51JI8p3eXqd5mY3WF9VkAvUooLZKaRq9qc/WFXJG9/h8rxFYnvjwtgGIEIsRhwSwR+zc95FqUmWXZboVQJe7ZyENRAvQ/bCoBKwiUzzxFjmim/t07LlHGa/wt82lqNi261sb+9xkczuwpbSHQARpJyQoZhn1pTiTLUCgYEAr6ps1oZ4YNyQYmIg+gBkYhubwZoS0qD2LAKOg36bTsZkqcAEIR8MV0bj4oSdumzdSSiNjzRF1U6k4AL67aEF+vL8goRoLl/w82eTQX6pe3dB2GKMUXNea50gbGeAkBwCqRXC+Ht+ZX16aQQMs4iUZWEsQ74azoVTTGswfMyK0kkCgYAXBMya9oTrULqOSBe1ARTrgpd/N7ftisSDMkeoDKsz/V8ZQDmFPoajDmlq69SXvJk7Su9RIi+gVGYIYEDVHeJH3EPWq+987r1tax3umhfrbYFiTrVhhq2sJT4Xca6ylMVcVofy6g74z53rW/XF/Yso5FSrH7X+TSXNreECwxCKgA=="

	rsaHexPubKey1024 = "30818902818100a76011f71034f77c3a03a6ef2601ab847e9e2eba7243e83c0f7b46e61d5cd08d450a3b8948cad9e78fa435d27409e83634cfa54676cdd4f9a0ee6fcca662247a25ea26e8ce4746663267638626d576ee6c3b80e6200d76342e6fe50f7d1b866f18889f211819bebb98888f1b34b9b4d44a881eef5437cd958b206c65f69e6bf30203010001"
	rsaHexPriKey1024 = "3082025d02010002818100a76011f71034f77c3a03a6ef2601ab847e9e2eba7243e83c0f7b46e61d5cd08d450a3b8948cad9e78fa435d27409e83634cfa54676cdd4f9a0ee6fcca662247a25ea26e8ce4746663267638626d576ee6c3b80e6200d76342e6fe50f7d1b866f18889f211819bebb98888f1b34b9b4d44a881eef5437cd958b206c65f69e6bf302030100010281810099e4a9600314d060f66e9934d63b3edb0a18a35a66e9ad445befbb56a5b4cb44b9301961b6fe5cb09ed01b74afa0d453d2e7014df2ba7a9233b8482f60e468283288e4a365c51dea24535824f190d86f2a898cca3b90fa77b69b496927f1d7f8be00df0e6bf712d69c49a1d9924d0197e2e456a96196bf24f653045670ce0941024100c81a071c75ec9ee4de22393b85af1104d9e1f5e07d55abc4a34a1bcc502fc76dc8c87a3e7e56fedfdd3530bbaf6e0b2a59222722908b7260c42a06728a3e5b51024100d621a9b9ba1730eb25b38fe51e96cf8b65c5c505a6ae485f4f62a83bc4dd6764648d67bb82d24fea13faeef3134efe7318155179eb652f19bbf1365f01433a03024100b275cc1bccec4075dbcae80236e300a9b3ec7b8e4019b4fcc5a8e58bdd840f37d15742f713546131a4a6b894db0ba8b7971107982313cae99469eaa022bd24510240378df645dc54e5f92c07e11e558855025a7e2bf6a25ef721db2bc26ff74c65e5b2fcc8dbea3dfc43c3b947c342d02ccdd982b667c63db3319f041ed21936c2d7024054058716c23b14388dae0f6a577324af971ef596e2ac48d13d89519c3f3e7329fab29f9b2d108460477e7515727e9d5d025d5c599033ece08d9a3a82b0f11ee4"

	rsaHexPubKey2048 = "3082010a0282010100ccb565d6fd4f477cd62a623e361c9a3a6826fc3256213cf1688f92f614219417a0de6646d35d5303146623238160b16ea7a2a840938dc1a40f2ba68ce1d79bbea30b4f4f05fcaa97cf7151c0e9ecf12997a2b3b0539e095e7d0bc3de5bb7bb62817589f44cc0d87bc2d4f148b90dd47335b91c92874763306fe8919dcfd118011fcf0895395bd535b57bcad8f83b9f842c1ebe1a3f0c6c8fd39d9bc6c7152ad90e38d97394e584956b947008a0364011fa7125492c779a0f8c3dcdb5f502519be781ef0a55cf062ed512319d7fb0dbfe91bb9e97096a4be6bfc2bfe48c2a7e525496cbea5180c71585cc6f1abeced10b99fbf2d984f5644a550acaeb62b83d190203010001"
	rsaHexPriKey2048 = "308204a20201000282010100ccb565d6fd4f477cd62a623e361c9a3a6826fc3256213cf1688f92f614219417a0de6646d35d5303146623238160b16ea7a2a840938dc1a40f2ba68ce1d79bbea30b4f4f05fcaa97cf7151c0e9ecf12997a2b3b0539e095e7d0bc3de5bb7bb62817589f44cc0d87bc2d4f148b90dd47335b91c92874763306fe8919dcfd118011fcf0895395bd535b57bcad8f83b9f842c1ebe1a3f0c6c8fd39d9bc6c7152ad90e38d97394e584956b947008a0364011fa7125492c779a0f8c3dcdb5f502519be781ef0a55cf062ed512319d7fb0dbfe91bb9e97096a4be6bfc2bfe48c2a7e525496cbea5180c71585cc6f1abeced10b99fbf2d984f5644a550acaeb62b83d190203010001028201003740aae9395be1a6bf43975ac54e390e94b819101911459abf27297a83fa8037547352d5c10d0a6fe55ca01560415202d4fa614174d22936f7e54741f55f35a961e6969474c03ae758d57444869f2e84946a14e7fdd9c51b9cd2c51e4a513021a961a947a843d0eaaeaebd256cd55fc76cf3b6d391f1e1c2dc21c0d40098a64a83b724a18b01e53525957e601f6a532599b2e4915842872016f46b45829e0885687e62671e72ca810cc80a033f7ca9c76981746ce4d0619d27f9d95ce6397217d184719ba5caa3edca09f8faa578729fca288420fbdff0da3d82ca7a4ed3f34831e3b3fa1e1b62b4286ad882164ed9b6c470a6e36bd7910faf3c87502ca1309102818100ee41ab305bf9b19a6b879daaf20e0ec76b34a0c5846e6fffc3fa4826c854bcaae3262928a0b9a0eb827acf86bc7d1440d6f789fb6da2600bead44c0bde631f85130e7e28f2f61623b41710e5e52e44c74c049b20dd4aed8c4f61086a491d5d2423df8d0bb2ff0cd6e31de5475b6b4941691430e08f51e635a5ced1a6c183fff502818100dbf42451e598e6281f1f00221668ce8541308864b5778381fa78e04f9a6fbed7a71e2aa9bc1f23d253d4f1cef62d3fd8716549e0adcf3e4dfeb6fc73675426ffe5a02ff8909e79471dea923e42f396bc2183ec189bec02ab37cb6fd2edd96b291ba8fe09535c03f9182e9e7a87f9c095a3d687ec54422eaeaa481ba4df0286150281806983ebac9f0f15f8ad66820d12e5e6e5aa34c47eb507b3d23198c61b66dd20310e27f85265dbcfc87d20a687a5323fa5f78de92dd07ff8c94e5676d74ac5db4fb400d71e8b7b3092df4ed7ccf89265235e272c0c81f48cff76a82271efaf71706ff2b1245d41570e53c709a37079331824d12c5447249e2f641f13fa25f9af81028180435c9eeef1f904abcef4288f47fbab1c065dfdb79217db0fa88cf26d8ea7a073dd3b90e750b4dcbca26df9ec5f5a764e2c544feede6c34f1a00b9c7f1f6b17529199a077689b101b669f1b50b42273cc841b29e853805144ec9e824dc008311872df2b85e1a0b19accfc220ef6abd77e3ca20c18a5a96b3094f7e67774d10a0d02818075e22184e9f56ebd5239c1b1e4179b1a0fb90ac074c0ca51fe546290dc1b8016021e925642e08054fd66d9f334896ed8f5e50fc78937cb32f82d5e86656094c08e13e16408f9d4f680b5e06907e4faba509f0086c53c0f501bb483334369d12061320e6c66bb7a7686eb25603daa03371e2991acdf5a04fa4257f59ed4728aa8"

	eccBase64PubKey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE/sT6vKddsDd9tgU+b0Fo/Q8YT3wpXVe3JBQgk8+VI3dodQP8YilrvBFndZ2RoXkiQhSGTrmNW3Y7znzZnd+SGw=="
	eccBase64PriKey = "MHcCAQEEINPAYGsiVuUyA74gpNRlqUsEMoLNJ/ZbZpeVjY5qMuwNoAoGCCqGSM49AwEHoUQDQgAE/sT6vKddsDd9tgU+b0Fo/Q8YT3wpXVe3JBQgk8+VI3dodQP8YilrvBFndZ2RoXkiQhSGTrmNW3Y7znzZnd+SGw=="

	eccHexPubKey = "3059301306072a8648ce3d020106082a8648ce3d030107034200042a23ef71cd46a9b0f40c4e3ffcec80aa2e42c14d2b8d90a0875ccd9e9e7fdb53fe0cb11ad5a0d6729ad424d04f1e7c3007218eabdac811d9a58218c14ed5778a"
	eccHexPriKey = "30770201010420dabf169297e416276581ce3dca36e29599e061fe8351999b546f3fc930624ab7a00a06082a8648ce3d030107a144034200042a23ef71cd46a9b0f40c4e3ffcec80aa2e42c14d2b8d90a0875ccd9e9e7fdb53fe0cb11ad5a0d6729ad424d04f1e7c3007218eabdac811d9a58218c14ed5778a"

	key = "1234567812345678"
	iv  = "1234567812345678"

	hmac_key = "test"
)

var (
	eccBase64Sign EccSigner
	eccHexSign    EccSigner

	rsaBase64Sign1024 RsaSigner
	rsaBase64Sign2048 RsaSigner
	rsaHexSign1024    RsaSigner
	rsaHexSign2048    RsaSigner

	aesCbcSign AesCbcSigner
	aesCtrSign AesCtrSigner

	hashSign HashSigner
)

func init() {
	rsaBase64Sign1024 = NewRsaSign(rsaBase64PriKey1024, rsaBase64PubKey1024)
	rsaBase64Sign2048 = NewRsaSign(rsaBase64PriKey2048, rsaBase64PubKey2048)
	rsaHexSign1024 = NewRsaSign(rsaHexPriKey1024, rsaHexPubKey1024)
	rsaHexSign2048 = NewRsaSign(rsaHexPriKey2048, rsaHexPubKey2048)

	eccBase64Sign = NewEccSign(eccBase64PriKey, eccBase64PubKey)
	eccHexSign = NewEccSign(eccHexPriKey, eccHexPubKey)

	aesCbcSign = NewAesCbcSign(key, iv)
	aesCtrSign = NewAesCtrSign(key, iv)

	hashSign = NewHashSign(hmac_key)
}

func TestEccSignBase64(t *testing.T) {
	rText, sText, err := eccBase64Sign.EccSignBase64([]byte(msg))
	fmt.Println(rText, sText, err)

	res := eccBase64Sign.EccVerifySignBase64([]byte(msg), rText, sText)
	fmt.Println(res)
}

func TestEccSignHex(t *testing.T) {
	rText, sText, err := eccHexSign.EccSignHex([]byte(msg))
	fmt.Println(rText, sText, err)

	res := eccHexSign.EccVerifySignHex([]byte(msg), rText, sText)
	fmt.Println(res)
}

func TestRsaEncryptToBase64(t *testing.T) {
	base64CipherText, err := rsaBase64Sign1024.RsaEncryptToBase64([]byte(msg))
	fmt.Println(base64CipherText, err)

	plainText, err := rsaBase64Sign1024.RsaDecryptByBase64(base64CipherText)
	fmt.Println(string(plainText), err)

	base64CipherText, err = rsaBase64Sign2048.RsaEncryptToBase64([]byte(msg))
	fmt.Println(base64CipherText, err)

	plainText, err = rsaBase64Sign2048.RsaDecryptByBase64(base64CipherText)
	fmt.Println(string(plainText), err)
}

func TestRsaEncryptToHex(t *testing.T) {
	hexCipherText, err := rsaHexSign1024.RsaEncryptToHex([]byte(msg))
	fmt.Println(hexCipherText, err)

	plainText, err := rsaHexSign1024.RsaDecryptByHex(hexCipherText)
	fmt.Println(string(plainText), err)

	hexCipherText, err = rsaHexSign2048.RsaEncryptToHex([]byte(msg))
	fmt.Println(hexCipherText, err)

	plainText, err = rsaHexSign2048.RsaDecryptByHex(hexCipherText)
	fmt.Println(string(plainText), err)
}

func TestRsaSignBase64(t *testing.T) {
	base64CipherText, err := rsaBase64Sign1024.RsaSignBase64([]byte(msg))
	fmt.Println(base64CipherText, err)

	res := rsaBase64Sign1024.RsaVerifySignBase64([]byte(msg), base64CipherText)
	fmt.Println(res)

	base64CipherText, err = rsaBase64Sign2048.RsaSignBase64([]byte(msg))
	fmt.Println(base64CipherText, err)

	res = rsaBase64Sign2048.RsaVerifySignBase64([]byte(msg), base64CipherText)
	fmt.Println(res)
}

func TestRsaSignHex(t *testing.T) {
	hexCipherText, err := rsaHexSign1024.RsaSignHex([]byte(msg))
	fmt.Println(hexCipherText, err)

	res := rsaHexSign1024.RsaVerifySignHex([]byte(msg), hexCipherText)
	fmt.Println(res)

	hexCipherText, err = rsaHexSign2048.RsaSignHex([]byte(msg))
	fmt.Println(hexCipherText, err)

	res = rsaHexSign2048.RsaVerifySignHex([]byte(msg), hexCipherText)
	fmt.Println(res)
}

func TestAesCbcSign(t *testing.T) {
	cipherBytes, err := aesCbcSign.AesCbcEncrypt([]byte(msg))
	fmt.Println(cipherBytes, err)

	plainText, err := aesCbcSign.AesCbcDecrypt(cipherBytes)
	fmt.Println(string(plainText), err)

	base64Cipher, err := aesCbcSign.AesCbcEncryptBase64([]byte(msg))
	fmt.Println(base64Cipher, err)

	plainText, err = aesCbcSign.AesCbcDecryptByBase64(base64Cipher)
	fmt.Println(string(plainText), err)

	hexCipher, err := aesCbcSign.AesCbcEncryptHex([]byte(msg))
	fmt.Println(hexCipher, err)

	plainText, err = aesCbcSign.AesCbcDecryptByHex(hexCipher)
	fmt.Println(string(plainText), err)
}

func TestAesCtrSign(t *testing.T) {
	cipherBytes, err := aesCtrSign.AesCtrEncrypt([]byte(msg))
	fmt.Println(cipherBytes, err)

	plainText, err := aesCtrSign.AesCtrDecrypt(cipherBytes)
	fmt.Println(string(plainText), err)

	base64Cipher, err := aesCtrSign.AesCtrEncryptBase64([]byte(msg))
	fmt.Println(base64Cipher, err)

	plainText, err = aesCtrSign.AesCtrDecryptByBase64(base64Cipher)
	fmt.Println(string(plainText), err)

	hexCipher, err := aesCtrSign.AesCtrEncryptHex([]byte(msg))
	fmt.Println(hexCipher, err)

	plainText, err = aesCtrSign.AesCtrDecryptByHex(hexCipher)
	fmt.Println(string(plainText), err)
}

func TestHashSign(t *testing.T) {
	res := hashSign.HmacSha256Hex("hmac text")
	fmt.Println(res)

	res = hashSign.HmacSha512Hex("hmac text")
	fmt.Println(res)

	res = hashSign.Sha1Hex([]byte("sha text"))
	fmt.Println(res)

	res = hashSign.Sha256Hex([]byte("sha text"))
	fmt.Println(res)

	res = hashSign.Sha512Hex([]byte("sha text"))
	fmt.Println(res)
}
