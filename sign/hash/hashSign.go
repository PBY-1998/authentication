/**
    @author: potten
    @since: 2022/12/13
    @desc: //TODO
**/
package hash

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"io"
)

type HashSign struct {
	Key []byte
}

func (h *HashSign) Sha1Hex(data []byte) string {
	return hex.EncodeToString(Sha1(data))
}

func Sha1(data []byte) []byte {
	digest := sha1.New()
	digest.Write(data)
	return digest.Sum(nil)
}

func (h *HashSign) Sha256Hex(data []byte) string {
	return hex.EncodeToString(Sha256(data))
}

func Sha256(data []byte) []byte {
	digest := sha256.New()
	digest.Write(data)
	return digest.Sum(nil)
}

func (h *HashSign) Sha512Hex(data []byte) string {
	return hex.EncodeToString(Sha512(data))
}

func Sha512(data []byte) []byte {
	digest := sha512.New()
	digest.Write(data)
	return digest.Sum(nil)
}

func HmacSha256(key []byte, body string) []byte {
	hm := hmac.New(sha256.New, key)
	io.WriteString(hm, body)
	return hm.Sum(nil)
}

func (h *HashSign) HmacSha256Hex(body string) string {
	return hex.EncodeToString(HmacSha256(h.Key, body))
}

func HmacSha512(key []byte, body string) []byte {
	hm := hmac.New(sha512.New, key)
	io.WriteString(hm, body)
	return hm.Sum(nil)
}

func (h *HashSign) HmacSha512Hex(body string) string {
	return hex.EncodeToString(HmacSha512(h.Key, body))
}
