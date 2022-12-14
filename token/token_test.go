/**
    @author: potten
    @since: 2022/12/13
    @desc: //TODO
**/
package token

import (
	"fmt"
	"testing"
)

var tokenStr = "JWT eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2NzE1MjQwODEsImlhdCI6MTY3MDkxOTI4MSwiQXBwSWQiOiI2MzcxYjg2ZGUyYWFiYWIwNGYwOGJjMTYiLCJJbmZvIjp7Il9pZCI6IjYzNzFiODZkZTJhYWJhYjA0ZjA4YmMxNiIsIm5hbWUiOiLlva3pgqbnhLEiLCJwaG9uZSI6IjE4ODg0MDU4NzA3In19.VZLyxrPi2Ot9uwKAE4lQxQ9-FqGGczD1CYZp6ql8uWI"
var publicKey = "MIGJAoGBAMAPcQ6qkyMJ3IA/8yDmVOg+/oWH2MYwwLnMC1kuLLncMtfWZNjNGb5fOk3wMIZYU9oSI+y+IsMcGSNizU1KUPbdP3M0ExmCNCId3ygOGJLmYBsFUV+/mTNSQpjd7fqHeySyDFobXRMS1BB5wFGHpmzU1oZd8o1GLtiUVzi3Ppf3AgMBAAE="
var token Tokener

func init() {
	token = NewToken(publicKey)
}

func Test_GeneratorJwt(t *testing.T) {
	appId := "6371b86de2aabab04f08bc16"
	user := map[string]interface{}{
		"_id":   "6371b86de2aabab04f08bc16",
		"name":  "彭邦焱",
		"phone": "18884058707",
	}
	token, err := token.GeneratorToken(appId, user)
	fmt.Printf(token, err)
}

func Test_ParseJwt(t *testing.T) {
	res, err := token.ParseToken(tokenStr)
	fmt.Println(res, err)
}
