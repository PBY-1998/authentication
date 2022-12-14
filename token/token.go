/**
    @author: potten
    @since: 2022/12/13
    @desc: //TODO
**/
package token

import (
	"fmt"
	"github.com/PBY-1998/authentication"
	"github.com/golang-jwt/jwt/v4"
	"strings"
	"time"
)

type Token struct {
	publicKey string
}

type TokenClaims struct {
	*jwt.StandardClaims
	*User
}

type User struct {
	AppId string
	Info  interface{}
}

type Tokener interface {
	GeneratorToken(appId string, user interface{}) (string, error) // 生成JWT
	ParseToken(token string) (jwt.MapClaims, error)                // 解析JWT
}

func NewToken(publicKey string) Tokener {
	return &Token{
		publicKey: publicKey,
	}
}

func (j *Token) GeneratorToken(appId string, user interface{}) (string, error) {
	claims := &TokenClaims{
		StandardClaims: &jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Minute * 60 * 24 * 7).Unix(), // 过期时间
			IssuedAt:  time.Now().Unix(),                                // 签发时间
		},
		User: &User{
			AppId: appId,
			Info:  user,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(j.publicKey))
}

func (j *Token) ParseToken(token string) (jwt.MapClaims, error) {
	tokens := strings.Split(token, " ")
	if len(tokens) != 2 && !strings.EqualFold("JWT", tokens[0]) {
		panic(authentication.ErrJwtValidation)
	}

	tokenClaims, err := jwt.Parse(tokens[1], func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(j.publicKey), nil
	})

	claims, ok := tokenClaims.Claims.(jwt.MapClaims)
	if ok && tokenClaims.Valid {
		return claims, nil
	}

	return nil, err
}
