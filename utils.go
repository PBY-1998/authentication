/**
    @author: potten
    @since: 2022/12/13
    @desc: //TODO
**/
package authentication

import "errors"

var (
	ErrCipherKey           = errors.New("The secret key is wrong and cannot be decrypted. Please check")
	ErrKeyLengthSixteen    = errors.New("a sixteen or twenty-four or thirty-two length secret key is required")
	ErrKeyLengtheEight     = errors.New("a eight-length secret key is required")
	ErrKeyLengthTwentyFour = errors.New("a twenty-four-length secret key is required")
	ErrPaddingSize         = errors.New("padding size error please check the secret key or iv")
	ErrIvAes               = errors.New("a sixteen-length ivaes is required")
	ErrIvDes               = errors.New("a eight-length ivdes key is required")
	ErrRsaBits             = errors.New("bits 1024 or 2048")

	ErrJwtValidation = errors.New("token header is not JWT")
)

const (
	Ivaes = "pengbangyan12345678"
	Ivdes = "pengbangyan"

	privateFileName = "private.pem"
	publicFileName  = "public.pem"

	eccPrivateFileName = "eccPrivate.pem"
	eccPublishFileName = "eccPublic.pem"

	privateKeyPrefix = " RSA PRIVATE KEY "
	publicKeyPrefix  = " RSA PUBLIC KEY "

	eccPrivateKeyPrefix = " ECC PRIVATE KEY "
	eccPublicKeyPrefix  = " ECC PUBLIC KEY "
)
