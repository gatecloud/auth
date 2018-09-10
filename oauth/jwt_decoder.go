package oauth

import (
	"errors"
	"io/ioutil"
	"path/filepath"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	uuid "github.com/satori/go.uuid"
)

type JWTDecoder struct {
	BaseDecoder
	Role    string `json:"rol"`
	Picture string `json:"pic"`
}

func (jwtd *JWTDecoder) Parse(token, verifiedURL string) (*ClientProfile, error) {
	var (
		jwtDecoder JWTDecoder
	)
	jwtToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		if token.Method.Alg() == jwt.SigningMethodRS256.Name {
			path := filepath.Join(verifiedURL)
			keyData, err := ioutil.ReadFile(path)
			if err != nil {
				return nil, errors.New("Open CA.pem error")
			}

			key, _ := jwt.ParseRSAPublicKeyFromPEM(keyData)
			return key, nil
		}
		return nil, errors.New("unexpected signing method")
	})
	if err != nil {
		return nil, err
	}

	if claims, claimOk := jwtToken.Claims.(jwt.MapClaims); claimOk && jwtToken.Valid {
		expiredAt, ok := claims["exp"].(float64)
		if !ok {
			return nil, errors.New("exp is null")
		}

		jwtDecoder.ExpiredAt = int64(expiredAt)

		jwtDecoder.Subject, ok = claims["sub"].(string)
		if !ok {
			return nil, errors.New("sub is null")
		}

		jwtDecoder.Role, ok = claims["rol"].(string)
		if !ok {
			return nil, errors.New("rol")
		}
		jwtDecoder.Picture, ok = claims["pic"].(string)
		if !ok {
			return nil, errors.New("pic")
		}

		if jwtDecoder.Subject == "" {
			return nil, errors.New("sub is empty")
		}

		now := time.Now().Add(2 * time.Second).Unix()
		if now > jwtDecoder.ExpiredAt {
			return nil, errors.New("token has been expired")
		}
	}
	*jwtd = jwtDecoder

	id, err := uuid.FromString(jwtd.Subject)
	if err != nil {
		return nil, errors.New("sub is not string type")
	}

	clientProfile := &ClientProfile{
		ExpiredAt: time.Unix(jwtd.ExpiredAt, 0),
		ID:        id,
		RoleName:  jwtd.Role,
		LoginedBy: jwtd.Picture,
	}

	return clientProfile, nil
}
