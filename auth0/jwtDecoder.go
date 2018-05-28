package auth0

import (
	"errors"

	jwt "github.com/dgrijalva/jwt-go"
)

var (
	jwksURL = "https://xxxx.auth0.com/.well-known/jwks.json"
)

type JWTDecoder struct {
	BaseDecoder
	Nickname  string `json:"nickname"`
	Name      string `json:"name"`
	Picture   string `json:"picture"`
	UpdatedAt string `json:"updated_at"`
	Issue     string `json:"iss"`
	Subject   string `json:"sub"`
	Audience  string `json:"aud"`
	Iat       string `json:"iat"`
	Exp       string `json:"exp"`
}

func (jwtd *JWTDecoder) Parse(token, verifiedURL string) error {
	var (
		jwtDecoder JWTDecoder
		ok         bool
	)

	jwtToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		if token.Method.Alg() == jwt.SigningMethodRS256.Name {
			keyData, err := ParseJWKS(jwksURL, "RS256")
			if err != nil {
				return nil, err
			}

			key, _ := jwt.ParseRSAPublicKeyFromPEM([]byte(keyData))
			return key, nil
		}
		return nil, errors.New("unexpected signing method")
	})
	if err != nil {
		return err
	}
	if claims, claimOk := jwtToken.Claims.(jwt.MapClaims); claimOk && jwtToken.Valid {
		jwtDecoder.Issue, ok = claims["iss"].(string)
		if !ok {
			return errors.New("iss is null")
		}
		jwtDecoder.Subject, ok = claims["sub"].(string)
		if !ok {
			return errors.New("sub is null")
		}
		jwtDecoder.Audience, ok = claims["aud"].(string)
		if !ok {
			return errors.New("the aud(client id) is null")
		}
	}
	*jwtd = jwtDecoder
	jwtd.BaseDecoder.Subject = jwtDecoder.Subject
	return nil
}

func (jwtd *JWTDecoder) GetAudience() string {
	return jwtd.Audience
}
