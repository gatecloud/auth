package auth0

import (
	"errors"
	"fmt"
	"net/http"
	"reflect"

	"bitbucket.org/zetaapp/go_library/services"
)

type JWKS map[string][]JWK

type JWK map[string]interface{}

func ParseJWKS(jwksURL, signingKey string) (string, error) {
	if jwksURL == "" {
		return "", errors.New("path can not be empty")
	}

	jwks := make(JWKS)
	httpManager := services.HttpManager{
		Method:        "GET",
		URL:           jwksURL,
		RequestHeader: make(http.Header),
		Object:        &jwks,
		Retry:         3,
	}

	r, err := httpManager.Request()
	if err != nil {
		return "", fmt.Errorf("%s, %s", r.Status, err.Error())
	}

	publicKey := "-----BEGIN CERTIFICATE-----\r\n"
	for _, jwk := range jwks["keys"] {
		if jwk["alg"] == signingKey {
			v := reflect.ValueOf(jwk["x5c"])
			if !v.IsValid() || v.Kind() != reflect.Slice {
				return "", errors.New("x5c is not valid or the type is not slice")
			}
			certificate, ok := v.Index(0).Interface().(string)
			if ok {
				publicKey += certificate
			}
			break
		}
	}

	publicKey += "\r\n-----END CERTIFICATE-----\r\n"
	return publicKey, nil
}
