package oauth

import (
	"errors"
	"net/http"

	"github.com/gatecloud/utils"
)

type OpaqueDecoder struct {
	BaseDecoder
}

func (o *OpaqueDecoder) Parse(token, verifiedURL string) (*ClientProfile, error) {
	var clientProifle ClientProfile
	header := make(http.Header)
	header.Set("Authorization", "Bearer "+token)
	request := utils.Request{
		Method: "GET",
		URL:    verifiedURL,
		Header: header,
		Object: &clientProifle,
		Retry:  3,
	}

	r, err := request.Do()
	if err != nil {
		return nil, errors.New("Status Code:" + r.Status + ", " + err.Error())
	}

	o.Subject = clientProifle.ID.String()

	return &clientProifle, nil
}
