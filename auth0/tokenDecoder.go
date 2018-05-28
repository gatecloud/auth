package auth0

import (
	"errors"
	"strings"
)

type TokenDecoder interface {
	Parse(token, verifiedURL string) error
	GetIDFromSubject() (string, error)
	GetAudience() string
}

type BaseDecoder struct {
	Subject string
}

func (d *BaseDecoder) Parse(token, verifiedURL string) error {
	return nil
}

func (d *BaseDecoder) GetIDFromSubject() (string, error) {
	idStr := d.Subject
	splitStr := strings.SplitN(d.Subject, "|", 2)
	if len(splitStr) == 2 {
		idStr = splitStr[1]
	}
	if idStr == "" {
		return "", errors.New("subject does not contain ID")
	}

	return idStr, nil
}

func (d *BaseDecoder) GetAudience() string {
	return ""
}
