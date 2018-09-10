package oauth

type TokenDecoder interface {
	Parse(token, verifiedURL string) (*ClientProfile, error)
}

type BaseDecoder struct {
	Subject   string `json:"sub"`
	ExpiredAt int64  `json:"exp"`
}

func (d *BaseDecoder) Parse(token, verifiedURL string) error {
	return nil
}
