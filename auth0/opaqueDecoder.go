package auth0

import (
	"errors"
	"net/http"
	"time"

	"bitbucket.org/zetaapp/go_library/services"
)

type OpaqueDecoder struct {
	BaseDecoder
}

// The UserID varies based on different URL
// /userinfo: the sub's format is "auth0|a7d71b03-e5c4-4e1f-b381-1f092ba83dd9",
// /api/v2/users?q=id: the user id is "auth0|c369489f-707c-4680-98b4-8f26187093cf"
type Auth0User struct {
	Sub       string    `json:"sub"`
	Auth0ID   string    `json:"user_id"`
	Nickname  string    `json:"nickname"`
	Name      string    `json:"name"`
	Picture   string    `json:"picture"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (o *OpaqueDecoder) Parse(token, verifiedURL string) error {
	var (
		auth0User     Auth0User
	)
	header := make(http.Header)
	header.Set("Authorization", "Bearer "+token)
	httpManager := services.HttpManager{
		Method:        "GET",
		URL:           verifiedURL,
		RequestHeader: header,
		Object:        &auth0User,
		Retry:         3,
	}
	r, err := httpManager.Request()
	if err != nil {
		return errors.New("Status Code:" + r.Status + ", " + err.Error())
	}
	o.BaseDecoder.Subject = auth0User.Sub
	return nil
}
