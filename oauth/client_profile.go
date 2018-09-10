package oauth

import (
	"errors"
	"reflect"
	"time"

	uuid "github.com/satori/go.uuid"
)

type ClientProfile struct {
	ID           uuid.UUID `json:"profile_id" gorm:"primary_key;type:uuid;"`
	DisplayName  string    `json:"display_name"`
	RoleName     string    `json:"role_name"`
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresIn    int64     `json:"expires_in"`
	ExpiredAt    time.Time `json:"expired_at"`
	TokenType    string    `json:"token_type"`
	Domain       string    `json:"domain"`
	LoginedBy    string    `json:"logined_by"`
}

type Model struct {
	ID        uuid.UUID `gorm:"primary_key;type:uuid;default:uuid_generate_v4()"`
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt *time.Time `json:"-" sql:"index"`
}

func (cp *ClientProfile) GetProfileID() uuid.UUID {
	return cp.ID
}

func (cp *ClientProfile) GetClientDisplayName() string {
	return cp.LoginedBy
}

func (cp *ClientProfile) GetRoleName() string {
	return cp.RoleName
}

func (cp *ClientProfile) GetAccessToken() string {
	return cp.AccessToken
}

func (cp *ClientProfile) GetRefreshToken() string {
	return cp.RefreshToken
}

func (cp *ClientProfile) GetExpiredAt() time.Time {
	return cp.ExpiredAt
}

func (cp *ClientProfile) GetExpiresIn() int64 {
	return cp.ExpiresIn
}

func (cp *ClientProfile) GetTokenType() string {
	return cp.TokenType
}

func (cp *ClientProfile) GetScope() string {
	return ""
}

func (cp *ClientProfile) SetClient(client interface{}) error {
	v := reflect.ValueOf(client)
	if !v.IsValid() {
		return errors.New("client can not be empty")
	}

	c, ok := v.Elem().Interface().(ClientProfile)
	if !ok {
		return errors.New("the type is not match")
	}

	*cp = c
	return nil
}

func (cp *ClientProfile) IsValid() bool {
	client := reflect.ValueOf(cp)
	if !client.IsValid() {
		return false
	}
	now := time.Now().Add(2 * time.Second)
	if now.After(cp.ExpiredAt) {
		return false
	}
	return true
}
