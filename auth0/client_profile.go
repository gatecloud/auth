package auth0

import (
	"errors"
	"reflect"
	"time"

	uuid "github.com/satori/go.uuid"
)

type ClientProfile struct {
	Model
	ProfileID         uuid.UUID `json:"user_id" gorm:"type:uuid;not null;"`
	ClientDisplayName string    `json:"client_display_name"`
	DisplayName       string    `json:"display_name"`
	RoleName          string    `json:"role_name"`
	Domain            string    `json:"domain"`
	ExpiresAt         time.Time `json:"expires_at" gorm:"not null"`
	AccessToken       string    `json:"access_token" gorm:"not null"`
	RefreshToken      string    `json:"refresh_token"`
	ExpiresIn         int64     `json:"expires_in" gorm:"not null"`
	TokenType         string    `json:"token_type"`
	Scope             string    `json:"scope"`
}

type Model struct {
	ID        uuid.UUID `gorm:"primary_key;type:uuid;default:uuid_generate_v4()"`
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt *time.Time `json:"-" sql:"index"`
}

func (cp *ClientProfile) GetProfileID() uuid.UUID {
	return cp.ProfileID
}

func (cp *ClientProfile) GetClientDisplayName() string {
	return cp.ClientDisplayName
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
	return cp.ExpiresAt
}

func (cp *ClientProfile) GetExpiresIn() int64 {
	return cp.ExpiresIn
}

func (cp *ClientProfile) GetTokenType() string {
	return cp.TokenType
}

func (cp *ClientProfile) GetScope() string {
	return cp.Scope
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
	if now.After(cp.ExpiresAt) {
		return false
	}
	return true
}
