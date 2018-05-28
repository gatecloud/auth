package auth0

import (
	"auth"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jinzhu/gorm"
	uuid "github.com/satori/go.uuid"
)

var (
	url                        = "https://xxxx.auth0.com/userinfo"
	clientTokenExpiresDuration = 86400
)

type GormStorage struct {
	db           *gorm.DB
	client       *ClientProfile
	tokenDecoder TokenDecoder
}

func NewStorage(db *gorm.DB) auth.Storage {
	gormStorage := &GormStorage{
		db:     db,
		client: &ClientProfile{},
	}
	return gormStorage
}

func (gs *GormStorage) Clone() auth.Storage {
	return gs
}

func (gs *GormStorage) Close() {
	gs.db.Close()
}

func (gs *GormStorage) GetClient(token string) (auth.Client, error) {
	*gs.client = ClientProfile{} // Important! Clear the space every time
	gs.db.Where("access_token = ?", token).Find(gs.client)
	fmt.Println("gs.CLient:", gs.client.IsValid())
	if !gs.client.IsValid() {
		var (
			clientProfile ClientProfile
			verifiedURL   string
		)
		if len(strings.SplitN(token, ".", 3)) == 3 {
			gs.tokenDecoder = &JWTDecoder{}
		} else {
			gs.tokenDecoder = &OpaqueDecoder{}
			verifiedURL = url
		}
		err := gs.tokenDecoder.Parse(token, verifiedURL)
		if err != nil {
			return nil, err
		}

		profileID, err := gs.tokenDecoder.GetIDFromSubject()
		if err != nil {
			return nil, err
		}

		roleName := "MB"
		audience := gs.tokenDecoder.GetAudience()
		if audience != "" {
			var (
				role       Role
				nestedRole NestedRole
			)
			if err := gs.db.Table(role.TableName()).
				Select("users.id, role_name, status").
				Joins("JOIN users on users.role_id = info_roles.id").
				Where("users.id = ?", profileID).
				Scan(&role).Error; err != nil {
				return nil, errors.New("fail to find user's role by ProfileID")
			}
			if err := gs.db.Where("client_id = ?", audience).
				Find(&nestedRole).Error; err != nil {
				return nil, errors.New("unauthorized client")
			}
			roleName = nestedRole.NestedRoleName
			if nestedRole.NestedRoleName == "" {
				roleName = role.RoleName
			}
		}

		// TODO: add the check of user's status

		if profileID == "" {
			return nil, errors.New("UUID Missing")
		}

		id, err := uuid.FromString(profileID)
		if err != nil {
			return nil, err
		}

		if id == (uuid.UUID{}) {
			return nil, errors.New("UUID Invalid")
		}

		clientProfile.AccessToken = token
		clientProfile.ProfileID = id
		clientProfile.RoleName = roleName
		clientProfile.ExpiresIn = int64(clientTokenExpiresDuration)
		clientProfile.ExpiresAt = time.Now().
			Add(time.Duration(clientProfile.ExpiresIn) * time.Second)

		if err := gs.SaveClient(&clientProfile); err != nil {
			return nil, err
		}
	}
	return gs.client, nil
}

func (gs *GormStorage) SaveClient(client interface{}) error {
	err := gs.client.SetClient(client)
	if err != nil {
		return err
	}

	return gs.db.Save(gs.client).Error
}

func (gs *GormStorage) DeleteClient() error {
	return gs.db.Delete(gs.client).Error
}

type Role struct {
	UserID     uuid.UUID `json:"id"`
	RoleName   string    `json:"role_name"`
	UserStatus int       `json:"status"`
}

func (Role) TableName() string {
	return "info_roles"
}

type NestedRole struct {
	ClientID       string `validate:"required" gorm:"not null;unique_index"`
	ClientName     string
	RoleName       string
	NestedRoleName string
}

func (NestedRole) TableName() string {
	return "info_nested_roles"
}
