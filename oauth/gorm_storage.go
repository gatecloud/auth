package oauth

import (
	"auth"
	"strings"

	"github.com/jinzhu/gorm"
)

type GormStorage struct {
	db              *gorm.DB
	client          *ClientProfile
	tokenDecoder    TokenDecoder
	certificatePath string
	authServerPath  string
}

func NewStorage(db *gorm.DB, certPath, authServerPath string) auth.Storage {
	gormStorage := &GormStorage{
		db:              db,
		client:          &ClientProfile{},
		certificatePath: certPath,
		authServerPath:  authServerPath,
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
	*gs.client = ClientProfile{}
	verifiedURL := ""
	s := strings.SplitN(token, ".", 3)
	if len(s) == 3 {
		gs.tokenDecoder = &JWTDecoder{}
		clientProfile, err := gs.tokenDecoder.Parse(token, gs.certificatePath)
		if err != nil {
			return nil, err
		}
		gs.client.SetClient(clientProfile)
	} else {
		gs.db.Where("access_token = ?", token).Find(gs.client)
		if gs.client.IsValid() {
			return gs.client, nil
		}

		gs.tokenDecoder = &OpaqueDecoder{}
		verifiedURL = gs.authServerPath
		clientProfile, err := gs.tokenDecoder.Parse(token, verifiedURL)
		if err != nil {
			return nil, err
		}
		if err := gs.SaveClient(clientProfile); err != nil {
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
