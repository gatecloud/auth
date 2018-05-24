package oauth

import (
	"auth"
	"fmt"
	"net/http"

	"bitbucket.org/zetaapp/go_library/services"
	"github.com/jinzhu/gorm"
)

var (
	url = "http://localhost:8060/token"
)

type GormStorage struct {
	db     *gorm.DB
	client *ClientProfile
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
	gs.db.Where("access_token = ?", token).Find(gs.client)
	if !gs.client.IsValid() {
		var clientProfile ClientProfile
		header := make(http.Header)
		header.Set("Authorization", "Bearer "+token)

		httpManager := services.HttpManager{
			Method:        "GET",
			URL:           url,
			RequestHeader: header,
			Object:        &clientProfile,
			Retry:         3,
		}

		if r, err := httpManager.Request(); err != nil {
			return nil, fmt.Errorf("%s, %s", r.Status, err.Error())
		}

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

	if err = gs.db.Save(gs.client).Error; err != nil {
		return err
	}
	return nil
}

func (gs *GormStorage) DeleteClient() error {
	if err := gs.db.Delete(gs.client).Error; err != nil {
		return err
	}
	return nil
}
