package auth

import (
	"errors"
)

type AuthServer struct {
	Storage Storage
}

func InitAuthServer(storage Storage) (*AuthServer, error) {
	if storage == nil {
		return nil, errors.New("storage can not be empty")
	}

	authServer := &AuthServer{
		Storage: storage,
	}
	return authServer, nil
}

func (as *AuthServer) GetClient(token string) (Client, error) {
	if token == "" {
		return nil, errors.New("token can not be empty")
	}
	client, err := as.Storage.GetClient(token)
	if err != nil {
		return nil, err
	}
	return client, err
}
