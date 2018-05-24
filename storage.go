package auth

type Storage interface {
	Clone() Storage
	Close()
	GetClient(token string) (Client, error)
	SaveClient(client interface{}) error
	DeleteClient() error
}
