package auth

// Client information
type Client interface {
	GetAccessToken() string
	GetRefreshToken() string
	GetExpiresIn() int64
	GetTokenType() string
	GetScope() string
	SetClient(client interface{}) error
	IsValid() bool
}
