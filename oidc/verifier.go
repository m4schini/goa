package oidc

import (
	"context"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/m4schini/goa"
	"golang.org/x/oauth2"
	"time"
)

type oidcVerifier struct {
	config Config
}

func NewVerifier(config Config) *oidcVerifier {
	v := new(oidcVerifier)
	v.config = config
	return v
}

func (v *oidcVerifier) UserInfo(ctx context.Context, token *oauth2.Token) (userInfo goa.UserInfo, err error) {
	return UserInfo(ctx, token, v.config)
}

func UserInfo(ctx context.Context, token *oauth2.Token, config Config) (userInfo goa.UserInfo, err error) {
	provider, err := oidc.NewProvider(ctx, config.Url)
	if err != nil {
		return userInfo, err
	}
	user, err := provider.UserInfo(ctx, oauth2.StaticTokenSource(token))
	if err != nil {
		return userInfo, err
	}
	err = user.Claims(&userInfo)
	return userInfo, err
}

func Verify(accessToken string, verifier goa.Verifier) (goa.UserInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	token := &oauth2.Token{
		AccessToken: accessToken,
		TokenType:   "Bearer",
	}
	return verifier.UserInfo(ctx, token)
}
