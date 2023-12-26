package goa

import (
	"context"
	"golang.org/x/oauth2"
)

type Authenticator interface {
	Authenticate(ctx context.Context) (token *oauth2.Token, err error)
	UserInfo(ctx context.Context, token *oauth2.Token) (userInfo UserInfo, err error)
}

type UserInfo map[string]any
