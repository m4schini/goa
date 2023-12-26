package oidc

import (
	"context"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/m4schini/goa"
	"golang.org/x/oauth2"
)

type Config struct {
	// e.g. Keycloak url: https://iam.bluebutterfly.dev/realms/<realm>
	Url          string
	ClientId     string
	ClientSecret string
}

type Session struct {
	OAuth2Token   oauth2.Token  `json:"OAuth2Token"`
	IDTokenClaims IDTokenClaims `json:"IDTokenClaims"`
}

type IDTokenClaims struct {
	Exp               int    `json:"exp"`
	Iat               int    `json:"iat"`
	AuthTime          int    `json:"auth_time"`
	Jti               string `json:"jti"`
	Iss               string `json:"iss"`
	Aud               string `json:"aud"`
	Sub               string `json:"sub"`
	Typ               string `json:"typ"`
	Azp               string `json:"azp"`
	SessionState      string `json:"session_state"`
	AtHash            string `json:"at_hash"`
	Acr               string `json:"acr"`
	Sid               string `json:"sid"`
	EmailVerified     bool   `json:"email_verified"`
	Name              string `json:"name"`
	PreferredUsername string `json:"preferred_username"`
	Locale            string `json:"locale"`
	GivenName         string `json:"given_name"`
	FamilyName        string `json:"family_name"`
	Email             string `json:"email"`
}

func UserInfo(ctx context.Context, token *oauth2.Token, config Config) (userInfo goa.UserInfo, err error) {
	provider, err := oidc.NewProvider(ctx, config.Url)
	if err != nil {
		return userInfo, err
	}
	user, err := provider.UserInfo(ctx, &PseudoTokenSource{token: token})
	if err != nil {
		return userInfo, err
	}
	err = user.Claims(&userInfo)
	return userInfo, err
}

type PseudoTokenSource struct {
	token *oauth2.Token
}

func (p *PseudoTokenSource) Token() (*oauth2.Token, error) {
	return p.token, nil
}
