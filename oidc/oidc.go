package oidc

import (
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
