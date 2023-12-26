package keycloak

import "github.com/m4schini/goa"

type UserInfoJson struct {
	Id            string `json:"sub"`
	Username      string `json:"preferred_username"`
	FullName      string `json:"name"`
	EmailAddress  string `json:"email"`
	Locale        string `json:"locale"`
	Name          string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	EmailVerified bool   `json:"email_verified"`
}

func ID(info goa.UserInfo) string {
	return userInfoString(info, "sub")
}

func Username(info goa.UserInfo) string {
	return userInfoString(info, "preferred_username")
}

func Email(info goa.UserInfo) string {
	return userInfoString(info, "email")
}

func userInfoString(info goa.UserInfo, key string) string {
	sub, exists := info[key]
	if !exists {
		sub = ""
	}
	id, ok := sub.(string)
	if !ok {
		id = ""
	}
	return id
}
