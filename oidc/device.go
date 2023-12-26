package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/m4schini/goa"
	"golang.org/x/oauth2"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

var AuthorizationPendingErr = fmt.Errorf("authorization_pending")

type DeviceFlowAuthOption func(flow *deviceFlow)

type deviceFlow struct {
	config          Config
	verificationUri string
	deviceCode      string
	deviceCodeWait  sync.WaitGroup
}

type DeviceFlowJson struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationUri         string `json:"verification_uri"`
	VerificationUriComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

func NewDeviceFlowAuth(cfg Config) *deviceFlow {
	a := new(deviceFlow)
	a.config = cfg
	a.deviceCodeWait.Add(1)
	return a
}

func WithCustomVerificationUri(verificationUri string) DeviceFlowAuthOption {
	return func(flow *deviceFlow) {
		flow.verificationUri = verificationUri
	}
}

func (a *deviceFlow) Authenticate(ctx context.Context) (token *oauth2.Token, err error) {
	return a.AuthenticateSession(ctx)
}

func (a *deviceFlow) UserInfo(ctx context.Context, token *oauth2.Token) (userInfo goa.UserInfo, err error) {
	return UserInfo(ctx, token, a.config)
}

func (a *deviceFlow) DeviceCode() <-chan string {
	ch := make(chan string)
	go func() {
		defer close(ch)
		a.deviceCodeWait.Wait()
		ch <- a.deviceCode
	}()
	return ch
}

func (a *deviceFlow) VerificationUri() <-chan string {
	ch := make(chan string)
	go func() {
		if a.verificationUri != "" {
			ch <- a.verificationUri
			close(ch)
		} else {
			<-a.DeviceCode()
			ch <- a.verificationUri
			close(ch)
		}
	}()

	return ch
}

func (a *deviceFlow) AuthenticateSession(ctx context.Context) (token *oauth2.Token, err error) {
	if a.config.Url == "" {
		return nil, fmt.Errorf("missing oidc config")
	}
	ch := make(chan *Session)
	defer close(ch)

	provider, err := oidc.NewProvider(ctx, a.config.Url)
	if err != nil {
		return nil, err
	}
	endpoint := provider.Endpoint()

	deviceAuthUrl := endpoint.DeviceAuthURL
	form := url.Values{}
	form.Add("client_id", a.config.ClientId)
	form.Add("client_secret", a.config.ClientSecret)
	resp, err := http.Post(deviceAuthUrl, "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var decodedResp DeviceFlowJson
	err = json.Unmarshal(body, &decodedResp)
	if err != nil {
		return nil, err
	}

	a.deviceCode = decodedResp.UserCode
	if a.verificationUri == "" {
		a.verificationUri = decodedResp.VerificationUri
	}
	a.deviceCodeWait.Done()

	oauth2Token, err := waitForToken(5*time.Second, endpoint, a.config.ClientId, a.config.ClientSecret, decodedResp.DeviceCode)
	if err != nil {
		return nil, err
	}

	return oauth2Token, nil
}

func waitForToken(interval time.Duration, endpoint oauth2.Endpoint, clientId, clientSecret, deviceCode string) (*oauth2.Token, error) {
	for {
		token, err := getToken(endpoint, clientId, clientSecret, deviceCode)
		authorizationPending := errors.Is(err, AuthorizationPendingErr)
		if authorizationPending {
			time.Sleep(interval)
			continue
		}
		return token, err
	}
}

func getToken(endpoint oauth2.Endpoint, clientId, clientSecret, deviceCode string) (*oauth2.Token, error) {
	tokenUrl := endpoint.TokenURL
	form := url.Values{}
	form.Add("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
	form.Add("requested_token_type", "urn:ietf:params:oauth:token-type:id_token")
	form.Add("client_id", clientId)
	form.Add("client_secret", clientSecret)
	form.Add("device_code", deviceCode)
	resp, err := http.Post(tokenUrl, "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var tokenErr TokenErrorJson
	err = json.Unmarshal(body, &tokenErr)
	if err != nil {
		return nil, err
	}
	if tokenErr.Error == "authorization_pending" {
		return nil, AuthorizationPendingErr
	}
	if tokenErr.Error != "" {
		return nil, fmt.Errorf(tokenErr.ErrorDescription)
	}

	var oauth2Token oauth2.Token
	err = json.Unmarshal(body, &oauth2Token)
	return &oauth2Token, err
}

type TokenErrorJson struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}
