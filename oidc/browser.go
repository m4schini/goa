package oidc

import (
	"context"
	"fmt"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/m4schini/goa"
	"github.com/m4schini/goa/util"
	"golang.org/x/oauth2"
	"math/rand"
	"net"
	"net/http"
	"strings"
)

type BrowserFlowAuthOption func(flow *browserFlow)

type browserFlow struct {
	config Config
}

func NewBrowserFlowAuth(cfg Config, opts ...BrowserFlowAuthOption) *browserFlow {
	a := new(browserFlow)
	a.config = cfg

	for _, apply := range opts {
		apply(a)
	}

	return a
}

func (a *browserFlow) Authenticate(ctx context.Context) (token *oauth2.Token, err error) {
	s, err := a.AuthenticateSession(ctx)
	if err != nil {
		return nil, err
	}
	return s, nil
}

func (a *browserFlow) UserInfo(ctx context.Context, token *oauth2.Token) (userInfo goa.UserInfo, err error) {
	return UserInfo(ctx, token, a.config)
}

func (a *browserFlow) AuthenticateSession(ctx context.Context) (token *oauth2.Token, err error) {
	if a.config.Url == "" {
		return nil, fmt.Errorf("missing oidc config")
	}
	ch := make(chan *oauth2.Token)
	defer close(ch)

	l, err := net.ListenTCP("tcp", &net.TCPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: 0,
	})
	if err != nil {
		return nil, err
	}
	defer l.Close()

	mux, err := a.RegisterAuthHandler(ctx, ch, l)
	if err != nil {
		return nil, err
	}

	go func() {
		http.Serve(l, mux)
	}()
	err = util.TryOpen(fmt.Sprintf("http://%v/auth", l.Addr()))
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case s := <-ch:
		return s, nil
	}
}

func (a *browserFlow) RegisterAuthHandler(ctx context.Context, returnCh chan *oauth2.Token, listener *net.TCPListener) (*http.ServeMux, error) {
	if listener == nil {
		return nil, fmt.Errorf("invalid listener")
	}
	mux := http.NewServeMux()
	addr := listener.Addr().String()

	provider, err := oidc.NewProvider(ctx, a.config.Url)
	if err != nil {
		return nil, err
	}

	redirectURL := fmt.Sprintf("http://%v/auth/callback", addr)
	// Configure an OpenID Connect aware OAuth2 client.
	oauth2Config := oauth2.Config{
		ClientID:     a.config.ClientId,
		ClientSecret: a.config.ClientSecret,
		RedirectURL:  redirectURL,
		// Discovery returns the OAuth2 endpoints.
		Endpoint: provider.Endpoint(),
		// "openid" is a required scope for OpenID Connect flows.
		Scopes: []string{oidc.ScopeOpenID, "profile", "email"},
	}
	state := fmt.Sprintf("%v", rand.Int63())

	oidcConfig := &oidc.Config{
		ClientID: a.config.ClientId,
	}
	verifier := provider.Verifier(oidcConfig)

	mux.HandleFunc("/auth/", loginHandler(ctx, oauth2Config, verifier, state))
	mux.HandleFunc("/auth/callback/", callbackHandler(ctx, oauth2Config, state, returnCh))
	return mux, nil
}

func loginHandler(ctx context.Context, oauth2Config oauth2.Config, verifier *oidc.IDTokenVerifier, state string) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		rawAccessToken := r.Header.Get("Authorization")
		if rawAccessToken == "" {
			http.Redirect(w, r, oauth2Config.AuthCodeURL(state), http.StatusFound)
			return
		}

		parts := strings.Split(rawAccessToken, " ")
		if len(parts) != 2 {
			w.WriteHeader(400)
			return
		}
		_, err := verifier.Verify(ctx, parts[1])

		if err != nil {
			http.Redirect(w, r, oauth2Config.AuthCodeURL(state), http.StatusFound)
			return
		}

		w.Write([]byte("hello world"))
	}
}

func callbackHandler(ctx context.Context, oauth2Config oauth2.Config, state string, returnCh chan *oauth2.Token) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("state") != state {
			http.Error(w, "state did not match", http.StatusBadRequest)
			return
		}

		oauth2Token, err := oauth2Config.Exchange(ctx, r.URL.Query().Get("code"))
		if err != nil {
			http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
			return
		}

		returnCh <- oauth2Token
		w.Write([]byte(fmt.Sprintf("Hello. You can now close this window.")))
	}
}
