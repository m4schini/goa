package grpc

import (
	"context"
	"fmt"
	"github.com/m4schini/goa"
	"golang.org/x/oauth2"
	"google.golang.org/grpc/metadata"
)

func VerifyContext(ctx context.Context, verifier goa.Verifier) (info goa.UserInfo, err error) {
	md, exists := metadata.FromIncomingContext(ctx)
	if !exists {
		return nil, fmt.Errorf("metadata is missing")
	}
	tokens := md.Get("token")
	if len(tokens) != 1 {
		return nil, fmt.Errorf("token is missing")
	}
	token := &oauth2.Token{
		AccessToken: tokens[0],
		TokenType:   "Bearer",
	}

	// returns err of unauthorized
	return verifier.UserInfo(ctx, token)
}
