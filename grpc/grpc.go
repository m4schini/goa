package grpc

import (
	"context"
	"fmt"
	"github.com/m4schini/goa"
	"github.com/m4schini/goa/oidc"
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
	return oidc.Verify(tokens[0], verifier)
}

func AppendToken(ctx context.Context, token *oauth2.Token) context.Context {
	return metadata.AppendToOutgoingContext(ctx, "token", token.AccessToken)
}
