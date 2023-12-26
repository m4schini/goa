package cobra

import (
	"github.com/m4schini/goa"
	"github.com/spf13/cobra"
	"golang.org/x/oauth2"
)

func CmdAuthE(token *oauth2.Token, authenticator goa.Authenticator) func(cmd *cobra.Command, args []string) (err error) {
	return func(cmd *cobra.Command, args []string) (err error) {
		ctx := cmd.Context()
		t, err := authenticator.Authenticate(ctx)
		if err != nil {
			return err
		}
		*token = *t
		return nil
	}
}

func CmdUserE(userInfo *goa.UserInfo, token *oauth2.Token, verifier goa.Verifier, authenticator goa.Authenticator) func(cmd *cobra.Command, args []string) (err error) {
	return func(cmd *cobra.Command, args []string) (err error) {
		err = CmdAuthE(token, authenticator)(cmd, args)
		if err != nil {
			return err
		}
		ctx := cmd.Context()
		user, err := verifier.UserInfo(ctx, token)
		if err != nil {
			return err
		}
		*userInfo = user
		return nil
	}
}
