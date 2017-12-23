# go-oauth-authenticator
Go OAuth authenticator

## Google OAuth authenticator

use `GoogleAuthenticator` to authenticate google oauth token.

`GoogleAuthenticator.AuthenticateMiddleware(clientID string)` is a gin middleware that validates the oauth token and sets claims in gin.Context

`GoogleAuthenticator.GetClaims(authorization string, clientID string)` validates and return parsed claims
