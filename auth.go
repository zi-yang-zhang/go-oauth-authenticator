package auth

import (
	"strings"

	"errors"

	jwt "github.com/dgrijalva/jwt-go"
)

const (
	IssuerGoogle = "google"
)

//AuthenticationInfo provides access to parsed JWT token
type AuthenticationInfo interface {
	GetEmail() string
	GetId() string
	GetClaims() interface{}
	GetIssuer() string
}

//Authenticator parses and return AuthenticationInfo contains parsed info
type Authenticator interface {
	GetClaims(authorization string) (AuthenticationInfo, error)
}

//AuthenticationProvider holds mapping of Authenticators
type AuthenticationProvider struct {
	Authenticators map[string]Authenticator
	AuthParams     map[string]interface{}
}

//New creates new AuthenticationProvider with default providers
func New(authParams map[string]interface{}) *AuthenticationProvider {
	google := &GoogleAuthenticator{clientID: authParams[IssuerGoogle].(string)}
	provider := &AuthenticationProvider{
		Authenticators: map[string]Authenticator{
			GoogleIssuerWithScheme:    google,
			GoogleIssuerWithoutScheme: google,
		},
		AuthParams: authParams,
	}
	return provider
}

//Authenticate authenticates JWT using Authenticator selected based on iss in the claims
func (provider *AuthenticationProvider) Authenticate(authorization string) (AuthenticationInfo, error) {
	authorizationHeader := strings.Split(authorization, " ")
	if len(authorizationHeader) < 2 {
		return nil, errors.New("JWT malformed")
	}
	jwtString := authorizationHeader[1]
	jwtParser := new(jwt.Parser)
	jwtParser.SkipClaimsValidation = true
	token, err := jwtParser.Parse(jwtString, nil)

	if err.(*jwt.ValidationError).Errors == jwt.ValidationErrorUnverifiable {
		claims := token.Claims.(jwt.MapClaims)
		authenticator, ok := provider.Authenticators[claims["iss"].(string)]
		if !ok {
			return nil, errors.New("cannot find supported Authenticator")
		}
		return authenticator.GetClaims(authorization)

	} else {
		return nil, err
	}

}
