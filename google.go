package auth

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log"
	"net/http"
	"strings"

	jwt "github.com/dgrijalva/jwt-go"
)

const (
	GoogleCertURL             = "https://www.googleapis.com/oauth2/v1/certs"
	GoogleIssuerWithScheme    = "https://accounts.google.com"
	GoogleIssuerWithoutScheme = "accounts.google.com"
)

//GoogleJWTClaims is the google jwt claim
type GoogleJWTClaims struct {
	jwt.StandardClaims
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	FamilyName    string `json:"family_name"`
	GivenName     string `json:"given_name"`
	Locale        string `json:"locale"`
	DisplayName   string `json:"name"`
	Picture       string `json:"picture"`
}

//GoogleAuthenticator provides gin Middleware for validating google oauth2 token
type GoogleAuthenticator struct {
	clientID string
}

func (c *GoogleJWTClaims) GetEmail() string {
	return c.Email
}

func (c *GoogleJWTClaims) GetId() string {
	return c.Subject
}

func (c *GoogleJWTClaims) GetClaims() interface{} {
	return c
}

func (c *GoogleJWTClaims) GetIssuer() string {
	return IssuerGoogle
}

//GetClaims validates and gets the claims info from jwt
func (authenticator *GoogleAuthenticator) GetClaims(authorization string) (AuthenticationInfo, error) {
	jwtString := strings.Split(authorization, " ")[1]
	jwtParser := new(jwt.Parser)
	jwtParser.SkipClaimsValidation = true
	token, err := jwtParser.ParseWithClaims(jwtString, &GoogleJWTClaims{}, authenticator.getKey())
	if err != nil {
		return nil, err
	}

	claims := token.Claims.(*GoogleJWTClaims)
	ve := claims.validWithClientID(authenticator.clientID)

	return claims, ve
}

func (authenticator *GoogleAuthenticator) getKey() jwt.Keyfunc {
	return func(token *jwt.Token) (interface{}, error) {
		response, err := http.Get(GoogleCertURL)
		if err != nil {
			log.Fatal("Cannot get certificate from google: ", err)
			panic(err)
		}
		defer response.Body.Close()
		var certs map[string]string
		err = json.NewDecoder(response.Body).Decode(&certs)
		if err != nil {
			log.Fatal("Cannot decode certificate from google: ", err)
			panic(err)
		}
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, errors.New("key not found for google oauth")
		}
		raw, ok := certs[kid]
		if !ok {
			return nil, errors.New("key not found for google oauth")
		}
		block, _ := pem.Decode([]byte(raw))
		var cert *x509.Certificate
		cert, _ = x509.ParseCertificate(block.Bytes)
		rsaPublicKey := cert.PublicKey.(*rsa.PublicKey)
		return rsaPublicKey, nil

	}

}

func (c *GoogleJWTClaims) validWithClientID(aud string) error {
	err := c.valid()
	vErr := new(jwt.ValidationError)
	if err != nil {
		vErr = err.(*jwt.ValidationError)
	}
	if !c.StandardClaims.VerifyAudience(aud, true) {
		vErr.Inner = errors.New("wrong google clientId")
		vErr.Errors |= jwt.ValidationErrorAudience
	}
	if vErr.Errors == 0 {
		return nil
	}
	return vErr
}

func (c *GoogleJWTClaims) valid() error {
	err := c.StandardClaims.Valid()
	vErr := new(jwt.ValidationError)
	if err != nil {
		vErr = err.(*jwt.ValidationError)
	}

	if !c.StandardClaims.VerifyIssuer(GoogleIssuerWithoutScheme, true) && !c.StandardClaims.VerifyIssuer(GoogleIssuerWithScheme, true) {
		vErr.Inner = errors.New("not google issued token")
		vErr.Errors |= jwt.ValidationErrorIssuer
	}

	if vErr.Errors == 0 {
		return nil
	}

	return vErr
}
