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
	"github.com/gin-gonic/gin"
)

//GoogleJWTClaims is the google jwt claim
type GoogleJWTClaims struct {
	*jwt.StandardClaims
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	FamilyName    string `json:"family_name"`
	GivenName     string `json:"given_name"`
	Locale        string `json:"locale"`
	DisplayName   string `json:"name"`
	Picture       string `json:"picture"`
}

type googleCerts struct {
	Keys map[string]string
}

//GoogleAuthenticator provides gin Middleware for validating google oauth2 token
type GoogleAuthenticator struct {
}

//AuthenticateMiddleware is the gin Middleware for validating google oauth2 token
func (authenticator *GoogleAuthenticator) AuthenticateMiddleware(args interface{}) gin.HandlerFunc {
	return func(c *gin.Context) {
		authorization := c.GetHeader("Authorization")
		claims, ve := authenticator.GetClaims(authorization, args.(string))

		if ve == nil {
			c.Set(jwtKey, claims)
			c.Next()
		} else {
			c.AbortWithStatusJSON(401, gin.H{
				"error": ve.Error(),
			})
			return
		}

	}

}

//GetClaims validates and gets the claims info from jwt
func (authenticator *GoogleAuthenticator) GetClaims(authorization string, clientID string) (interface{}, error) {
	jwtString := strings.Split(authorization, " ")[1]
	jwtParser := new(jwt.Parser)
	jwtParser.SkipClaimsValidation = true
	token, err := jwtParser.ParseWithClaims(jwtString, &GoogleJWTClaims{}, authenticator.getKey())
	if err != nil {
		return nil, err
	}

	claims := token.Claims.(*GoogleJWTClaims)
	ve := claims.validWithClientID(clientID)
	return claims, ve
}

func (authenticator *GoogleAuthenticator) getKey() jwt.Keyfunc {
	return func(token *jwt.Token) (interface{}, error) {
		response, err := http.Get("https://www.googleapis.com/oauth2/v1/certs")
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

func (g *GoogleJWTClaims) validWithClientID(aud string) error {
	err := g.valid()
	vErr := new(jwt.ValidationError)
	if err != nil {
		vErr = err.(*jwt.ValidationError)
	}
	if !g.StandardClaims.VerifyAudience(aud, true) {
		vErr.Inner = errors.New("Wrong google clientId")
		vErr.Errors |= jwt.ValidationErrorAudience
	}
	if vErr.Errors == 0 {
		return nil
	}
	return vErr
}

func (g *GoogleJWTClaims) valid() error {
	err := g.StandardClaims.Valid()
	vErr := new(jwt.ValidationError)
	if err != nil {
		vErr = err.(*jwt.ValidationError)
	}

	if !g.StandardClaims.VerifyIssuer("accounts.google.com", true) && !g.StandardClaims.VerifyIssuer("https://accounts.google.com", true) {
		vErr.Inner = errors.New("Not google issued token")
		vErr.Errors |= jwt.ValidationErrorIssuer
	}

	if vErr.Errors == 0 {
		return nil
	}

	return vErr
}
