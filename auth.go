package auth

import (
	"github.com/gin-gonic/gin"
)

//Authenticator provides gin Middleware for jwt authentication
type authenticator interface {
	AuthenticateMiddleware(interface{}) gin.HandlerFunc
	GetClaims() (interface{}, error)
}

const jwtKey = "jwt_key"

//GetGoogleClaims gets the GoogleJWTClaims from gin.Context
func GetGoogleClaims(c *gin.Context) (*GoogleJWTClaims, bool) {
	claim, ok := c.Get(jwtKey)
	return claim.(*GoogleJWTClaims), ok
}
