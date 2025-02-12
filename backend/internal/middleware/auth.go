package middleware

import (
	"log/slog"
	"net/http"
	"pcap-analyzer/internal/types"
	"pcap-analyzer/internal/utils"

	"github.com/gin-gonic/gin"
)

func AuthenticateMiddleware(c *gin.Context) {
	// Get token from the authorization header
	tokenString, err := utils.ExtractBearerToken(c.GetHeader("Authorization"))
	if err != nil {
		slog.Error("Token not found", "error", err)
		c.JSON(http.StatusUnauthorized, types.FailResponse{
			Status:  types.Fail,
			Message: "Token not found.",
		})
		c.Abort()
		return
	}

	// Verify the token
	_, err = utils.VerifyToken(tokenString)
	if err != nil {
		slog.Error("Token verification failed", "error", err)
		c.JSON(http.StatusUnauthorized, types.FailResponse{
			Status:  types.Fail,
			Message: "Token verification failed.",
		})
		c.Abort()
		return
	}

	// TODO(ahmet): Token decode edildiği halde gerekli sectionlar var mı diye kontrol edilecek.

	// set token values to context
	claims := utils.ExtractClaims(tokenString)
	if claims == nil {
		slog.Error("Claims not found")
		c.JSON(http.StatusUnauthorized, types.FailResponse{
			Status:  types.Fail,
			Message: "Token verification failed.",
		})
		c.Abort()
		return
	}
	c.Set("user_id", claims["sub"].(string))

	c.Next()
}
