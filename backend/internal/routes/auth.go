package routes

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"

	"pcap-analyzer/internal/types"
	"pcap-analyzer/internal/utils"
)

// @Summary		Login
// @Description	Login to the system
// @Tags			Auth
// @Accept			json
// @Produce		application/json
// @Param			body	body	api.Login.LoginRequest	true	"Login request"
// @Success		200	{object}	api.Login.Response	"Success"
// @Failure		400	{object}	types.FailResponse	"Invalid username or password"
// @Failure		500	{object}	types.FailResponse	"An error occurred, please try again later"
// @Router			/login [post]
func Login(c *gin.Context) {
	type Response struct {
		types.SuccessResponse
		Token string `json:"token" example:"ey......"`
	}

	type LoginRequest struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
	}

	// Check if already authenticated
	_, err := utils.ExtractBearerToken(c.GetHeader("Authorization"))
	if err == nil {
		slog.Error("Already authenticated", "error", err)
		c.JSON(http.StatusBadRequest, types.FailResponse{
			Code:    types.Fail,
			Message: "Already authenticated",
		})
		return
	}

	loginParams := LoginRequest{}
	c.ShouldBindJSON(&loginParams)

	// TODO(ahmet): Implement mongodb login mechanism here
	if loginParams.Username == "ahmet" || loginParams.Username == "ahmet1413" {
		token, err := utils.CreateJWTToken(loginParams.Username)
		if err != nil {
			c.JSON(http.StatusInternalServerError, types.FailResponse{
				Code:    types.Fail,
				Message: "An error occurred, please try again later",
			})
			return
		}

		r := Response{
			SuccessResponse: types.SuccessResponse{
				Code:    types.Success,
				Message: "Successfully logged in",
			},
			Token: token,
		}

		c.JSON(http.StatusOK, r)
		return
	}

	c.JSON(http.StatusBadRequest, types.FailResponse{
		Code:    types.Fail,
		Message: "Invalid username or password",
	})
}

// @Summary		Register
// @Description	Register to the system
// @Tags			Auth
// @Accept			json
// @Produce		application/json
// @Param			body	body	api.Register.RegisterRequest	true	"Register request"
// @Success		200	{object}	api.Register.Response	"Success"
// @Failure		400	{object}	types.FailResponse	"Already authenticated"
// @Failure		500	{object}	types.FailResponse	"An error occurred, please try again later"
// @Router			/register [post]
func Register(c *gin.Context) {
	type Response struct {
		types.SuccessResponse
		Token string `json:"token" example:"ey......"`
	}

	type RegisterRequest struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
	}

	// Check if already authenticated
	_, err := utils.ExtractBearerToken(c.GetHeader("Authorization"))
	if err == nil {
		slog.Error("Already authenticated", "error", err)
		c.JSON(http.StatusBadRequest, types.FailResponse{
			Code:    types.Fail,
			Message: "Already authenticated",
		})
		return
	}

	registerParams := RegisterRequest{}
	c.ShouldBindJSON(&registerParams)

	// TODO(ahmet): Implement mongodb register mechanism here
	username := registerParams.Username
	password := registerParams.Password

	fmt.Printf("Username: %s, Password: %s\n", username, password)

	token, err := utils.CreateJWTToken(username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, types.FailResponse{
			Code:    types.Fail,
			Message: "An error occurred, please try again later",
		})
		return
	}

	r := Response{
		SuccessResponse: types.SuccessResponse{
			Code:    types.Success,
			Message: "Successfully logged in",
		},
		Token: token,
	}

	c.JSON(http.StatusOK, r)
}
