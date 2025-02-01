package routes

import (
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"

	"pcap-analyzer/internal/database"
	"pcap-analyzer/internal/schemas"
	"pcap-analyzer/internal/types"
	"pcap-analyzer/internal/utils"
)

// @Summary		Login
// @Description	Login to the system
// @Tags			Auth
// @Accept			json
// @Produce		application/json
// @Param			body	body	types.LoginRequest	true	"Login request"
// @Success		200	{object}	types.LoginResponse	"Success"
// @Failure		400	{object}	types.FailResponse	"Invalid username or password"
// @Failure		500	{object}	types.FailResponse	"An error occurred, please try again later"
// @Router			/login [post]
func Login(c *gin.Context) {
	// Check if already authenticated
	_, err := utils.ExtractBearerToken(c.GetHeader("Authorization"))
	if err == nil {
		slog.Error("Already authenticated", "error", err)
		c.JSON(http.StatusBadRequest, types.FailResponse{
			Status:  types.Fail,
			Message: "Already authenticated",
		})
		return
	}

	loginParams := types.LoginRequest{}
	c.ShouldBindJSON(&loginParams)

	// Set collection
	database.DB.SetCollection("users")

	// Check if the user exists
	var user schemas.User
	err = database.DB.FindOne(bson.M{"username": loginParams.Username}, &user)
	if err != nil {
		c.JSON(http.StatusUnauthorized, types.FailResponse{
			Status:  types.Fail,
			Message: "Invalid username or password",
		})
		return
	}

	if !utils.ComparePassword(loginParams.Password, user.Password) {
		c.JSON(http.StatusUnauthorized, types.FailResponse{
			Status:  types.Fail,
			Message: "Invalid username or password",
		})
		return
	}

	token, err := utils.CreateJWTToken(user.ID)

	if err != nil {
		c.JSON(http.StatusInternalServerError, types.FailResponse{
			Status:  types.Fail,
			Message: "An error occurred, please try again later",
		})
		return
	}

	r := types.LoginResponse{
		SuccessResponse: types.SuccessResponse{
			Status:  types.Success,
			Message: "Successfully logged in",
		},
		Token: token,
	}

	c.JSON(http.StatusOK, r)
}

// @Summary		Register
// @Description	Register to the system
// @Tags			Auth
// @Accept			json
// @Produce		application/json
// @Param			body	body	types.RegisterRequest	true	"Register request"
// @Success		200	{object}	types.RegisterResponse	"Success"
// @Failure		400	{object}	types.FailResponse	"Already authenticated"
// @Failure		409	{object}	types.FailResponse	"User already exists"
// @Failure		500	{object}	types.FailResponse	"An error occurred, please try again later"
// @Router			/register [post]
func Register(c *gin.Context) {

	// Check if already authenticated
	_, err := utils.ExtractBearerToken(c.GetHeader("Authorization"))
	if err == nil {
		slog.Error("Already authenticated", "error", err)
		c.JSON(http.StatusBadRequest, types.FailResponse{
			Status:  types.Fail,
			Message: "Already authenticated",
		})
		return
	}

	registerParams := types.RegisterRequest{}
	c.ShouldBindJSON(&registerParams)

	// Check if the user already exists
	database.DB.SetCollection("users")

	var user schemas.User

	err = database.DB.FindOne(bson.M{"username": registerParams.Username}, &user)
	if err == nil {
		c.JSON(http.StatusConflict, types.FailResponse{
			Status:  types.Fail,
			Message: "User already exists",
		})
		return
	}

	// Insert the user
	newUser := schemas.User{
		Username: registerParams.Username,
		Password: utils.HashPassword(registerParams.Password),
	}
	insertResult, err := database.DB.InsertOne(newUser)
	if err != nil {
		c.JSON(http.StatusInternalServerError, types.FailResponse{
			Status:  types.Fail,
			Message: "An error occurred, please try again later",
		})
		return
	}
	slog.Debug("Inserted a user.", "user", insertResult.InsertedID)

	token, err := utils.CreateJWTToken(insertResult.InsertedID.(primitive.ObjectID).Hex())
	if err != nil {
		c.JSON(http.StatusInternalServerError, types.FailResponse{
			Status:  types.Fail,
			Message: "An error occurred, please try again later",
		})
		return
	}

	r := types.RegisterResponse{
		SuccessResponse: types.SuccessResponse{
			Status:  types.Success,
			Message: "Successfully registered user.",
		},
		Token: token,
	}

	c.JSON(http.StatusOK, r)
}
