package api

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"

	"pcap-analyzer/config"
	"pcap-analyzer/constants"
	"pcap-analyzer/docs"
	"pcap-analyzer/internal/middleware"
	"pcap-analyzer/internal/routes"
	"pcap-analyzer/internal/types"
)

// Sample Code
// @Summary		Get version
// @Description	Get version of the service
// @Tags			Basics
// @Accept			plain
// @Produce		application/json
// @Success		200	{object}	api.Version.Response	"Success"
// @Router			/version [get]
func Version(c *gin.Context) {
	type Response struct {
		types.SuccessResponse
		Version string `json:"version" example:"v1.0.0"`
	}

	r := Response{
		SuccessResponse: types.SuccessResponse{
			Status:  types.Success,
			Message: "Successfully retrieved version",
		},
		Version: constants.Version,
	}

	c.JSON(http.StatusOK, r)
}

func StartApiServer() {
	slog.Info("Starting REST API server")

	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()

	prefix := config.GetEnv().ApiPrefix
	port := config.GetEnv().ApiPort

	docs.SwaggerInfo.BasePath = prefix
	docs.SwaggerInfo.Title = "Pcap Analyzer backend API"
	docs.SwaggerInfo.Description = "API for pcap analyzer services."
	docs.SwaggerInfo.Version = constants.Version
	docs.SwaggerInfo.Schemes = []string{"http"}
	r.GET("/docs/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	// CORS
	r.Use(cors.New(cors.Config{
		AllowOrigins: []string{"*"},
		AllowHeaders: []string{"Content-Type", "Content-Length", "Accept-Encoding", "X-CSRF-Token", "Authorization", "accept", "origin", "Cache-Control", "X-Requested-With"},
	}))

	// Endpoints
	r.GET(prefix+"/version", middleware.AuthenticateMiddleware, Version)
	r.POST(prefix+"/login", routes.Login)
	r.POST(prefix+"/register", routes.Register)

	err := r.Run(fmt.Sprintf(":%s", port))
	if err != nil {
		slog.Error("PCAP Analyzer API Server failed", "Error", err)
	}
}
