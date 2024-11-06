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
	"pcap-analyzer/docs"
	"pcap-analyzer/internal/types"
)

type ApiModel interface {
	Version(c *gin.Context)
}

type Api struct{}

func NewApi() *Api {
	return &Api{}
}

// @Summary		Get version
// @Description	Get version of the service
// @Tags			Basics
// @Accept			plain
// @Produce		application/json
// @Success		200	{object}	api.Version.Response	"Success"
// @Router			/version [get]
func (a *Api) Version(c *gin.Context) {
	type Response struct {
		types.SuccessResponse
		Version string `json:"version" example:"v1.0.0"`
	}

	r := Response{
		SuccessResponse: types.SuccessResponse{
			Code:    types.Success,
			Message: "Successfully retrieved version",
		},
		Version: config.Version,
	}

	c.JSON(http.StatusOK, r)
}

func (a *Api) StartApiServer() {
	slog.Info("Starting REST API server")

	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()

	prefix := config.GetEnv().ApiPrefix
	port := config.GetEnv().ApiPort

	// Swagger 2.0 Meta Information
	docs.SwaggerInfo.BasePath = prefix
	docs.SwaggerInfo.Title = "Pcap Analyzer backend API"
	docs.SwaggerInfo.Description = "API for pcap analyzer services."
	docs.SwaggerInfo.Version = config.Version
	docs.SwaggerInfo.Schemes = []string{"http"}
	r.GET("/docs/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	// CORS Settings
	r.Use(cors.New(cors.Config{
		AllowOrigins: []string{"*"},
	}))

	// API endpoints
	r.GET(prefix+"/version", a.Version)

	err := r.Run(fmt.Sprintf(":%s", port))
	if err != nil {
		slog.Error("PCAP Analyzer API Server failed", "Error", err)
	}
}
