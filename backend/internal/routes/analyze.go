package routes

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"pcap-analyzer/config"
	"pcap-analyzer/internal/types"
	"pcap-analyzer/internal/utils"

	"github.com/gin-gonic/gin"
)

// @Summary		Analyze pcap file
// @Description	Analyze pcap file
// @Tags			Analyze
// @Accept			multipart/form-data
// @Produce		application/json
// @Param			file	formData	file	true	"PCAP file"
// @Success		200	{object}	types.PacketOutput	"Success"
// @Failure		400	{object}	types.FailResponse	"Invalid file"
// @Failure		500	{object}	types.FailResponse	"An error occurred, please try again later"
// @Router			/analyze [post]
func Analyze(c *gin.Context) {
	file, err := c.FormFile("file")
	if err != nil {
		slog.Error("Error occurred while getting file", "Error", err)
		c.JSON(http.StatusBadRequest, types.FailResponse{
			Status:  types.Fail,
			Message: "Invalid file",
		})
		return
	}

	filePath := "uploads/" + file.Filename
	fmt.Println(filePath)
	if err := c.SaveUploadedFile(file, filePath); err != nil {
		slog.Error("Error occurred while saving file", "Error", err)
		c.JSON(http.StatusInternalServerError, types.FailResponse{
			Status:  types.Fail,
			Message: "An error occurred, please try again later",
		})
		return
	}

	outputFile, err := os.Create("output.txt")
	if err != nil {
		slog.Error("Error occurred while creating output file", "Error", err)
		c.JSON(http.StatusInternalServerError, types.FailResponse{
			Status:  types.Fail,
			Message: "An error occurred, please try again later",
		})
		return
	}
	defer outputFile.Close()

	packetOutput, err := utils.AnalyzePcap(filePath, config.GetEnv().Keywords, outputFile)
	fmt.Println(packetOutput)
	if err != nil {
		slog.Error("Error occurred while analyzing pcap file", "Error", err)
		c.JSON(http.StatusInternalServerError, types.FailResponse{
			Status:  types.Fail,
			Message: "An error occurred, please try again later",
		})
		return
	}

	c.JSON(http.StatusOK, packetOutput)
}
