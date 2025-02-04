package routes

import (
	"encoding/json"
	"fmt"
	"log"
	"log/slog"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/gopacket/pcap"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"

	"pcap-analyzer/config"
	"pcap-analyzer/internal/database"
	"pcap-analyzer/internal/schemas"
	"pcap-analyzer/internal/types"
	"pcap-analyzer/internal/utils"
)

// @Summary     Get analysis
// @Description Get analysis
// @Tags        Analyzer
// @Accept      json
// @Produce     application/json
// @Security    BearerAuth
// @Param       Authorization header string true "Authorization header with Bearer token"
// @Success     200 {object} types.SuccessResponse "Success"
// @Failure     404 {object} types.FailResponse "Analysis not found"
// @Failure     500 {object} types.FailResponse "An error occurred, please try again later"
// @Router      /analysis [get]
func GetAnalysis(c *gin.Context) {
	database.DB.SetCollection("analysis")

	type AnalysisResponse struct {
		ID         string    `bson:"_id"`
		FileName   string    `bson:"file_name"`
		PcapPath   string    `bson:"file_path"`
		UploadedAt time.Time `bson:"uploaded_at"`
		AnalyzedAt time.Time `bson:"analyzed_at"`
	}

	var analysis []AnalysisResponse
	// Select only id, filename, filepath, uploadedat, analyzedat, fields
	err := database.DB.FindWithProjection(bson.M{"user_id": c.GetString("user_id")}, bson.M{
		"_id":         1,
		"file_name":   1,
		"file_path":   1,
		"uploaded_at": 1,
		"analyzed_at": 1,
	}, &analysis)
	if err != nil {
		slog.Error("Failed to get analysis", "error", err)
		c.JSON(http.StatusInternalServerError, types.FailResponse{
			Status:  types.Fail,
			Message: "An error occurred, please try again later",
		})
		return
	}

	if analysis == nil {
		c.JSON(http.StatusNotFound, types.FailResponse{
			Status:  types.Fail,
			Message: "Analysis not found",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"Status":   types.Success,
		"Analysis": analysis,
	})
}

// @Summary     Get analysis by ID
// @Description Get analysis by ID
// @Tags        Analyzer
// @Accept      json
// @Produce     application/json
// @Param       id path string true "Analysis ID"
// @Security    BearerAuth
// @Param       Authorization header string true "Authorization header with Bearer token"
// @Param	    category query string false "Category"
// @Success     200 {object} types.SuccessResponse "Success"
// @Failure     400 {object} types.FailResponse "Invalid analyze ID"
// @Failure     404 {object} types.FailResponse "Analysis not found"
// @Failure     500 {object} types.FailResponse "An error occurred, please try again later"
// @Router      /analysis/{id} [get]
func GetAnalysisByID(c *gin.Context) {
	database.DB.SetCollection("analysis")

	analyzeId, err := primitive.ObjectIDFromHex(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, types.FailResponse{
			Status:  types.Fail,
			Message: "Invalid analyze ID",
		})
		return
	}

	var analysis schemas.Analyze
	err = database.DB.FindOne(bson.M{"_id": analyzeId, "user_id": c.GetString("user_id")}, &analysis)
	if err != nil {
		c.JSON(http.StatusNotFound, types.FailResponse{
			Status:  types.Fail,
			Message: "Analysis not found",
		})
		return
	}

	if analysis.ID == "" {
		c.JSON(http.StatusNotFound, types.FailResponse{
			Status:  types.Fail,
			Message: "Analysis not found",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"Status":   types.Success,
		"Analysis": analysis,
	})
}

// @Summary		Download analysis
// @Description	Download analysis
// @Tags		Analyzer
// @Accept		application/octet-stream
// @Produce		application/octet-stream
// @Security 	BearerAuth
// @Param		Authorization header string true "Bearer token for authorization"
// @Param		id path string true "Analysis ID"
// @Success		200	{object}	types.SuccessResponse	"Success"
// @Failure		400	{object}	types.FailResponse	"Invalid analyze ID"
// @Failure		404	{object}	types.FailResponse	"Analysis not found"
// @Router		/analysis/{id}/download [get]
func DownloadAnalysis(c *gin.Context) {
	database.DB.SetCollection("analysis")

	analyzeId, err := primitive.ObjectIDFromHex(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, types.FailResponse{
			Status:  types.Fail,
			Message: "Invalid analyze ID",
		})
		return
	}

	var analysis schemas.Analyze
	err = database.DB.FindOne(bson.M{"_id": analyzeId, "user_id": c.GetString("user_id")}, &analysis)
	if err != nil {
		c.JSON(http.StatusNotFound, types.FailResponse{
			Status:  types.Fail,
			Message: "Analysis not found",
		})
		return
	}

	if analysis.ID == "" {
		c.JSON(http.StatusNotFound, types.FailResponse{
			Status:  types.Fail,
			Message: "Analysis not found",
		})
		return
	}

	c.Header("Content-Disposition", "attachment; filename="+analysis.FileName)
	c.Header("Content-Type", "application/octet-stream")
	c.File("uploads/" + c.GetString("user_id") + "/" + analysis.FileName)
}

// @Summary		Get exported files
// @Description	Get exported files
// @Tags		Analyzer
// @Accept		application/json
// @Produce		application/json
// @Security 	BearerAuth
// @Param		Authorization header string true "Bearer token for authorization"
// @Param		id path string true "Analysis ID"
// @Success		200	{object}	types.SuccessResponse	"Success"
// @Failure		400	{object}	types.FailResponse	"Invalid analyze ID"
// @Failure		404	{object}	types.FailResponse	"Analysis not found"
// @Router		/analysis/{id}/files [get]
func GetExportedFiles(c *gin.Context) {
	database.DB.SetCollection("analysis")

	analyzeId, err := primitive.ObjectIDFromHex(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, types.FailResponse{
			Status:  types.Fail,
			Message: "Invalid analyze ID",
		})
		return
	}

	var analysis schemas.Analyze
	err = database.DB.FindOne(bson.M{"_id": analyzeId, "user_id": c.GetString("user_id")}, &analysis)
	if err != nil {
		c.JSON(http.StatusNotFound, types.FailResponse{
			Status:  types.Fail,
			Message: "Analysis not found",
		})
		return
	}

	if analysis.ID == "" || len(analysis.ExportedFiles) == 0 {
		c.JSON(http.StatusNotFound, types.FailResponse{
			Status:  types.Fail,
			Message: "Analysis not found",
		})
		return
	}

	var exportedFileUrls []string
	for _, file := range analysis.ExportedFiles {
		exportedFileUrls = append(exportedFileUrls, config.GetEnv().ApiPrefix+"/analysis/"+analyzeId.Hex()+"/files/"+file+"/download")
	}

	// TODO(ahmet): Daha sonrasında doysanın meta bilgisini de döndürebiliriz,
	// şimdilik sadece indirme URL'lerini ve isimlerini döndürüyoruz.
	c.JSON(http.StatusOK, gin.H{
		"Status":           types.Success,
		"ExportedFileUrls": exportedFileUrls,
		"ExportedFiles":    analysis.ExportedFiles,
	})
}

// @Summary		Download exported file
// @Description	Download exported file
// @Tags		Analyzer
// @Accept		application/octet-stream
// @Produce		application/octet-stream
// @Security 	BearerAuth
// @Param		Authorization header string true "Bearer token for authorization"
// @Param		id path string true "Analysis ID"
// @Param		file path string true "File name"
// @Success		200	{object}	types.SuccessResponse	"Success"
// @Failure		400	{object}	types.FailResponse	"Invalid analyze ID"
// @Failure		404	{object}	types.FailResponse	"Analysis not found"
// @Router		/analysis/{id}/files/{file}/download [get]
func DownloadExportedFile(c *gin.Context) {
	database.DB.SetCollection("analysis")

	analyzeId, err := primitive.ObjectIDFromHex(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, types.FailResponse{
			Status:  types.Fail,
			Message: "Invalid analyze ID",
		})
		return
	}

	var analysis schemas.Analyze
	err = database.DB.FindOne(bson.M{"_id": analyzeId, "user_id": c.GetString("user_id")}, &analysis)
	if err != nil {
		c.JSON(http.StatusNotFound, types.FailResponse{
			Status:  types.Fail,
			Message: "Analysis not found",
		})
		return
	}

	if analysis.ID == "" {
		c.JSON(http.StatusNotFound, types.FailResponse{
			Status:  types.Fail,
			Message: "Analysis not found",
		})
		return
	}

	fileName := c.Param("file")
	if fileName == "" {
		c.JSON(http.StatusBadRequest, types.FailResponse{
			Status:  types.Fail,
			Message: "Invalid file",
		})
		return
	}

	c.Header("Content-Disposition", "attachment; filename="+fileName)
	c.Header("Content-Type", "application/octet-stream")
	c.File("uploads/" + c.GetString("user_id") + "/" + analysis.FileName + "_files/" + fileName)
}

// @Summary		Delete analysis
// @Description	Delete analysis
// @Tags		Analyzer
// @Accept		application/json
// @Produce		application/json
// @Security 	BearerAuth
// @Param		Authorization header string true "Bearer token for authorization"
// @Param		id path string true "Analysis ID"
// @Success		200	{object}	types.SuccessResponse	"Success"
// @Failure		400	{object}	types.FailResponse	"Invalid analyze ID"
// @Failure		404	{object}	types.FailResponse	"Analysis not found"
// @Failure		500	{object}	types.FailResponse	"An error occurred, please try again later"
// @Router		/analysis/{id} [delete]
func DeleteAnalysis(c *gin.Context) {
	database.DB.SetCollection("analysis")

	analyzeId, err := primitive.ObjectIDFromHex(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, types.FailResponse{
			Status:  types.Fail,
			Message: "Invalid analyze ID",
		})
		return
	}

	var analysis schemas.Analyze
	err = database.DB.FindOne(bson.M{"_id": analyzeId, "user_id": c.GetString("user_id")}, &analysis)
	if err != nil {
		c.JSON(http.StatusNotFound, types.FailResponse{
			Status:  types.Fail,
			Message: "Analysis not found",
		})
		return
	}

	if analysis.ID == "" {
		c.JSON(http.StatusNotFound, types.FailResponse{
			Status:  types.Fail,
			Message: "Analysis not found",
		})
		return
	}
	os.Remove("uploads/" + c.GetString("user_id") + "/" + analysis.FileName)
	os.RemoveAll("uploads/" + c.GetString("user_id") + "/" + analysis.FileName + "_files")

	deleteResults, err := database.DB.DeleteOne(bson.M{"_id": analyzeId, "user_id": c.GetString("user_id")})
	if err != nil {
		c.JSON(http.StatusInternalServerError, types.FailResponse{
			Status:  types.Fail,
			Message: "An error occurred, please try again later",
		})
		return
	}

	if deleteResults.DeletedCount == 0 {
		c.JSON(http.StatusNotFound, types.FailResponse{
			Status:  types.Fail,
			Message: "Analysis not found",
		})
		return
	}

	c.JSON(http.StatusOK, types.SuccessResponse{
		Status:  types.Success,
		Message: "Successfully deleted the analysis",
	})
}

// @Summary		Analyze with Suricata
// @Description	Analyze with Suricata
// @Tags		Analyzer
// @Accept		application/json
// @Produce		application/json
// @Security 	BearerAuth
// @Param		Authorization header string true "Bearer token for authorization"
// @Param		id path string true "Analysis ID"
// @Success		200	{object}	types.SuccessResponse	"Success"
// @Failure		400	{object}	types.FailResponse	"Invalid analyze ID"
// @Failure		404	{object}	types.FailResponse	"Analysis not found"
// @Router		/analysis/{id} [post]
func SuricataAnalysis(c *gin.Context) {
	// Form-data'dan rules alanını al
	rulesJson := c.PostForm("rules")
	if rulesJson == "" {
		c.JSON(http.StatusBadRequest, types.FailResponse{
			Status:  types.Fail,
			Message: "Rules parametresi bulunamadı",
		})
		return
	}

	// JSON yapısını tanımla
	var temp_ruleIds []string

	// JSON'ı parse et
	if err := json.Unmarshal([]byte(rulesJson), &temp_ruleIds); err != nil {
		c.JSON(http.StatusBadRequest, types.FailResponse{
			Status:  types.Fail,
			Message: "Geçersiz rules formatı",
		})
		return
	}

	var ruleIds []primitive.ObjectID
	for _, ruleId := range temp_ruleIds {
		objectID, err := primitive.ObjectIDFromHex(ruleId)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"status":  "fail",
				"message": "Invalid rule ID: " + ruleId,
			})
			return
		}
		ruleIds = append(ruleIds, objectID)
	}

	// get paths with rule ids from database
	database.DB.SetCollection("rules")

	var rules []schemas.Rules
	err := database.DB.FindAll(bson.M{"_id": bson.M{"$in": ruleIds}, "creator_id": c.GetString("user_id")}, &rules)
	if err != nil {
		c.JSON(http.StatusInternalServerError, types.FailResponse{
			Status:  types.Fail,
			Message: "An error occurred, please try again later",
		})
		return
	}

	if len(rules) == 0 {
		c.JSON(http.StatusNotFound, types.FailResponse{
			Status:  types.Fail,
			Message: "Rules not found",
		})
		return
	}

	file, _ := c.FormFile("file")

	if file == nil {
		c.JSON(http.StatusBadGateway, types.FailResponse{
			Status:  types.Fail,
			Message: "Invalid file",
		})
		return
	}

	var uploadedFileName string = fmt.Sprintf("%d_%s", rand.Int63(), file.Filename)
	uploadedFileName = url.QueryEscape(uploadedFileName)
	uploadedFileName = filepath.Clean(uploadedFileName)

	var userFolder string = "uploads/" + c.GetString("user_id")
	if _, err := os.Stat(userFolder); os.IsNotExist(err) {
		os.Mkdir(userFolder, 0755)
	}
	var exportFolder string = userFolder + "/extracted_files"
	if _, err := os.Stat(exportFolder); os.IsNotExist(err) {
		os.Mkdir(userFolder, 0755)
	}

	c.SaveUploadedFile(file, userFolder+"/"+uploadedFileName)
	uploadedTime := time.Now()

	handle, err := pcap.OpenOffline(userFolder + "/" + uploadedFileName)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Extract files
	outputExportFolder := userFolder + "/" + uploadedFileName + "_files"
	if _, err := os.Stat(outputExportFolder); os.IsNotExist(err) {
		os.Mkdir(userFolder, 0755)
	}
	exportedFiles := utils.ExtractFilesUsingTshark(userFolder+"/"+uploadedFileName, outputExportFolder)

	outputDir := userFolder + "/" + uploadedFileName + "_suricata"
	if _, err := os.Stat(outputDir); os.IsNotExist(err) {
		os.Mkdir(outputDir, 0755)
	}

	for _, rule := range rules {
		suricataCmd := exec.Command("suricata", "-r", userFolder+"/"+uploadedFileName, "-S", rule.Path, "-l", outputDir)
		suricataCmd.Stdout = os.Stdout
		suricataCmd.Stderr = os.Stderr

		err = suricataCmd.Run()
		if err != nil {
			slog.Error("Suricata çalıştırılırken bir hata oluştu.")
			c.JSON(http.StatusInternalServerError, types.FailResponse{
				Status:  types.Fail,
				Message: "An error occurred, please try again later",
			})
			return
		}
	}

	// Read suricata logs
	suricataLogs := utils.ReadSuricataLogs(outputDir)
	alerts := utils.GetAlertsFromSuricataLogs(suricataLogs)

	// Save results to mongodb
	database.DB.SetCollection("analysis")

	newAnalysis := schemas.Analyze{
		FileName:      uploadedFileName,
		UserID:        c.GetString("user_id"),
		UploadedAt:    uploadedTime,
		AnalyzedAt:    time.Now(),
		Alerts:        alerts,
		ExportedFiles: exportedFiles,
	}

	insertResult, err := database.DB.InsertOne(newAnalysis)
	if err != nil {
		c.JSON(http.StatusInternalServerError, types.FailResponse{
			Status:  types.Fail,
			Message: "An error occurred, please try again later",
		})
		return
	}

	var exportedFileUrls []string
	for _, file := range exportedFiles {
		exportedFileUrls = append(exportedFileUrls, config.GetEnv().ApiPrefix+"/analysis/"+insertResult.InsertedID.(primitive.ObjectID).Hex()+"/files/"+file+"/download")
	}

	uploadedFilePath := config.GetEnv().ApiPrefix + "/analysis/" + insertResult.InsertedID.(primitive.ObjectID).Hex() + "/download"
	_, err = database.DB.UpdateOne(bson.M{"_id": insertResult.InsertedID}, bson.M{"$set": bson.M{"file_path": uploadedFilePath, "exported_files": exportedFiles}})
	if err != nil {
		c.JSON(http.StatusInternalServerError, types.FailResponse{
			Status:  types.Fail,
			Message: "An error occurred, please try again later",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"Status":           types.Success,
		"Message":          "Successfully analyzed the pcap file",
		"ResultId":         insertResult.InsertedID,
		"ResultDetailsUrl": config.GetEnv().ApiPrefix + "/analysis/" + insertResult.InsertedID.(primitive.ObjectID).Hex(),
		"PcapPath":         uploadedFilePath,
		"ExportedFileUrls": exportedFileUrls,
		"ExportedFiles":    exportedFiles,
		"Alerts":           alerts,
	})
}
