package routes

import (
	"net/http"
	"os"
	"path/filepath"
	"pcap-analyzer/internal/database"
	"pcap-analyzer/internal/schemas"
	"pcap-analyzer/internal/types"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// CreateRule creates a new rule
// @Summary		Create a new rule
// @Description	Create a new rule
// @Tags			Rules
// @Accept			multipart/form-data
// @Produce		json
// @Security 	BearerAuth
// @param 		description formData string true "Description"
// @param 		rules_file formData file true "Rule file"
// @Success		200	{object} types.SuccessResponse	"Success"
// @Failure		502	{object} types.FailResponse	"Fail"
// @Router			/rules [post]
func CreateRule(c *gin.Context) {
	description, _ := c.GetPostForm("description")
	if description == "" {
		c.JSON(http.StatusBadGateway, types.FailResponse{
			Status:  types.Fail,
			Message: "Description is required",
		})
		return
	}

	description = filepath.Clean(description)

	file, _ := c.FormFile("rules_file")
	if file == nil {
		c.JSON(http.StatusBadGateway, types.FailResponse{
			Status:  types.Fail,
			Message: "Invalid file",
		})
		return
	}

	var userFolder string = "rules/" + c.GetString("user_id")
	if _, err := os.Stat(userFolder); os.IsNotExist(err) {
		os.Mkdir(userFolder, 0755)
	}

	filePath := userFolder + "/" + uuid.New().String() + ".rules"
	if err := c.SaveUploadedFile(file, filePath); err != nil {
		c.JSON(http.StatusInternalServerError, types.FailResponse{
			Status:  types.Fail,
			Message: "Failed to save file",
		})
		return
	}

	// save it to the database
	database.DB.SetCollection("rules")
	rule := schemas.Rules{
		Name:        file.Filename,
		Description: description,
		CreatorID:   c.GetString("user_id"),
		Path:        filePath,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	insertedRule, err := database.DB.InsertOne(rule)
	if err != nil {
		c.JSON(http.StatusInternalServerError, types.FailResponse{
			Status:  types.Fail,
			Message: "Failed to save rule",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"Status":  types.Success,
		"Message": "File uploaded successfully",
		"rule_id": insertedRule.InsertedID,
	})

}

// GetRules returns all rules
// @Summary		Get all rules
// @Description	Get all rules
// @Tags			Rules
// @Accept			json
// @Produce		json
// @Security 	BearerAuth
// @Success		200	{object} types.SuccessResponse	"Success"
// @Failure		502	{object} types.FailResponse	"Fail"
// @Router			/rules [get]
func GetRules(c *gin.Context) {
	type TempRules struct {
		ID          string    `bson:"_id,omitempty"`
		Name        string    `bson:"name"`
		Description string    `bson:"description"`
		CreatedAt   time.Time `bson:"created_at"`
		UpdatedAt   time.Time `bson:"updated_at"`
	}

	userId := c.GetString("user_id")

	database.DB.SetCollection("rules")
	rules := []TempRules{}
	err := database.DB.FindAll(bson.M{"creator_id": userId}, &rules)
	if err != nil {
		c.JSON(http.StatusInternalServerError, types.FailResponse{
			Status:  types.Fail,
			Message: "Failed to get rules",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"Status": types.Success,
		"Rules":  rules,
	})
}

// DeleteRule deletes a rule
// @Summary		Delete a rule
// @Description	Delete a rule
// @Tags			Rules
// @Accept			json
// @Produce		json
// @Security 	BearerAuth
// @param 		rule_id path string true "Rule ID"
// @Success		200	{object} types.SuccessResponse	"Success"
// @Failure		502	{object} types.FailResponse	"Fail"
// @Router			/rules/{rule_id} [delete]
func DeleteRule(c *gin.Context) {
	database.DB.SetCollection("rules")

	ruleId, err := primitive.ObjectIDFromHex(c.Param("rule_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, types.FailResponse{
			Status:  types.Fail,
			Message: "Invalid analyze ID",
		})
		return
	}

	rule := schemas.Rules{}
	err = database.DB.FindOne(bson.M{"_id": ruleId, "creator_id": c.GetString("user_id")}, &rule)
	if err != nil {
		c.JSON(http.StatusInternalServerError, types.FailResponse{
			Status:  types.Fail,
			Message: "Failed to get rule",
		})
		return
	}

	// delete the .rules file
	if err := os.Remove(rule.Path); err != nil {
		c.JSON(http.StatusInternalServerError, types.FailResponse{
			Status:  types.Fail,
			Message: "Failed to delete rule file",
		})
		return
	}

	deleteResults, err := database.DB.DeleteOne(bson.M{"_id": ruleId, "creator_id": c.GetString("user_id")})
	if err != nil {
		c.JSON(http.StatusInternalServerError, types.FailResponse{
			Status:  types.Fail,
			Message: "Failed to delete rule",
		})
		return
	}

	if deleteResults.DeletedCount == 0 {
		c.JSON(http.StatusNotFound, types.FailResponse{
			Status:  types.Fail,
			Message: "Rule not found",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"Status":  types.Success,
		"Message": "Rule deleted successfully",
	})
}
