package config

import (
	"pcap-analyzer/constants"
	"pcap-analyzer/internal/types"
	"pcap-analyzer/internal/utils"
)

type Env struct {
	Debug              bool
	MaxFileSize        int
	ApiHost            string
	ApiPort            string
	ApiPrefix          string
	DBConnectionString string
	DBName             string
	Keywords           types.Keywords
}

func GetEnv() (e Env) {
	e.Debug = utils.GetBoolEnvWithDefault("DEBUG", true)                  // TODO(ahmet): Set this true while pushing to prod.
	e.MaxFileSize = utils.GetIntEnvWithDefault("MAX_FILE_SIZE", 20971520) // 20MB
	e.ApiHost = utils.GetEnvWithDefault("API_HOST", "http://127.0.0.1")
	e.ApiPort = utils.GetEnvWithDefault("API_PORT", "8000")
	e.ApiPrefix = utils.GetEnvWithDefault("API_PREFIX", "/api/v1")
	e.DBConnectionString = utils.GetEnvWithDefault("MONGODB_CONNECTION_STRING", "mongodb://127.0.0.1:27017/")
	e.DBName = utils.GetEnvWithDefault("MONGODB_DATABASE_NAME", "pcap-analyzer")
	e.Keywords = constants.Keywords

	return e
}
