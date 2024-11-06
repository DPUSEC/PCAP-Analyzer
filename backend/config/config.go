package config

import (
	"pcap-analyzer/internal/utils"
)

const Version = "v0.0.1"

type Env struct {
	Debug       bool
	MaxFileSize int
	ApiHost     string
	ApiPort     string
	ApiPrefix   string
}

func GetEnv() (e Env) {
	e.Debug = utils.GetBoolEnvWithDefault("DEBUG", true)                  // TODO(ahmet): Set this true while pushing to prod.
	e.MaxFileSize = utils.GetIntEnvWithDefault("MAX_FILE_SIZE", 20971520) // 20MB
	e.ApiHost = utils.GetEnvWithDefault("API_HOST", "http://127.0.0.1")
	e.ApiPort = utils.GetEnvWithDefault("API_PORT", "8000")
	e.ApiPrefix = utils.GetEnvWithDefault("API_PREFIX", "/api/v1")

	return e
}
