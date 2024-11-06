package utils

import (
	"os"
	"strconv"

	"log/slog"
)

func InitializeLogger() {

	level := slog.LevelInfo

	if os.Getenv("DEBUG") == "true" {
		level = slog.LevelDebug
	}

	logHandler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: level,
	})

	logger := slog.New(logHandler)
	slog.SetDefault(logger)

	slog.Debug("Logger initialized")

}

func GetEnvWithDefault(key string, defaultValue string) string {
	value := os.Getenv(key)

	if value == "" {
		value = defaultValue
	}

	return value
}

func GetBoolEnvWithDefault(key string, defaultValue bool) bool {
	value := os.Getenv(key)

	if value == "" {
		return defaultValue
	}

	if value == "true" {
		return true
	}

	return false
}

func GetIntEnvWithDefault(key string, defaultValue int) int {
	value := os.Getenv(key)

	if value == "" {
		return defaultValue
	}

	intValue, err := strconv.Atoi(value)

	if err != nil {
		slog.Error("Error parsing integer from environment variable", "Key", key)
		return defaultValue
	}

	return intValue
}
