package main

import (
	"context"
	"log/slog"
	"pcap-analyzer/config"
	"pcap-analyzer/internal/api"
	db "pcap-analyzer/internal/database"
	"pcap-analyzer/internal/utils"
	"time"
)

func main() {
	utils.InitializeLogger()
	slog.Info("Starting backend service...")

	// Connect to MongoDB
	err := db.ConnectToMongoDB(config.GetEnv().DBConnectionString, config.GetEnv().DBName)
	if err != nil {
		slog.Error("MongoDB connection error.", "error", err)
		return
	}

	_, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	api.StartApiServer()
}
