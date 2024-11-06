package main

import (
	"log/slog"
	"pcap-analyzer/internal/api"
	"pcap-analyzer/internal/utils"
)

func main() {
	utils.InitializeLogger()
	slog.Info("Starting backend service")

	api := api.NewApi()

	api.StartApiServer()
}
