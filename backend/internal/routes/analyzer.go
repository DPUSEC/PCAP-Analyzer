package routes

import (
	"fmt"
	"log"
	"log/slog"
	"math/rand"
	"net/http"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"pcap-analyzer/config"
	"pcap-analyzer/internal/database"
	"pcap-analyzer/internal/schemas"
	"pcap-analyzer/internal/types"
	"pcap-analyzer/internal/utils"
)

// @Summary		Analyze
// @Description	Analyze a pcap file
// @Tags		Analyzer
// @Accept		multipart/form-data
// @Produce		application/json
// @Param		file	formData	file	true	"PCAP file"
// @Security 	BearerAuth
// @param 		Authorization header string true "Authorization"
// @Success		200	{object}	types.SuccessResponse	"Success"
// @Failure		400	{object}	types.FailResponse	"Invalid file"
// @Failure		500	{object}	types.FailResponse	"An error occurred, please try again later"
// @Router		/analyze [post]
func Analyze(c *gin.Context) {
	// TODO(Baris): bu fonksiyon optimize edilecek
	keywords, err := utils.LoadKeywords(config.GetEnv().KeywordsFilePath)
	if err != nil {
		slog.Error("Failed to load keywords")
		c.JSON(http.StatusInternalServerError, types.FailResponse{
			Status:  types.Fail,
			Message: "An error occurred, please try again later",
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

	// WARN(ahmet): Prod'a alınırken uploads absolute path olarak ayarlanmalı.
	var filePath string = "./uploads/" + uploadedFileName
	c.SaveUploadedFile(file, filePath)

	var portScanThreshold int = 10          //port tarama eşik değeri
	var ipRequstThreshold int = 20          // ip istek eşik değeri
	var ipResponseThreshold int = 20        // ip yanıt eşik değeri
	var packetCounter int = 0               // Paket sayısı sayacı paket id için
	var fileTransferInfo []types.PacketInfo // Dosya transferi bilgileri için paket bilgileri listesi
	var credentialsInfo []types.PacketInfo  //	Kullanıcı kimlik bilgileri için paket bilgileri listesi
	var rce []types.PacketInfo              // Uyarı bilgileri için paket bilgileri listesi
	var sql_injection []types.PacketInfo    // SQL Injection bilgileri için paket bilgileri listesi
	var xss []types.PacketInfo              // XSS bilgileri için paket bilgileri listesi
	var log4shell []types.PacketInfo        // Log4Shell bilgileri için paket bilgileri listesi

	//Pcap dosyasını analiz etme fonksiyonu tamamı
	ipRequests := make(map[string]int)                     // IP requests
	ipResponses := make(map[string]int)                    // IP responses
	portScanDetection := make(map[string]map[int]struct{}) // Port scanning
	communicationPorts := make(map[int]struct{})           // communication ports
	portUsage := make(map[int]map[string]int)              // Port usage: "requests" and "responses"
	httpRequestsByIP := make(map[string][]string)          // Kaynak IP'lere göre HTTP isteklerini gruplandır

	handle, err := pcap.OpenOffline(filePath)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		packetCounter++
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer == nil {
			continue
		}
		ip, _ := ipLayer.(*layers.IPv4)
		srcIP := ip.SrcIP.String()
		dstIP := ip.DstIP.String()
		ipRequests[srcIP]++
		ipResponses[dstIP]++

		var srcPort, dstPort int
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		udpLayer := packet.Layer(layers.LayerTypeUDP)

		if tcpLayer != nil {
			if tcp, ok := tcpLayer.(*layers.TCP); ok {
				srcPort = int(tcp.SrcPort)
				dstPort = int(tcp.DstPort)
				communicationPorts[dstPort] = struct{}{}

				if _, exists := portUsage[srcPort]; !exists {
					portUsage[srcPort] = map[string]int{"requests": 0, "responses": 0}
				}
				portUsage[srcPort]["requests"]++

				if _, exists := portUsage[dstPort]; !exists {
					portUsage[dstPort] = map[string]int{"requests": 0, "responses": 0}
				}
				portUsage[dstPort]["responses"]++

				if _, exists := portScanDetection[srcIP]; !exists {
					portScanDetection[srcIP] = make(map[int]struct{})
				}
				portScanDetection[srcIP][dstPort] = struct{}{}
			}
		} else if udpLayer != nil {
			if udp, ok := udpLayer.(*layers.UDP); ok {
				srcPort = int(udp.SrcPort)
				dstPort = int(udp.DstPort)
				communicationPorts[dstPort] = struct{}{}

				if _, exists := portUsage[srcPort]; !exists {
					portUsage[srcPort] = map[string]int{"requests": 0, "responses": 0}
				}
				portUsage[srcPort]["requests"]++

				if _, exists := portUsage[dstPort]; !exists {
					portUsage[dstPort] = map[string]int{"requests": 0, "responses": 0}
				}
				portUsage[dstPort]["responses"]++
			}
		}

		appLayer := packet.ApplicationLayer()
		if appLayer == nil {
			continue
		}
		payload := string(appLayer.Payload())

		if strings.Contains(strings.ToUpper(payload), "POST") || strings.Contains(strings.ToUpper(payload), "GET") {
			lines := strings.Split(payload, "\r\n")
			if len(lines) > 0 {
				// HTTP isteğini gruplamak için kaynağa göre haritaya ekleyin
				httpRequestsByIP[srcIP] = append(httpRequestsByIP[srcIP], lines[0])
			}
		}
		// HTTP isteklerini IP ve path bazında gruplandır ve say
		httpReqCount := make(map[string]map[string]int)
		for ip, requests := range httpRequestsByIP {
			if _, exists := httpReqCount[ip]; !exists {
				httpReqCount[ip] = make(map[string]int)
			}
			for _, request := range requests {
				parts := strings.Fields(request)
				if len(parts) >= 2 {
					path := parts[1]
					httpReqCount[ip][path]++
				}
			}
		}
		for _, keyword := range keywords.AuthKeywords {
			if strings.Contains(strings.ToLower(payload), strings.ToLower(keyword)) {
				command, arg := utils.ExtractCommandAndArg(payload, keyword)
				credentialsInfo = append(credentialsInfo, types.PacketInfo{
					SrcIP: srcIP, DstIP: dstIP,
					SrcPort: srcPort, DstPort: dstPort,
					PacketID: packetCounter, Command: command, Arg: arg,
				})
				break
			}
		}
		for _, keyword := range keywords.RCE {
			if strings.Contains(strings.ToLower(payload), strings.ToLower(keyword)) {
				command, arg := utils.ExtractCommandAndArg(payload, keyword)
				rce = append(rce, types.PacketInfo{
					SrcIP: srcIP, DstIP: dstIP,
					SrcPort: srcPort, DstPort: dstPort,
					PacketID: packetCounter, Command: command, Arg: arg, MatchedKeyword: keyword,
				})
				break
			}
		}
		for _, keyword := range keywords.SQLInjection {
			if strings.Contains(strings.ToLower(payload), strings.ToLower(keyword)) {
				command, arg := utils.ExtractCommandAndArg(payload, keyword)
				sql_injection = append(sql_injection, types.PacketInfo{
					SrcIP: srcIP, DstIP: dstIP,
					SrcPort: srcPort, DstPort: dstPort,
					PacketID: packetCounter, Command: command, Arg: arg, MatchedKeyword: keyword,
				})
				break
			}
		}
		for _, keyword := range keywords.XSS {
			if strings.Contains(strings.ToLower(payload), strings.ToLower(keyword)) {
				command, arg := utils.ExtractCommandAndArg(payload, keyword)
				xss = append(xss, types.PacketInfo{
					SrcIP: srcIP, DstIP: dstIP,
					SrcPort: srcPort, DstPort: dstPort,
					PacketID: packetCounter, Command: command, Arg: arg, MatchedKeyword: keyword,
				})
				break
			}
		}

		for _, keyword := range keywords.FileTransferKeywords {
			if strings.Contains(strings.ToLower(payload), strings.ToLower(keyword)) {
				command, arg := utils.ExtractCommandAndArg(payload, keyword)
				fileName := utils.GenerateFileName(payload)
				fileTransferInfo = append(fileTransferInfo, types.PacketInfo{
					SrcIP: srcIP, DstIP: dstIP,
					SrcPort: srcPort, DstPort: dstPort,
					PacketID: packetCounter, Command: command, Arg: arg, FileName: fileName,
				})
				break
			}
		}

		for _, keyword := range keywords.LOG4SHELL {
			if strings.Contains(strings.ToLower(payload), strings.ToLower(keyword)) {
				command, arg := utils.ExtractCommandAndArg(payload, keyword)
				log4shell = append(log4shell, types.PacketInfo{SrcIP: srcIP, DstIP: dstIP, SrcPort: srcPort, DstPort: dstPort, PacketID: packetCounter, Command: command, Arg: arg, MatchedKeyword: keyword})
				break
			}
		}
	}

	// HTTP isteklerini IP ve path bazında gruplandır ve say
	httpReqCount := make(map[string]map[string]int)
	pathTotal := make(map[string]int)

	for ip, requests := range httpRequestsByIP {
		if _, exists := httpReqCount[ip]; !exists {
			httpReqCount[ip] = make(map[string]int)
		}

		for _, request := range requests {
			parts := strings.Fields(request)
			if len(parts) >= 2 {
				path := parts[1]

				// Check if the path contains only printable characters
				if utils.IsPrintable(path) {
					httpReqCount[ip][path]++
				}
			}
		}
	}
	for ip, paths := range httpReqCount {
		if len(paths) == 0 {
			delete(httpReqCount, ip)
		}
		for path, count := range paths {
			pathTotal[path] += count
		}
	}

	// Sort IP requests by count in descending order
	type ipStats struct {
		IP    string
		Count int
	}

	var ipRequestSlice []ipStats
	for ip, count := range ipRequests {
		ipRequestSlice = append(ipRequestSlice, ipStats{IP: ip, Count: count})
	}
	sort.Slice(ipRequestSlice, func(i, j int) bool {
		return ipRequestSlice[i].Count > ipRequestSlice[j].Count
	})

	var ipResponseSlice []ipStats
	for ip, count := range ipResponses {
		ipResponseSlice = append(ipResponseSlice, ipStats{IP: ip, Count: count})
	}
	sort.Slice(ipResponseSlice, func(i, j int) bool {
		return ipResponseSlice[i].Count > ipResponseSlice[j].Count
	})

	var (
		ipResponseArray        []types.ResponseStats
		ipRequestArray         []types.RequestStats
		portStatsArray         []types.PortStats
		portScanDetectionArray []types.PortScanDetection
		httpReqArray           []types.HttpReq
		httpReqIPsArray        []types.HttpReqIPs
		credentialsArray       []types.CredentialsInfo
		fileTransferArray      []types.FileTransfer
		rceArray               []types.RemoteCodeExecution
		sqlInjectionArray      []types.SQLInjection
		xssArray               []types.XSS
		log4shellArray         []types.Log4Shell
	)

	// IP Yanıt Sayıları
	if len(ipResponseSlice) != 0 {
		for _, stats := range ipResponseSlice {
			if stats.Count >= ipResponseThreshold {
				ipResponseArray = append(ipResponseArray, types.ResponseStats{IP: stats.IP, Count: stats.Count})
			}
		}
	}

	// IP İstek Sayıları
	if len(ipRequestSlice) != 0 {
		for _, stats := range ipRequestSlice {
			if stats.Count >= ipRequstThreshold {
				ipRequestArray = append(ipRequestArray, types.RequestStats{IP: stats.IP, Count: stats.Count})
			}
		}
	}

	type portStats struct {
		Port      int
		Requests  int
		Responses int
	}
	var portStatsSlice []portStats
	for port, usage := range portUsage {
		portStatsSlice = append(portStatsSlice, portStats{
			Port:      port,
			Requests:  usage["requests"],
			Responses: usage["responses"],
		})
	}
	// Port Kullanım İstatistikleri
	if len(portStatsSlice) != 0 {
		for _, stats := range portStatsSlice {
			if stats.Requests >= 10 {
				portStatsArray = append(portStatsArray, types.PortStats{Port: stats.Port, Requests: stats.Requests, Responses: stats.Responses})
			}
		}
	}

	// Port Tarama Tespiti
	if len(portScanDetection) != 0 {
		for ip, ports := range portScanDetection {
			if len(ports) > portScanThreshold {
				portScanDetectionArray = append(portScanDetectionArray, types.PortScanDetection{IP: ip, Ports: len(ports)})
			}
		}
	}

	// HTTP İstekleri
	if len(httpReqCount) != 0 {
		for ip, paths := range httpReqCount {
			httpReqIPsArray = append(httpReqIPsArray, types.HttpReqIPs{SourceIP: ip, TotalRequestCount: ipRequests[ip]})
			for path, count := range paths {
				httpReqArray = append(httpReqArray, types.HttpReq{Path: path, RequestCount: count})
			}
		}
	}

	// Credentials
	if len(credentialsInfo) > 0 {
		for _, info := range credentialsInfo {
			if utils.IsPrintable(info.Arg) && utils.IsPrintable(info.Command) {
				credentialsArray = append(credentialsArray, types.CredentialsInfo{PacketID: info.PacketID, Source: info.SrcIP, Destination: info.DstIP, Command: info.Command, Arg: info.Arg})
			}
		}
	}

	// Dosya Transferleri
	if len(fileTransferInfo) > 0 {
		for _, info := range fileTransferInfo {
			if utils.IsPrintable(info.Arg) && utils.IsPrintable(info.FileName) && utils.IsPrintable(info.Command) {
				fileTransferArray = append(fileTransferArray, types.FileTransfer{PacketID: info.PacketID, Source: info.SrcIP, Dest: info.DstIP, Command: info.Command, Arg: info.Arg, FileName: info.FileName})
			}
		}
	}

	// RCE
	if len(rce) != 0 {
		for _, info := range rce {
			if utils.IsPrintable(info.Arg) && utils.IsPrintable(info.Command) {
				rceArray = append(rceArray, types.RemoteCodeExecution{PacketID: info.PacketID, Source: info.SrcIP, Destination: info.DstIP, Command: info.Command, Arg: info.Arg})
			}
		}
	}

	// SQL Injection
	if len(sql_injection) != 0 {
		for _, info := range sql_injection {
			if utils.IsPrintable(info.Arg) {
				sqlInjectionArray = append(sqlInjectionArray, types.SQLInjection{PacketID: info.PacketID, Source: info.SrcIP, Destination: info.DstIP, Command: info.Command, Arg: info.Arg, MatchedKeyword: info.MatchedKeyword})
			}
		}
	}

	// XSS
	if len(xss) != 0 {
		for _, info := range xss {
			if utils.IsPrintable(info.Arg) {
				xssArray = append(xssArray, types.XSS{PacketID: info.PacketID, Source: info.SrcIP, Destination: info.DstIP, Command: info.Command, Arg: info.Arg})
			}
		}
	}

	if len(log4shell) != 0 {
		for _, info := range log4shell {
			if utils.IsPrintable(info.Arg) {
				log4shellArray = append(log4shellArray, types.Log4Shell{PacketID: info.PacketID, Source: info.SrcIP, Destination: info.DstIP, Arg: info.Arg, MatchedKeyword: info.MatchedKeyword})
			}
		}
	}

	// Save results to mongodb
	// TODO(ahmet): Analiz ve upload tarihleri farklı olabilir, sonra ilgilenilecek.
	database.DB.SetCollection("analysis")

	newAnalysis := schemas.Analyze{
		FileName:                 uploadedFileName,
		FilePath:                 filePath,
		UploadedAt:               time.Now().String(),
		AnalyzedAt:               time.Now().String(),
		Status:                   1,
		IpResponseResults:        ipResponseArray,
		IpRequestResults:         ipRequestArray,
		PortStatResults:          portStatsArray,
		PortScanDetectionResults: portScanDetectionArray,
		HttpReqResults:           httpReqArray,
		HttpReqIPsResults:        httpReqIPsArray,
		CredentialsResults:       credentialsArray,
		FileTransferResults:      fileTransferArray,
		RceResults:               rceArray,
		SqlInjectionResults:      sqlInjectionArray,
		XssResults:               xssArray,
		Log4ShellResults:         log4shellArray,
	}
	insertResult, err := database.DB.InsertOne(newAnalysis)
	if err != nil {
		c.JSON(http.StatusInternalServerError, types.FailResponse{
			Status:  types.Fail,
			Message: "An error occurred, please try again later",
		})
		return
	}
	slog.Debug("Inserted an analysis.", "analysis", insertResult.InsertedID)

	c.JSON(http.StatusOK, gin.H{
		"Status":  types.Success,
		"Message": "Successfully analyzed the pcap file",
		"Results": gin.H{
			"IpResponse":        ipResponseArray,
			"IpRequest":         ipRequestArray,
			"PortStats":         portStatsArray,
			"PortScanDetection": portScanDetectionArray,
			"HttpRequests":      httpReqArray,
			"HttpRequestsByIP":  httpReqIPsArray,
			"Credentials":       credentialsArray,
			"FileTransfer":      fileTransferArray,
			"RCE":               rceArray,
			"SQLInjection":      sqlInjectionArray,
			"XSS":               xssArray,
			"Log4Shell":         log4shellArray,
		},
	})
}
