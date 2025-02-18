package utils

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"os"
	"os/exec"
	"pcap-analyzer/internal/database"
	"pcap-analyzer/internal/schemas"
	"pcap-analyzer/internal/types"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/bson"
)

func IsPrintable(s string) bool { //Print edilebilir karakterler için kontrol fonksiyonu
	for _, r := range s {
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

func GenerateFileName(payload string) string {
	rand := fmt.Sprintf("%x", rand.Int63())
	return "file-" + rand + ".txt"
}

func ExtractCommandAndArg(payload string, keyword string) (string, string) { //Komut ve argümanları ayıklama fonksiyonu
	lines := strings.Split(payload, "\r\n")
	for _, line := range lines {
		if strings.Contains(strings.ToLower(line), strings.ToLower(keyword)) {
			parts := strings.Fields(line)
			if len(parts) > 1 {
				return parts[0], parts[1]
			}
			return parts[0], ""
		}
	}
	return "", ""
}

// extractFilesUsingTshark, TShark komutunu kullanarak PCAP dosyasındaki tum protokoller uzerinden dosya cikarir
func ExtractFilesUsingTshark(pcapFilePath, outputDir string) (exportedFileList []schemas.ExportedFiles) {
	// Cikti dizini yoksa olusturuluyor
	err := os.MkdirAll(outputDir, os.ModePerm)
	if err != nil {
		slog.Error("Cikti dizini olusturulurken hata olustu.")
	}
	tsharkProtocols := []string{"dicom", "ftp-data", "http", "imf", "smb", "tftp"}
	for a := range tsharkProtocols {
		// TShark komutunu olusturuyoruz: Protokol belirtmeden tum protokoller icin dosya cikar
		tsharkCmd := fmt.Sprintf("tshark -r %s --export-objects %s,%s", pcapFilePath, tsharkProtocols[a], outputDir)

		cmd := exec.Command("sh", "-c", tsharkCmd)
		var out bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &out
		cmd.Run()
	}

	// Get exported file list
	exportedFiles, err := os.ReadDir(outputDir)
	if err != nil {
		slog.Error("Cikti dizininde dosya listesi alinirken hata olustu.")
	}
	for _, file := range exportedFiles {
		// Rename files to random UUID's
		newFileName := GenerateFileNameWithExtension(file.Name())
		err := os.Rename(outputDir+"/"+file.Name(), outputDir+"/"+newFileName)
		if err != nil {
			slog.Error("Dosya adi degistirilirken hata olustu.")
		}
		var temp schemas.ExportedFiles
		temp.FileName = newFileName
		temp.InternalPath = outputDir + "/" + newFileName
		exportedFileList = append(exportedFileList, temp)
	}
	return exportedFileList
}

func GenerateFileNameWithExtension(fileName string) string {
	temp := strings.Split(fileName, ".")
	return uuid.New().String() + "." + temp[len(temp)-1]
}

func GetPortList(ports map[int]struct{}) []int {
	var portList []int
	for port := range ports {
		portList = append(portList, port)
	}
	return portList
}

func LoadKeywords(filePath string) (types.Keywords, error) { //Anahtar kelimeleri yükleme fonksiyonu
	var keywords types.Keywords

	jsonFile, err := os.Open(filePath)
	if err != nil {
		return keywords, err
	}
	defer jsonFile.Close()

	byteValue, _ := io.ReadAll(jsonFile)
	if err := json.Unmarshal(byteValue, &keywords); err != nil {
		return keywords, err
	}

	return keywords, nil
}

func ReadSuricataLogs(eveJsonPath string) []string {
	var logs []string

	eveJsonFile := eveJsonPath + "/eve.json"
	file, err := os.Open(eveJsonFile)
	if err != nil {
		slog.Error("Failed to open eve.json file")
		return logs
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		logs = append(logs, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		slog.Error("Error reading eve.json file")
		return logs
	}

	return logs
}

func getStringValue(v interface{}) string {
	switch val := v.(type) {
	case string:
		return val
	case float64:
		return fmt.Sprintf("%.0f", val)
	default:
		return fmt.Sprintf("%v", val)
	}
}

func getIntValue(v interface{}) int {
	switch val := v.(type) {
	case int:
		return val
	case float64:
		return int(val)
	default:
		return 0
	}
}

func getBoolValue(v interface{}) bool {
	switch val := v.(type) {
	case bool:
		return val
	default:
		return false
	}
}

func CreateDefaultRules() bool {
	database.DB.SetCollection("rules")

	defaultRules := []schemas.Rules{}
	err := database.DB.FindAll(bson.M{"creator_id": "67aca2522c035f56a31b0d5c"}, &defaultRules)
	if err != nil {
		return false
	}
	if len(defaultRules) != 9 {
		for _ = range defaultRules {
			_, err := database.DB.DeleteOne(bson.M{"creator_id": "67aca2522c035f56a31b0d5c"})
			if err != nil {
				return false
			}
		}
	} else {
		return true
	}
	_, err = database.DB.InsertOne(schemas.Rules{
		Name:        "Abuse.ch SSL Blacklist - DEFAULT",
		Description: "The SSL Blacklist (SSLBL) is a project of abuse.ch with the goal of detecting malicious SSL connections, by identifying and blacklisting SSL certificates used by botnet C&C servers. In addition, SSLBL identifies JA3 fingerprints that helps you to detect & block malware botnet C&C communication on the TCP layer. ",
		CreatorID:   "67aca2522c035f56a31b0d5c",
		Path:        "rules/67aca2522c035f56a31b0d5c/sslblacklist_tls_cert.rules",
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	})
	_, err = database.DB.InsertOne(schemas.Rules{
		Name:        "Abuse.ch URLhaus Suricata Rules - DEFAULT",
		Description: "URLhaus is a project from abuse.ch with the goal of sharing malicious URLs that are being used for malware distribution.",
		CreatorID:   "67aca2522c035f56a31b0d5c",
		Path:        "rules/67aca2522c035f56a31b0d5c/urlhaus_suricata.rules",
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	})
	_, err = database.DB.InsertOne(schemas.Rules{
		Name:        "Commodity malware rules for URL - DEFAULT",
		Description: "TCP/UDP, DNS and HTTP Windows threats artifacts observed at runtime.",
		CreatorID:   "67aca2522c035f56a31b0d5c",
		Path:        "rules/67aca2522c035f56a31b0d5c/malsilo-url.rules",
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	})
	_, err = database.DB.InsertOne(schemas.Rules{
		Name:        "Commodity malware rules for IP - DEFAULT",
		Description: "TCP/UDP, DNS and HTTP Windows threats artifacts observed at runtime.",
		CreatorID:   "67aca2522c035f56a31b0d5c",
		Path:        "rules/67aca2522c035f56a31b0d5c/malsilo-ip.rules",
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	})
	_, err = database.DB.InsertOne(schemas.Rules{
		Name:        "Commodity malware rules for DNS - DEFAULT",
		Description: "TCP/UDP, DNS and HTTP Windows threats artifacts observed at runtime.",
		CreatorID:   "67aca2522c035f56a31b0d5c",
		Path:        "rules/67aca2522c035f56a31b0d5c/malsilo-dns.rules",
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	})
	_, err = database.DB.InsertOne(schemas.Rules{
		Name:        "Positive Technologies Attack Detection Team ruleset - DEFAULT",
		Description: "The Attack Detection Team searches for new vulnerabilities and 0-days, reproduces it and creates PoC exploits to understand how these security flaws work and how related attacks can be detected on the network layer. Additionally, we are interested in malware and hackers' TTPs, so we develop Suricata rules for detecting all sorts of such activities.",
		CreatorID:   "67aca2522c035f56a31b0d5c",
		Path:        "rules/67aca2522c035f56a31b0d5c/pt-rules.rules",
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	})
	_, err = database.DB.InsertOne(schemas.Rules{
		Name:        "Emerging Threats (ET) Open - DEFAULT",
		Description: "It is a free and community-supported ruleset. Actively updated",
		CreatorID:   "67aca2522c035f56a31b0d5c",
		Path:        "rules/67aca2522c035f56a31b0d5c/emerging-all.rules",
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	})
	_, err = database.DB.InsertOne(schemas.Rules{
		Name:        "Abuse.ch Suricata JA3 Fingerprint Ruleset - DEFAULT",
		Description: "If you are running Suricata, you can use the SSLBL's Suricata JA3 fingerprint ruleset to detect and/or block malicious SSL connections in your network based on the JA3 fingerprint. Please note that your need Suricata 4.1.0 or newer in order to use the JA3 fingerprint ruleset.",
		CreatorID:   "67aca2522c035f56a31b0d5c",
		Path:        "rules/67aca2522c035f56a31b0d5c/ja3_fingerprints.rules",
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	})
	_, err = database.DB.InsertOne(schemas.Rules{
		Name:        "Suricata Default Rules - DEFAULT",
		Description: "A set of default rules for Suricata",
		CreatorID:   "67aca2522c035f56a31b0d5c",
		Path:        "rules/67aca2522c035f56a31b0d5c/suricata-defaults.rules",
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	})
	// Diğer rule'lar buraya gelecek.
	return err == nil
}

func GetAlertsFromSuricataLogs(logs []string) (alertlist []schemas.Alert) {

	var alerts []schemas.Alert

	for i := 0; i < len(logs); i++ {
		var tempAlert map[string]interface{}
		err := json.Unmarshal([]byte(logs[i]), &tempAlert)
		if err != nil {
			slog.Error("Failed to parse alert JSON", "error", err)
			continue
		}

		if eventType := tempAlert["event_type"]; eventType == "alert" {
			timestampStr := tempAlert["timestamp"].(string)
			parsedTime, err := time.Parse("2006-01-02T15:04:05.999999-0700", timestampStr)
			if err != nil {
				slog.Error("Timestamp parse error", "error", err)
				continue
			}

			alerts = append(alerts, schemas.Alert{
				Timestamp:            parsedTime,
				EventType:            "alert",
				FlowId:               getStringValue(tempAlert["flow_id"]),
				TransmissionProtocol: getStringValue(tempAlert["proto"]),
				Flow: schemas.InternalFlow{
					PktsToServer:  getIntValue(tempAlert["flow"].(map[string]interface{})["pkts_toserver"]),
					PktsToClient:  getIntValue(tempAlert["flow"].(map[string]interface{})["pkts_toclient"]),
					BytesToServer: getIntValue(tempAlert["flow"].(map[string]interface{})["bytes_toserver"]),
					BytesToClient: getIntValue(tempAlert["flow"].(map[string]interface{})["bytes_toclient"]),
					Start:         parsedTime,
					SrcIp:         getStringValue(tempAlert["flow"].(map[string]interface{})["src_ip"]),
					SrcPort:       getIntValue(tempAlert["flow"].(map[string]interface{})["src_port"]),
					DestIp:        getStringValue(tempAlert["flow"].(map[string]interface{})["dest_ip"]),
					DestPort:      getIntValue(tempAlert["flow"].(map[string]interface{})["dest_port"]),
				},
				SrcIp:     getStringValue(tempAlert["src_ip"]),
				SrcPort:   getIntValue(tempAlert["src_port"]),
				DstIp:     getStringValue(tempAlert["dest_ip"]),
				DstPort:   getIntValue(tempAlert["dest_port"]),
				PktSrc:    getStringValue(tempAlert["pkt_src"]),
				TxId:      getIntValue(tempAlert["tx_id"]),
				TxGuessed: getBoolValue(tempAlert["tx_guessed"]),
				Alert: schemas.InternalAlert{
					Action:      getStringValue(tempAlert["alert"].(map[string]interface{})["action"]),
					SignatureId: getIntValue(tempAlert["alert"].(map[string]interface{})["signature_id"]),
					Signature:   getStringValue(tempAlert["alert"].(map[string]interface{})["signature"]),
					Category:    getStringValue(tempAlert["alert"].(map[string]interface{})["category"]),
					Severity:    getIntValue(tempAlert["alert"].(map[string]interface{})["severity"]),
				},
			})
		}
	}

	return alerts
}
