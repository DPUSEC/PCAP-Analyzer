package utils

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"os"
	"os/exec"
	"pcap-analyzer/internal/types"
	"strings"
	"unicode"
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
func ExtractFilesUsingTshark(pcapFilePath, outputDir string, exportFiles []string) {
	// Cikti dizini yoksa olusturuluyor
	err := os.MkdirAll(outputDir, os.ModePerm)
	if err != nil {
		log.Fatalf("Cikti dizini olusturulurken hata olustu: %v", err)
	}
	for a := range exportFiles {
		// TShark komutunu olusturuyoruz: Protokol belirtmeden tum protokoller icin dosya cikar
		tsharkCmd := fmt.Sprintf("cd tshark && tshark -r %s --export-objects %s,%s", pcapFilePath, exportFiles[a], outputDir)

		// Windows'ta cmd komutunu calistiriyoruz
		cmd := exec.Command("cmd", "/C", tsharkCmd) // Windows icin cmd kullaniyoruz
		var out bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &out
		err = cmd.Run()
		if err != nil {
			log.Fatalf("TShark komutunu calistirirken hata olustu: %v\n%s", err, out.String())
		}

		// Ciktiyi kontrol et
		if out.Len() > 0 {
			fmt.Println("Disa aktarilan dosyalar:")
			fmt.Println(out.String())
		} else {
			fmt.Println("PCAP dosyasindan dosya cikarilamadi.")
		}
	}
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
