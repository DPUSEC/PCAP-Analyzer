package utils

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"pcap-analyzer/internal/types"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func AnalyzePcap(filePath string, keywords types.Keywords, output *os.File) (types.PacketOutput, error) {
	ipRequests := make(map[string]int)
	ipResponses := make(map[string]int)
	communicationPorts := make(map[int]struct{})
	var fileTransferInfo []types.PacketInfo
	var credentialsInfo []types.PacketInfo
	packetCounter := 0

	handle, err := pcap.OpenOffline(filePath)
	if err != nil {
		slog.Error("Error occurred while opening pcap file.", "Error", err)
		handle.Close()
		return types.PacketOutput{}, err
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

		var srcPort, dstPort string
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		udpLayer := packet.Layer(layers.LayerTypeUDP)

		if tcpLayer != nil {
			if tcp, ok := tcpLayer.(*layers.TCP); ok {
				srcPort = fmt.Sprintf("%d", tcp.SrcPort)
				dstPort = fmt.Sprintf("%d", tcp.DstPort)
				communicationPorts[int(tcp.DstPort)] = struct{}{}
			}
		} else if udpLayer != nil {
			if udp, ok := udpLayer.(*layers.UDP); ok {
				srcPort = fmt.Sprintf("%d", udp.SrcPort)
				dstPort = fmt.Sprintf("%d", udp.DstPort)
				communicationPorts[int(udp.DstPort)] = struct{}{}
			}
		}

		appLayer := packet.ApplicationLayer()
		if appLayer == nil {
			continue
		}
		payload := string(appLayer.Payload())

		// Anahtar kelimeleri kontrol ederken küçük-büyük harf duyarsızlık
		for _, keyword := range keywords.AuthKeywords {
			if strings.Contains(strings.ToLower(payload), strings.ToLower(keyword)) {
				credentialsInfo = append(credentialsInfo, types.PacketInfo{
					SrcIP: srcIP, DstIP: dstIP,
					SrcPort: srcPort, DstPort: dstPort,
					PacketID: packetCounter, Payload: payload,
				})
				break
			}
		}

		// Dosya transferi anahtar kelimeleri kontrolü (küçük-büyük harf duyarsız)
		for _, keyword := range keywords.FileTransferKeywords {
			if strings.Contains(strings.ToLower(payload), strings.ToLower(keyword)) {
				fileName := generateFileName(payload) // Dosya adını içeriğe göre oluşturuyoruz
				fileTransferInfo = append(fileTransferInfo, types.PacketInfo{
					SrcIP: srcIP, DstIP: dstIP,
					SrcPort: srcPort, DstPort: dstPort,
					PacketID: packetCounter, Payload: payload, FileName: fileName,
				})
				break
			}
		}
	}

	return types.PacketOutput{
		IPRequests:         ipRequests,
		IPResponses:        ipResponses,
		CommunicationPorts: communicationPorts,
		CredentialsInfo:    credentialsInfo,
		FileTransferInfo:   fileTransferInfo,
	}, nil
}

// TODO(Baris): Burası daha sonra yazılacak.
func generateFileName(payload string) string {
	return "mocked.txt"
}

func LoadKeywords(filePath string) (types.Keywords, error) {
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
