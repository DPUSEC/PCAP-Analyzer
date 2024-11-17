package constants

import (
	"pcap-analyzer/internal/types"
)

const Version = "v0.0.2"

var SecretKey = []byte("usmanim-nereye-gidersun-ebenin-korune-giderim-safiye")
var Keywords = types.Keywords{
	FileTransferKeywords: []string{"RETR"},
	AuthKeywords:         []string{"USER", "PASS"},
}
