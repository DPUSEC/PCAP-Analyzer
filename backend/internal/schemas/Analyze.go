package schemas

import (
	"time"
)

type InternalAlert struct {
	Action      string `bson:"action"`
	SignatureId int    `bson:"signature_id"`
	Signature   string `bson:"signature"`
	Category    string `bson:"category"`
	Severity    int    `bson:"severity"`
}

type InternalFlow struct {
	PktsToServer  int       `bson:"pkts_toserver"`
	PktsToClient  int       `bson:"pkts_toclient"`
	BytesToServer int       `bson:"bytes_toserver"`
	BytesToClient int       `bson:"bytes_toclient"`
	Start         time.Time `bson:"start"`
	SrcIp         string    `bson:"src_ip"`
	SrcPort       int       `bson:"src_port"`
	DestIp        string    `bson:"dest_ip"`
	DestPort      int       `bson:"dest_port"`
}

type Alert struct {
	Timestamp            time.Time     `bson:"timestamp"`
	EventType            string        `bson:"event_type"`
	FlowId               string        `bson:"flow_id"`
	Flow                 InternalFlow  `bson:"flow"`
	SrcIp                string        `bson:"src_ip"`
	SrcPort              int           `bson:"src_port"`
	DstIp                string        `bson:"dst_ip"`
	DstPort              int           `bson:"dst_port"`
	TransmissionProtocol string        `bson:"transmission_protocol"`
	PktSrc               string        `bson:"pkt_src"`
	TxId                 int           `bson:"tx_id"`
	TxGuessed            bool          `bson:"tx_guessed"`
	Alert                InternalAlert `bson:"alert"`
}

type ExportedFiles struct {
	FileName     string `bson:"file_name"`
	InternalPath string `bson:"internal_path"`
	DownloadLink string `bson:"download_link"`
}

// Analyze modeli
type Analyze struct {
	ID            string          `bson:"_id,omitempty"`
	FileName      string          `bson:"file_name"`
	PcapPath      string          `bson:"file_path"`
	UploadedAt    time.Time       `bson:"uploaded_at"`
	AnalyzedAt    time.Time       `bson:"analyzed_at"`
	UserID        string          `bson:"user_id"`
	Alerts        []Alert         `bson:"alerts"`
	ExportedFiles []ExportedFiles `bson:"exported_files"`
}
