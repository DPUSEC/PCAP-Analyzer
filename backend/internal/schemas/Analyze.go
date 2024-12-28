package schemas

import (
	"pcap-analyzer/internal/types"
	"time"
)

// Analyze modeli
type Analyze struct {
	ID         string    `bson:"_id,omitempty"`
	FileName   string    `bson:"file_name"`
	FilePath   string    `bson:"file_path"`
	UploadedAt time.Time `bson:"uploaded_at"`
	AnalyzedAt time.Time `bson:"analyzed_at"`
	UserID     string    `bson:"user_id"`

	// Status: 0: Uploaded, 1: Analyzed, 2: Error
	Status                   int                          `bson:"status"`
	IpResponseResults        []types.ResponseStats        `bson:"ip_response_results"`
	IpRequestResults         []types.RequestStats         `bson:"ip_request_results"`
	PortStatResults          []types.PortStats            `bson:"port_stat_results"`
	PortScanDetectionResults []types.PortScanDetection    `bson:"port_scan_detection_results"`
	HttpReqResults           []types.HttpReq              `bson:"http_req_results"`
	HttpReqIPsResults        []types.HttpReqIPs           `bson:"http_req_ips_results"`
	CredentialsResults       []types.GeneralCaptureStruct `bson:"credentials_results"`
	FileTransferResults      []types.GeneralCaptureStruct `bson:"file_transfer_results"`
	RceResults               []types.GeneralCaptureStruct `bson:"rce_results"`
	SqlInjectionResults      []types.GeneralCaptureStruct `bson:"sql_injection_results"`
	XssResults               []types.GeneralCaptureStruct `bson:"xss_results"`
	Log4ShellResults         []types.GeneralCaptureStruct `bson:"log4shell_results"`
}
