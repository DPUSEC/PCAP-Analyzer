package schemas

import (
	"pcap-analyzer/internal/types"
)

// Analyze modeli
type Analyze struct {
	ID         string `bson:"_id,omitempty"`
	FileName   string `bson:"file_name"`
	FilePath   string `bson:"file_path"`
	UploadedAt string `bson:"uploaded_at"`
	AnalyzedAt string `bson:"analyzed_at"`
	UserID     string `bson:"user_id"`

	// Status: 0: Uploaded, 1: Analyzed, 2: Error
	Status                   int                         `bson:"status"`
	IpResponseResults        []types.ResponseStats       `bson:"ip_response_results"`
	IpRequestResults         []types.RequestStats        `bson:"ip_request_results"`
	PortStatResults          []types.PortStats           `bson:"port_stat_results"`
	PortScanDetectionResults []types.PortScanDetection   `bson:"port_scan_detection_results"`
	HttpReqResults           []types.HttpReq             `bson:"http_req_results"`
	HttpReqIPsResults        []types.HttpReqIPs          `bson:"http_req_ips_results"`
	CredentialsResults       []types.CredentialsInfo     `bson:"credentials_results"`
	FileTransferResults      []types.FileTransfer        `bson:"file_transfer_results"`
	RceResults               []types.RemoteCodeExecution `bson:"rce_results"`
	SqlInjectionResults      []types.SQLInjection        `bson:"sql_injection_results"`
	XssResults               []types.XSS                 `bson:"xss_results"`
	Log4ShellResults         []types.Log4Shell           `bson:"log4shell_results"`
}
