package types

const (
	Success = true
	Fail    = false
)

type SuccessResponse struct {
	Status  bool   `json:"status" example:"true"`
	Message string `json:"message"`
}

type FailResponse struct {
	Status  bool   `json:"status" example:"false"`
	Message string `json:"message"`
}

type Env struct {
	Debug              bool
	MaxFileSize        int
	ApiHost            string
	ApiPort            string
	ApiPrefix          string
	DBConnectionString string
	DBName             string
	KeywordsFilePath   string
}

type Keywords struct { //Anahtar kelimeler için yapı
	FileTransferKeywords []string `json:"file_transfer_keywords"`
	AuthKeywords         []string `json:"auth_keywords"`
	RCE                  []string `json:"rce"`
	SQLInjection         []string `json:"sql_injection"`
	XSS                  []string `json:"xss"`
	LOG4SHELL            []string `json:"log4shell"`
}

type PacketInfo struct { //Paket bilgileri için yapı
	SrcIP          string //Kaynak IP
	DstIP          string //Hedef IP
	SrcPort        int    //Kaynak Port
	DstPort        int    //Hedef Port
	PacketID       int    //Paket ID
	Command        string //Komut
	Arg            string //Argüman
	FileName       string //Dosya adı
	Length         int    //Paket boyutu
	MatchedKeyword string //Eşleşen anahtar kelime xss, sql injection, rce için
}

type IPStats struct {
	IP    string `json:"ip"`
	Count int    `json:"count"`
}

type PortUsage struct {
	Port      int `json:"port"`
	Requests  int `json:"requests"`
	Responses int `json:"responses"`
}

type DetectionInfo struct {
	PacketID       int    `json:"packet_id"`
	SrcIP          string `json:"src_ip"`
	SrcPort        int    `json:"src_port"`
	DstIP          string `json:"dst_ip"`
	DstPort        int    `json:"dst_port"`
	MatchedKeyword string `json:"matched_keyword,omitempty"`
	Command        string `json:"command,omitempty"`
	Arg            string `json:"arg,omitempty"`
}

type HttpReq struct {
	Path         string
	RequestCount int
}
type HttpReqIPs struct {
	SourceIP          string
	TotalRequestCount int
}

type GeneralCaptureStruct struct {
	PacketID       int
	SrcIP          string
	SrcPort        int
	DstIP          string
	DstPort        int
	Command        string
	Arg            string
	FileName       any
	MatchedKeyword any
}

type ResponseStats struct {
	IP    string
	Count int
}

type RequestStats struct {
	IP    string
	Count int
}

type PortStats struct {
	Port      int
	Requests  int
	Responses int
}

type PortScanDetection struct {
	IP    string
	Ports int
}
