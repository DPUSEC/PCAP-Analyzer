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

type PacketInfo struct {
	SrcIP    string
	DstIP    string
	SrcPort  string
	DstPort  string
	PacketID int
	Payload  string
	FileName string
}

type PacketOutput struct {
	IPRequests         map[string]int
	IPResponses        map[string]int
	CommunicationPorts map[int]struct{}
	FileTransferInfo   []PacketInfo
	CredentialsInfo    []PacketInfo
}

type Keywords struct {
	FileTransferKeywords []string `json:"file_transfer_keywords"`
	AuthKeywords         []string `json:"auth_keywords"`
}
