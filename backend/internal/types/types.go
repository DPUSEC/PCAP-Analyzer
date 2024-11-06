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
