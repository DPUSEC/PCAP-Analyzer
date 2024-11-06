package types

const (
	Success                     = "Success"
	Fail                        = "Fail"
	ErrorIdenticalPriorityValue = "IdenticalPriorityValues"
)

type SuccessResponse struct {
	Code    string `json:"code" example:"Success"`
	Message string `json:"message"`
}

type FailResponse struct {
	Code    string `json:"code" example:"Fail"`
	Message string `json:"message"`
}

type ErrIdenticalPriorityValue struct {
	Code    string `json:"code" example:"IdenticalPriorityValues"`
	Message string `json:"message" example:"Identical priority values are not allowed"`
}
