package types

type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type LoginResponse struct {
	SuccessResponse
	Token string `json:"token" example:"ey......"`
}

type RegisterResponse struct {
	SuccessResponse
	Token string `json:"token" example:"ey......"`
}

type RegisterRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}
