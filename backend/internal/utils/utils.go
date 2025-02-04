package utils

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"log/slog"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"

	"pcap-analyzer/constants"
)

func InitializeLogger() {
	level := slog.LevelInfo

	if os.Getenv("DEBUG") == "true" {
		level = slog.LevelDebug
	}

	logHandler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: level,
	})

	logger := slog.New(logHandler)
	slog.SetDefault(logger)

	slog.Debug("Logger initialized")

}

func GetEnvWithDefault(key string, defaultValue string) string {
	value := os.Getenv(key)

	if value == "" {
		value = defaultValue
	}

	return value
}

func GetBoolEnvWithDefault(key string, defaultValue bool) bool {
	value := os.Getenv(key)

	if value == "" {
		return defaultValue
	}

	if value == "true" {
		return true
	}

	return false
}

func GetIntEnvWithDefault(key string, defaultValue int) int {
	value := os.Getenv(key)

	if value == "" {
		return defaultValue
	}

	intValue, err := strconv.Atoi(value)

	if err != nil {
		slog.Error("Error parsing integer from environment variable", "Key", key)
		return defaultValue
	}

	return intValue
}

func CreateJWTToken(userid string) (string, error) {
	claims := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": userid,                                     // Subject (user identifier)
		"exp": time.Now().Add(time.Hour * 24 * 30).Unix(), // Expiration time
		"iat": time.Now().Unix(),                          // Issued at
	})

	tokenString, err := claims.SignedString(constants.SecretKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func VerifyToken(tokenString string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return constants.SecretKey, nil
	})

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	return token, nil
}

func ExtractBearerToken(header string) (string, error) {
	if header == "" {
		return "", fmt.Errorf("bad header value")
	}

	jwtToken := strings.Split(header, " ")
	if len(jwtToken) != 2 {
		return "", fmt.Errorf("incorrectly formatted authorization header")
	}

	return jwtToken[1], nil
}

func ExtractClaims(tokenStr string) jwt.MapClaims {
	hmacSecretString := constants.SecretKey
	hmacSecret := []byte(hmacSecretString)
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		// check token signing method etc
		return hmacSecret, nil
	})

	if err != nil {
		return nil
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims
	} else {
		slog.Error("Invalid JWT Token")
		return nil
	}
}

func HashPassword(password string) string {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		slog.Error("Error hashing password", "Error", err)
		return ""
	}
	return string(hashedPassword)
}

func ComparePassword(password, hashedPassword string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	return err == nil
}
