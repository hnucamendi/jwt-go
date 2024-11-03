package jwt

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"time"
)

type JWT struct {
	TenantURL string
	AuthToken string
	ExpiresIn int
}

type CreateJWTConfig struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Audience     string `json:"audience"`
}

type JWTResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
	TokenType   string `json:"token_type"`
}

func (jwt *JWT) GenerateToken(client *http.Client, config *CreateJWTConfig) (string, error) {
	if jwt.AuthToken != "" {
		if time.Now().Unix() < int64(jwt.ExpiresIn) {
			return jwt.AuthToken, nil
		}
	}

	bodyData := map[string]string{
		"client_id":     config.ClientID,
		"client_secret": config.ClientSecret,
		"audience":      config.Audience,
		"grant_type":    "client_credentials",
	}

	body, err := json.Marshal(bodyData)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", jwt.TenantURL, bytes.NewBuffer(body))
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/json")

	res, err := client.Do(req)
	if err != nil {
		return "", err
	}

	defer res.Body.Close()

	b, err := io.ReadAll(res.Body)
	if err != nil {
		return "", err
	}

	var tokenStruct *JWTResponse
	err = json.Unmarshal(b, &tokenStruct)
	if err != nil {
		return "", err
	}

	jwt.AuthToken = tokenStruct.AccessToken
	jwt.ExpiresIn = tokenStruct.ExpiresIn

	return tokenStruct.AccessToken, nil
}
