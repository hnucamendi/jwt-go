package jwt

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"time"
)

func (jwt *JWTClient) GenerateToken(client *http.Client) (string, error) {
	if jwt.AuthToken != "" {
		if time.Now().Unix() < int64(jwt.ExpiresIn) {
			return jwt.AuthToken, nil
		}
	}

	bodyData := map[string]string{
		"client_id":     jwt.GenerateTokenConfig.ClientID,
		"client_secret": jwt.GenerateTokenConfig.ClientSecret,
		"audience":      jwt.GenerateTokenConfig.Audience,
		"grant_type":    jwt.GenerateTokenConfig.GrantType,
	}

	body, err := json.Marshal(bodyData)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", jwt.TenantURL+"/oauth/token", bytes.NewBuffer(body))
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
