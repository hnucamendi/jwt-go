package jwt

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"
)

type JWK struct {
	Alg string   `json:"alg"`
	E   string   `json:"e"`
	Kid string   `json:"kid"`
	Kty string   `json:"kty"`
	N   string   `json:"n"`
	Use string   `json:"use"`
	X5C []string `json:"x5c"`
	X5T string   `json:"x5t"`
}

type JWKs struct {
	Keys []*JWK `json:"keys"`
}

type Header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

type Payload struct {
	Iss string `json:"iss"`
	Sub string `json:"sub"`
	Aud string `json:"aud"`
	Iat int    `json:"iat"`
	Exp int    `json:"exp"`
	Gty string `json:"gty"`
	Azp string `json:"azp"`
}

type Token struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

func main() {
	client := &http.Client{
		Timeout: 20 * time.Second,
	}

	decodeURL := os.Getenv("DECODEURL")
	url := os.Getenv("URL")
	clientID := os.Getenv("CLIENT_ID")
	clientSecret := os.Getenv("CLIENT_SECRET")
	clientResource := os.Getenv("CLIENT_RESOURCE")
	grantType := os.Getenv("GRANT_TYPE")

	token, err := getToken(client, url, clientID, clientSecret, clientResource, grantType)
	if err != nil {
		fmt.Println(err)
	}

	err = validateToken(client, decodeURL, token)
	if err != nil {
		fmt.Println(err)
	}
}

func getToken(client *http.Client, url, clientID, clientSecret, clientResource, grantType string) (string, error) {
	payload := fmt.Sprintf(`{"client_id": %q, "client_secret": %q, "audience": %q, "grant_type": %q }`, clientID, clientSecret, clientResource, grantType)

	body := strings.NewReader(payload)

	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/json")

	res, err := client.Do(req)
	if err != nil {
		return "", err
	}

	defer res.Body.Close()

	var t *Token
	err = json.NewDecoder(res.Body).Decode(&t)
	if err != nil {
		return "", err
	}

	return t.AccessToken, nil
}

func validateToken(client *http.Client, url, token string) error {
	_, _, hMessage, dSignature, err := decodeToken(token)
	if err != nil {
		return err
	}

	p, err := loadPublicKeys(client, url)
	if err != nil {
		return err
	}

	// Convert modulus (n) and exponent (e) from Base64URL encoding
	modulusBytes, err := base64.RawURLEncoding.DecodeString(p.Keys[0].N)
	if err != nil {
		fmt.Println("Error decoding modulus:", err)
		return err
	}

	exponentBytes, err := base64.RawURLEncoding.DecodeString(p.Keys[0].E)
	if err != nil {
		fmt.Println("Error decoding exponent:", err)
		return err
	}

	// Convert exponent bytes to an integer
	var exponent int
	if len(exponentBytes) == 3 {
		exponent = int(exponentBytes[0])<<16 | int(exponentBytes[1])<<8 | int(exponentBytes[2])
	} else if len(exponentBytes) == 1 {
		exponent = int(exponentBytes[0])
	} else {
		fmt.Println("Unsupported exponent length")
		return err
	}

	// Create an rsa.PublicKey
	pubKey := &rsa.PublicKey{
		N: new(big.Int).SetBytes(modulusBytes),
		E: exponent,
	}

	// Print the public key (for verification purposes)
	fmt.Printf("Public Key: %+v\n", pubKey)

	fmt.Println(dSignature)

	// Now use the public key to verify a signature or decrypt a message
	// Example of verifying a signature
	message := hMessage
	signatureBase64 := dSignature

	signature, err := base64.RawURLEncoding.DecodeString(signatureBase64)
	if err != nil {
		fmt.Println("Error decoding signature:", err)
		return err
	}

	hashed := sha256.Sum256([]byte(message))
	err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hashed[:], signature)
	if err != nil {
		fmt.Println("Verification failed:", err)
		return err
	}

	fmt.Println("Signature verified successfully")
	return nil
}

func loadPublicKeys(client *http.Client, url string) (*JWKs, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	defer res.Body.Close()

	var pks *JWKs
	err = json.NewDecoder(res.Body).Decode(&pks)
	if err != nil {
		return nil, err
	}

	return pks, nil
}

func decodeToken(token string) (*Header, *Payload, string, string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return &Header{}, &Payload{}, "", "", fmt.Errorf("invalid token")
	}

	decodedHeader, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return &Header{}, &Payload{}, "", "", err
	}

	var header Header
	err = json.Unmarshal(decodedHeader, &header)
	if err != nil {
		return &Header{}, &Payload{}, "", "", err
	}

	decodedPayload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return &Header{}, &Payload{}, "", "", err
	}

	var payload Payload
	err = json.Unmarshal(decodedPayload, &payload)
	if err != nil {
		return &Header{}, &Payload{}, "", "", err
	}

	hashedMessage := parts[0] + "." + parts[1]

	return &header, &payload, hashedMessage, parts[2], nil
}
