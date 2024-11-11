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
	"strings"
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

func (jwt *JWTClient) ValidateToken(token string) error {
	_, _, hMessage, dSignature, err := decodeToken(token)
	if err != nil {
		return err
	}

	p, err := jwt.loadPublicKeys()
	if err != nil {
		return err
	}

	// Convert modulus (n) and exponent (e) from Base64URL encoding
	modulusBytes, err := base64.RawURLEncoding.DecodeString(p.Keys[0].N)
	if err != nil {
		return fmt.Errorf("error decoding modulus: %s", err.Error())
	}

	exponentBytes, err := base64.RawURLEncoding.DecodeString(p.Keys[0].E)
	if err != nil {
		return fmt.Errorf("error decoding exponent: %s", err.Error())
	}

	// Convert exponent bytes to an integer
	var exponent int
	if len(exponentBytes) == 3 {
		exponent = int(exponentBytes[0])<<16 | int(exponentBytes[1])<<8 | int(exponentBytes[2])
	} else if len(exponentBytes) == 1 {
		exponent = int(exponentBytes[0])
	} else {
		return fmt.Errorf("unsupported exponent length")
	}

	// Create an rsa.PublicKey
	pubKey := &rsa.PublicKey{
		N: new(big.Int).SetBytes(modulusBytes),
		E: exponent,
	}

	// Now use the public key to verify a signature or decrypt a message
	// Example of verifying a signature
	message := hMessage
	signatureBase64 := dSignature

	signature, err := base64.RawURLEncoding.DecodeString(signatureBase64)
	if err != nil {
		return fmt.Errorf("error decoding signature: %s", err.Error())
	}

	hashed := sha256.Sum256([]byte(message))
	err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hashed[:], signature)
	if err != nil {
		return fmt.Errorf("verification failed: %s", err.Error())
	}

	return nil
}

func (jwt *JWTClient) getOpenIDConfiguration() (*OpenIDConfiguration, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/.well-known/openid-configuration", jwt.TenantURL), nil)
	if err != nil {
		return nil, err
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer res.Body.Close()

	var openidConfig *OpenIDConfiguration
	err = json.NewDecoder(res.Body).Decode(&openidConfig)
	if err != nil {
		return nil, err
	}

	return openidConfig, nil
}

func (jwt *JWTClient) loadPublicKeys() (*JWKs, error) {
	config, err := jwt.getOpenIDConfiguration()
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("GET", config.JWKSURI, nil)
	if err != nil {
		return nil, err
	}

	res, err := http.DefaultClient.Do(req)
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
