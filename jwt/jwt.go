package jwt

type OpenIDConfiguration struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	DeviceAuthorizationEndpoint       string   `json:"device_authorization_endpoint"`
	UserinfoEndpoint                  string   `json:"userinfo_endpoint"`
	MFAChallengeEndpoint              string   `json:"mfa_challenge_endpoint"`
	JWKSURI                           string   `json:"jwks_uri"`
	RegistrationEndpoint              string   `json:"registration_endpoint"`
	RevocationEndpoint                string   `json:"revocation_endpoint"`
	ScopesSupported                   []string `json:"scopes_supported"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	ResponseModesSupported            []string `json:"response_modes_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	ClaimsSupported                   []string `json:"claims_supported"`
	RequestURIParameterSupported      bool     `json:"request_uri_parameter_supported"`
	RequestParameterSupported         bool     `json:"request_parameter_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	TokenEndpointAuthSigningAlgValues []string `json:"token_endpoint_auth_signing_alg_values_supported"`
	EndSessionEndpoint                string   `json:"end_session_endpoint"`
}

type JWTOpts func(*JWTClient) error

type GenerateTokenConfig struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Audience     string `json:"audience"`
	GrantType    string `json:"grant_type"`
}

type JWTClient struct {
	TenantURL string
	AuthToken string
	ExpiresIn int
	GenerateTokenConfig
}

type JWTResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
	TokenType   string `json:"token_type"`
}

func JWTTenantURL(url string) JWTOpts {
	return func(j *JWTClient) error {
		j.TenantURL = url
		return nil
	}
}

func JWTAuthToken(token string) JWTOpts {
	return func(j *JWTClient) error {
		j.AuthToken = token
		return nil
	}
}

func JWTExpiresIn(expiresIn int) JWTOpts {
	return func(j *JWTClient) error {
		j.ExpiresIn = expiresIn
		return nil
	}
}

func JWTClientID(clientID string) JWTOpts {
	return func(j *JWTClient) error {
		j.GenerateTokenConfig.ClientID = clientID
		return nil
	}
}

func JWTClientSecret(clientSecret string) JWTOpts {
	return func(j *JWTClient) error {
		j.GenerateTokenConfig.ClientSecret = clientSecret
		return nil
	}
}

func JWTAudience(audience string) JWTOpts {
	return func(j *JWTClient) error {
		j.GenerateTokenConfig.Audience = audience
		return nil
	}
}

func JWTGrantType(grantType string) JWTOpts {
	return func(j *JWTClient) error {
		j.GenerateTokenConfig.GrantType = grantType
		return nil
	}
}

func NewJWTClient(fn ...JWTOpts) *JWTClient {
	jwt := &JWTClient{}
	for _, f := range fn {
		f(jwt)
	}
	return jwt
}
