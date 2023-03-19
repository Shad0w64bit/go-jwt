package jwt

type JwtHeader struct{
	Algorithm int `json:"alg"`
	Type string `json:"typ"`
}

type JwtPayload map[string]any

type JwtToken struct {
	Header JwtHeader
	Payload JwtPayload
	Secret []byte
}

const  (
	HS256 = 10
	HS384 = 11
	HS512 = 12
	// ...
)