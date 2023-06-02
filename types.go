package jwt
import (

"github.com/google/uuid"
"time"
)

type JwtHeader struct{
	Algorithm int `json:"alg"`
	Type string `json:"typ"`
}

// type JwtPayload map[string]any

type JwtPayload struct{
	ID uuid.UUID `json:"jti"`
	CreatedAt time.Time `json:"iat"`
	ExpiredAt time.Duration `json:"exp"`
	Audience uuid.UUID `json:"aud"`
    Username string `json:"uname"`
    OrgName string `json:"oname"`
    UID uuid.UUID `json:"uid"`
	OID uuid.UUID `json:"oid"`
	Groups string `json:"grp"`
}



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
