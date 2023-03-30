package jwt
import (

"encoding/json"
"errors"
"github.com/google/uuid"
"time"


)


func mapkey(m map[int]string, value string) (key int, ok bool) {
  for k, v := range m {
    if v == value {
      key = k
      ok = true
      return
    }
  }
  return
}

func (h *JwtHeader) UnmarshalJSON(data []byte) error {
	raw := struct {
		Algorithm string `json:"alg"`
		Type string `json:"typ"`
	}{}

	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	algo, ok := mapkey(mapAlgo2Str, raw.Algorithm)
	if !ok {
		algo = -1
	}

	h.Algorithm = algo
	h.Type = raw.Type
	return nil
}

var mapAlgo2Str = map[int]string {
	HS256: "HS256",
	HS384: "HS384",
	HS512: "HS512",
}

func (h JwtHeader) MarshalJSON() ([]byte, error) {
	strAlgo, ok := mapAlgo2Str[h.Algorithm]
	if !ok {
		strAlgo = "Unknown"
        errors.New("Unknown algorithm")
		// return error ???
	}

	return json.Marshal(&struct {
		Algorithm string `json:"alg"`
		Type string `json:"typ"`
	}{
		Algorithm: strAlgo,
		Type: h.Type,
	})
}


func (p *JwtPayload) UnmarshalJSON(data []byte) error {
	raw := struct {
		ID uuid.UUID `json:"jti"`
        CreatedAt int64 `json:"iat"`
        ExpiredAt int64 `json:"exp"`
        OID uuid.UUID `json:"oid"`
        UID uuid.UUID `json:"uid"`
        Groups string `json:"grp"`
	}{}

	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

    iat := time.Unix( raw.CreatedAt, 0 )
    exp := time.Unix( raw.ExpiredAt, 0 ).Sub(iat)

    p.ID = raw.ID
    p.CreatedAt = iat
    p.ExpiredAt = exp
    p.OID = raw.OID
	p.UID = raw.UID
    p.Groups = raw.Groups
	return nil
}

func (p JwtPayload) MarshalJSON() ([]byte, error) {
    return json.Marshal(&struct {
        ID uuid.UUID `json:"jti"`
        CreatedAt int64 `json:"iat"`
        ExpiredAt int64 `json:"exp"`
        OID uuid.UUID `json:"oid"`
        UID uuid.UUID `json:"uid"`
        Groups string `json:"grp"`
    }{
        ID: p.ID,
        CreatedAt: p.CreatedAt.Unix(),
        ExpiredAt: p.CreatedAt.Add( p.ExpiredAt ).Unix(),
        OID: p.OID,
        UID: p.UID,
        Groups: p.Groups,
    })
}