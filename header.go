package jwt
import "encoding/json"


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
