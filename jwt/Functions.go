package jwt
import (

"crypto/hmac"
"crypto/sha256"
"crypto/sha512"
"encoding/base64"
"encoding/json"
"errors"
"fmt"
"hash"
"strings"

)

func getHashFunc(algo int) (func() hash.Hash, error) {
	switch algo {
		case HS256:
			return sha256.New, nil
		case HS384:
			return sha512.New384, nil
		case HS512:
			return sha512.New, nil
	}
	return nil, errors.New("Unknown algorithm")
}

func (p *JwtToken) GenerateToken() (string, error) {
	hb, err := json.Marshal(p.Header)
  	if err != nil {
		  return "", err
  	}

	pb, err := json.Marshal(p.Payload)
	if err != nil {
		  return "", err
	}

	enc := base64.URLEncoding.WithPadding(base64.NoPadding)

	// fmt.Println(p.Secret)

	sb := []byte(p.Secret)

//	sb := []byte(enc.EncodeToString([]byte(p.Secret)))
	//sb := []byte(base64.StdEncoding.EncodeToString([]byte(p.Secret)))

	//fmt.Println(string(sb))

	data := fmt.Sprintf("%s.%s",
		enc.EncodeToString(hb),
		enc.EncodeToString(pb))

	hf, err := getHashFunc(p.Header.Algorithm)
	if err != nil {
		return "", err
	}

	h := hmac.New(hf, sb)
	_, err = h.Write([]byte(data))
	if err != nil {
		return "", err
	}

	hm := h.Sum(nil)

	res := fmt.Sprintf("%s.%s", data, enc.EncodeToString(hm))
	return res, nil
}

func CreateToken(algo int, secret []byte) (*JwtToken, error) {
/*	al, err := algoToStr(algo)
	if err != nil {
		return nil, err
	}
 */

	return &JwtToken{
		Header: JwtHeader{
			Algorithm: algo,
			Type: "JWT",
		},
		Payload: JwtPayload{},
		Secret: secret,
	}, nil
}

func Validate(token string, secret []byte) error {
	arr := strings.Split(token, ".")
	if len(arr) != 3 {
		return errors.New("Invalid token format")
	}

	hb, err := base64.URLEncoding.DecodeString(arr[0])
	if err != nil {
		return err
	}

	var header JwtHeader
	if err := json.Unmarshal( hb, &header ); err != nil {
		return err
	}

	// Check sign

	data := fmt.Sprintf("%s.%s", arr[0], arr[1])

	hf, err := getHashFunc(header.Algorithm)
	if err != nil {
		return err
	}

	h := hmac.New(hf, secret)
	_, err = h.Write([]byte(data))
	if err != nil {
		return err
	}

	hm := h.Sum(nil)

	csign := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(hm)

	if strings.Compare(csign, arr[2]) != 0 {
		return errors.New("Invalid signature")
	}

	return nil
}