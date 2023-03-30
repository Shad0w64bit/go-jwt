package jwt
import (

"crypto/hmac"
"crypto/sha256"
"crypto/sha512"
"encoding/base64"
"encoding/json"
"errors"
"fmt"
"github.com/google/uuid"
"hash"
"strings"
"time"

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

func hashData(algo int, data []byte, secret []byte) ([]byte, error) {
	hf, err := getHashFunc(algo)
	if err != nil {
		return nil, err
	}

	h := hmac.New(hf, secret)
	_, err = h.Write(data)
	if err != nil {
		return nil, err
	}

	hm := h.Sum(nil)
    return hm, nil
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

	data := fmt.Sprintf("%s.%s",
		enc.EncodeToString(hb),
		enc.EncodeToString(pb))

    sign, err := hashData(p.Header.Algorithm, []byte(data), p.Secret)
    if err != nil {
        return "", err
    }

	res := fmt.Sprintf("%s.%s", data, enc.EncodeToString(sign))
	return res, nil
}

func (t *JwtToken) SetTTL(ttl time.Duration) *JwtToken {
	t.Payload.ExpiredAt = ttl
	return t
}

func (t *JwtToken) SetAlgorithm(a int) *JwtToken {
	t.Header.Algorithm = a
	return t
}

func (t *JwtToken) SetSecret(secret []byte) *JwtToken {
	t.Secret = secret
	return t
}


// algo int, secret []byte, ttl int
func New() (*JwtToken) {
	return &JwtToken{
		Header: JwtHeader{
			Algorithm: HS256,
			Type: "JWT",
		},
		Payload: JwtPayload{
			ID: uuid.New(),
			CreatedAt: time.Now(),
			ExpiredAt: time.Minute * 5,
		},
		Secret: nil,
	}
}

func Parse(strToken string) (*JwtToken, error) {
	arr := strings.Split(strToken, ".")
	if len(arr) != 3 {
		return nil, errors.New("Invalid token format")
	}

    enc := base64.URLEncoding.WithPadding(base64.NoPadding)

	hb, err := enc.DecodeString(arr[0])
	if err != nil {
		return nil, err
	}

    pb, err := enc.DecodeString(arr[1])
    if err != nil {
    		return nil, err
    	}

	token := New()

	if err := json.Unmarshal( hb, &token.Header ); err != nil {
		return nil, err
	}

    if err := json.Unmarshal( pb, &token.Payload ); err != nil {
		return nil, err
	}

    return token, nil
}


func Validate(token string, secret []byte) error {
    if err := ValidateTime(token, secret); err != nil {
        return err
    }
    if err := ValidateSign(token, secret); err != nil {
        return err
    }
    return nil
/*	arr := strings.Split(token, ".")
	if len(arr) != 3 {
		return errors.New("Invalid token format")
	}

    enc := base64.URLEncoding.WithPadding(base64.NoPadding)

	hb, err := enc.DecodeString(arr[0])
	if err != nil {
		return err
	}

    pb, err := enc.DecodeString(arr[1])
    if err != nil {
        return err
    }


	var header JwtHeader
    var payload JwtPayload

	if err := json.Unmarshal( hb, &header ); err != nil {
		return err
	}
    if err := json.Unmarshal( pb, &payload ); err != nil {
        return err
    }

	// Check sign

	data := fmt.Sprintf("%s.%s", arr[0], arr[1])

    sign, err := hashData(header.Algorithm, []byte(data), secret)
    if err != nil {
        return err
    }

	csign := enc.EncodeToString(sign)

    fmt.Println(csign,arr[2])

	if strings.Compare(csign, arr[2]) != 0 {
		return errors.New("Invalid signature")
	}

	return nil

 */
}

func ValidateSign(token string, secret []byte) error {
    	arr := strings.Split(token, ".")
    	if len(arr) != 3 {
    		return errors.New("Invalid token format")
    	}

        enc := base64.URLEncoding.WithPadding(base64.NoPadding)

    	hb, err := enc.DecodeString(arr[0])
    	if err != nil {
    		return err
    	}

    	var header JwtHeader

    	if err := json.Unmarshal( hb, &header ); err != nil {
    		return err
    	}

        // Check time
/*
        pb, err := enc.DecodeString(arr[1])
        if err != nil {
            return err
        }

        var payload JwtPayload
        if err := json.Unmarshal( pb, &payload ); err != nil {
            return err
        }

        if payload.CreatedAt.Add(payload.ExpiredAt).After( time.Now() ) {
            return errors.New("Token expired")
        }
*/
    	// Check sign

    	data := fmt.Sprintf("%s.%s", arr[0], arr[1])

        sign, err := hashData(header.Algorithm, []byte(data), secret)
        if err != nil {
            return err
        }

    	csign := enc.EncodeToString(sign)

       // fmt.Println(csign,arr[2])

    	if strings.Compare(csign, arr[2]) != 0 {
    		return errors.New("Invalid signature")
    	}

    	return nil
}

func ValidateTime(token string, secret []byte) error {
    	arr := strings.Split(token, ".")
    	if len(arr) != 3 {
    		return errors.New("Invalid token format")
    	}

        enc := base64.URLEncoding.WithPadding(base64.NoPadding)

        pb, err := enc.DecodeString(arr[1])
        if err != nil {
            return err
        }


        var payload JwtPayload
        if err := json.Unmarshal( pb, &payload ); err != nil {
            return err
        }

        // Check time
        exp := payload.CreatedAt.Add(payload.ExpiredAt)
        now := time.Now()

        if now.After(exp) {
            return errors.New("Token expired")
        }

    	return nil
}

