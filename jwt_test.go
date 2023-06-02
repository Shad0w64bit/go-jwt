package jwt_test

import (

jwt "github.com/Shad0w64bit/go-jwt"
"github.com/google/uuid"
"strings"
"testing"
"time"

)

func TestCreate(t *testing.T) {
    token := jwt.New()
    token.SetAlgorithm(jwt.HS256)
    token.SetSecret( []byte("qwe1234") )
    token.SetTTL(time.Minute * 5)
}

func TestConstToken(t *testing.T) {
	token := jwt.New()

    // Default value
    token.SetAlgorithm(jwt.HS256)
    token.SetSecret([]byte("qwe1234"))
    token.SetTTL(time.Minute * 5)

    id := uuid.MustParse("56ba1aaa-9889-4ef2-aa68-586443f9ffec")
    oid := uuid.MustParse("cb104e63-e6a1-42f2-89c2-d8057ae108ee")
    uid:= uuid.MustParse("4d4cd589-2fc4-465e-b5e0-0c8e82f88851")

    // Set Const Data
    token.Payload.ID = id
    token.Payload.CreatedAt = time.Unix(1672628645, 0) // time.Date(2023,1,2,3,4,5,0, time.UTC)
    token.Payload.OID = oid
    token.Payload.UID = uid
    token.Payload.Audience = uuid.MustParse("e7b39a94-64d6-4659-a8d9-db2453b9a45a")
    token.Payload.Username = "user1"
    token.Payload.OrgName = "MyOrg"
    token.Payload.Groups = "62ecaf48-4edc-46aa-97af-81ba76db2d9f:Admins"

    strToken, err := token.GenerateToken()
    if err != nil {
        t.Errorf(err.Error())
    }
    // fmt.Println(strToken)

    const validResult = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiI1NmJhMWFhYS05ODg5LTRlZjItYWE2OC01ODY0NDNmOWZmZWMiLCJpYXQiOjE2NzI2Mjg2NDUsImV4cCI6MTY3MjYyODk0NSwiYXVkIjoiZTdiMzlhOTQtNjRkNi00NjU5LWE4ZDktZGIyNDUzYjlhNDVhIiwidW5hbWUiOiJ1c2VyMSIsIm9uYW1lIjoiTXlPcmciLCJvaWQiOiJjYjEwNGU2My1lNmExLTQyZjItODljMi1kODA1N2FlMTA4ZWUiLCJ1aWQiOiI0ZDRjZDU4OS0yZmM0LTQ2NWUtYjVlMC0wYzhlODJmODg4NTEiLCJncnAiOiI2MmVjYWY0OC00ZWRjLTQ2YWEtOTdhZi04MWJhNzZkYjJkOWY6QWRtaW5zIn0.ZWftYAZDa3H5KkG9qYEB_hUqWAjOxCWRnadLylucD8o"

    if strToken != validResult {
        t.Error("Generated token is invalid")
    }

}

/*
//
// Тест TestParseAndValidate закрывает потребность проверять каждое поле по отдельности
// Если тест прошел значит все поля которые були получены были собраны обратно
//

func TestConstParse(t *testing.T) {
    const srcToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiI1NmJhMWFhYS05ODg5LTRlZjItYWE2OC01ODY0NDNmOWZmZWMiLCJpYXQiOjE2NzI2Mjg2NDUsImV4cCI6MTY3MjYyODk0NSwib2lkIjoiY2IxMDRlNjMtZTZhMS00MmYyLTg5YzItZDgwNTdhZTEwOGVlIiwidWlkIjoiNGQ0Y2Q1ODktMmZjNC00NjVlLWI1ZTAtMGM4ZTgyZjg4ODUxIiwiZ3JwIjoiNjJlY2FmNDgtNGVkYy00NmFhLTk3YWYtODFiYTc2ZGIyZDlmOkFkbWlucyJ9.wF4R4oHyijpbANlMP05r1UgQgxxsSDnjlYaRj4UxzxU"

    // Сравнение

    token, err := jwt.Parse(srcToken)
    if err != nil {
        t.Error(err)
    }

    _ = token

}
 */

func TestParseAndValidate(t *testing.T) {
//    const srcToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiI1NmJhMWFhYS05ODg5LTRlZjItYWE2OC01ODY0NDNmOWZmZWMiLCJpYXQiOjE2NzI2Mjg2NDUsImV4cCI6MTY3MjYyODk0NSwib2lkIjoiY2IxMDRlNjMtZTZhMS00MmYyLTg5YzItZDgwNTdhZTEwOGVlIiwidWlkIjoiNGQ0Y2Q1ODktMmZjNC00NjVlLWI1ZTAtMGM4ZTgyZjg4ODUxIiwiZ3JwIjoiNjJlY2FmNDgtNGVkYy00NmFhLTk3YWYtODFiYTc2ZGIyZDlmOkFkbWlucyJ9.wF4R4oHyijpbANlMP05r1UgQgxxsSDnjlYaRj4UxzxU"

    secret := []byte("qwe1234")
    jwtToken, err := jwt.New().SetSecret(secret).GenerateToken()
    if err != nil {
        t.Error(err)
    }

    gen1sign := strings.Split(jwtToken, ".")[2]

    token, err := jwt.Parse(jwtToken)
    if err != nil {
        t.Error(err)
    }

    token.SetSecret(secret)

    gen2token, err := token.GenerateToken()
    if err != nil {
        t.Error(err)
    }

    gen2sign := strings.Split(gen2token, ".")[2]

    if strings.Compare(gen1sign, gen2sign) != 0 {
        t.Error("Sign are different")
    }
}

func TestExpiredTimeValidate(t *testing.T) {
    const jwtToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiI1NmJhMWFhYS05ODg5LTRlZjItYWE2OC01ODY0NDNmOWZmZWMiLCJpYXQiOjE2NzI2Mjg2NDUsImV4cCI6MTY3MjYyODk0NSwib2lkIjoiY2IxMDRlNjMtZTZhMS00MmYyLTg5YzItZDgwNTdhZTEwOGVlIiwidWlkIjoiNGQ0Y2Q1ODktMmZjNC00NjVlLWI1ZTAtMGM4ZTgyZjg4ODUxIiwiZ3JwIjoiNjJlY2FmNDgtNGVkYy00NmFhLTk3YWYtODFiYTc2ZGIyZDlmOkFkbWlucyJ9.wF4R4oHyijpbANlMP05r1UgQgxxsSDnjlYaRj4UxzxU"
    secret := []byte("qwe1234")

    if err := jwt.ValidateTime(jwtToken, secret); err == nil {
        t.Errorf("Expired token has been accepted")
    }
}


func TestCreateSignValidate(t *testing.T) {
    secret := []byte("qwe1234")
    token := jwt.New().SetAlgorithm(jwt.HS256).SetSecret(secret)

    jwtToken, err := token.GenerateToken()
    if err != nil {
        t.Errorf(err.Error())
    }

    if err := jwt.Validate(jwtToken, secret); err != nil {
        t.Errorf(err.Error())
    }
/*
	token, err := jwt.CreateToken(jwt.HS256, secret, 300)
	if err != nil {
		t.Errorf(err.Error())
	}

	jwtToken, err := token.GenerateToken()
	if err != nil {
		t.Errorf(err.Error())
	}

	if err := jwt.Validate(jwtToken, secret); err != nil {
		t.Errorf(err.Error())
	}
 */
}

func TestTokenCreateValidateTime(t *testing.T){
	secret := []byte("qwe1234")
	token := jwt.New().SetSecret(secret)

	jwtToken, err := token.GenerateToken()
	if err != nil {
		t.Errorf(err.Error())
	}

	if err := jwt.ValidateTime(jwtToken, secret); err != nil {
		t.Errorf(err.Error())
	}
}

func TestTokenCreateValidateSign(t *testing.T){
	secret := []byte("qwe1234")
	token := jwt.New().SetSecret(secret)

	jwtToken, err := token.GenerateToken()
	if err != nil {
		t.Errorf(err.Error())
	}

	if err := jwt.ValidateSign(jwtToken, secret); err != nil {
		t.Errorf(err.Error())
	}
}


/*

JwtToken = CreateToken()
JwtToken = ParseToken(token string)

JwtToken.WithAlgo(HS256)
JwtToken.GetAlgo()

JwtToken.WithTTL(300)
JwtToken.GetTTL()

JwtToken.WithSecret(secret []data)
JwtToken.GetSecret()

JwtToken = ParseToken(token string)
// JwtToken.Validate()

// Bad ??
// JwtToken.Sign()
// JwtToken.ValidateSign()

ValidateSignTime(token string, secret []byte)
ValidateSign(token string, secret []byte)

// Equal
JwtToken.Generate()
JwtToken.ToString()

 */

