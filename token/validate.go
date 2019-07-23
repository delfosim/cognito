package token

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"

	"github.com/dgrijalva/jwt-go"
)

// Auth Auth
type Auth struct{}

// Key Key
type Key struct {
	Alg string `json:"alg"`
	E   string `json:"e"`
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	N   string `json:"n"`
}

type jwkKeys struct {
	Keys []Key `json:"keys"`
}

var jwk *jwkKeys
var err error

// NewAuth NewAuth
func NewAuth(AWSRegion, AWSCognitoUserPoolID string) (*Auth, error) {
	jwk, err = getKeysAWS(AWSRegion, AWSCognitoUserPoolID)
	if err != nil {
		return nil, err
	}

	return &Auth{}, nil
}

// Validate Validate
func (a *Auth) Validate(tokenString string, index int) (map[string]interface{}, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		key, errKey := convertKey(jwk.Keys[index].E, jwk.Keys[index].N)
		if errKey != nil {
			return nil, errKey
		}
		return key, nil
	})

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, err
}

func convertKey(rawE, rawN string) (*rsa.PublicKey, error) {
	decodedE, err := base64.RawURLEncoding.DecodeString(rawE)
	if err != nil {
		return nil, err
	}
	if len(decodedE) < 4 {
		ndata := make([]byte, 4)
		copy(ndata[4-len(decodedE):], decodedE)
		decodedE = ndata
	}
	pubKey := &rsa.PublicKey{
		N: &big.Int{},
		E: int(binary.BigEndian.Uint32(decodedE[:])),
	}
	decodedN, err := base64.RawURLEncoding.DecodeString(rawN)
	if err != nil {
		return nil, err
	}
	pubKey.N.SetBytes(decodedN)
	return pubKey, nil
}

func getKeysAWS(AWSRegion, AWSCognitoUserPoolID string) (*jwkKeys, error) {
	urlAWSKey := fmt.Sprintf(
		"https://cognito-idp.%s.amazonaws.com/%s/.well-known/jwks.json",
		AWSRegion,
		AWSCognitoUserPoolID)

	req, err := http.NewRequest("GET", urlAWSKey, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Accept", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	jwk := new(jwkKeys)
	if err := json.Unmarshal(body, jwk); err != nil {
		return nil, err
	}

	return jwk, nil
}
