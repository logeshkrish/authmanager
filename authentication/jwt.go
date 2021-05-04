package authentication

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"

	// "errors"

	redis "github.com/bluemeric/authmanager/redis"
	//settings "gopaddle/domainmanager/settings"
	"time"

	logs "github.com/bluemeric/authmanager/utils/log"

	jwt "github.com/dgrijalva/jwt-go"
)

type JWTAuthenticationBackend struct {
	privateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
}

const (
	tokenDuration = 72
	expireOffset  = 3600
)

var authBackendInstance *JWTAuthenticationBackend = nil

//JWT Key Initialization
func InitJWTAuthenticationBackend() *JWTAuthenticationBackend {
	if authBackendInstance == nil {
		authBackendInstance = &JWTAuthenticationBackend{
			privateKey: getPrivateKey(),
			PublicKey:  getPublicKey(),
		}
	}
	return authBackendInstance
}

//Generating Token with Private and Public keys
func (backend *JWTAuthenticationBackend) GenerateToken(userUUID string, emailID string, timestamp string, subject string, exptime int64, istime int64) (string, error) {
	//i, _ := strconv.Atoi(settings.Get().JWTExpirationDelta)
	// Create the Claims
	claims := &jwt.StandardClaims{
		Audience:  emailID,
		ExpiresAt: exptime,
		IssuedAt:  istime,
		Issuer:    "gopaddle",
		Subject:   subject,
		Id:        userUUID,
		// NotBefore: "",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS512, claims)
	// token.Claims["exp"] = time.Now().Add(time.Hour * time.Duration(i)).Unix()
	// token.Claims["iat"] = time.Now().Unix()
	// token.Claims["sub"] = userUUID
	// token.Claims["handle"] = handle
	// token.Claims["login_time"] = timestamp
	tokenString, err := token.SignedString(backend.privateKey)
	if err != nil {
		log.Error("Error generating JWT token: ", err.Error())
		return "", err
	}
	return tokenString, nil
}

//To Get the Token Remaining Validity
func (backend *JWTAuthenticationBackend) getTokenRemainingValidity(timestamp interface{}) int {
	if validity, ok := timestamp.(float64); ok {
		tm := time.Unix(int64(validity), 0)
		remainer := tm.Sub(time.Now())
		if remainer > 0 {
			return int(remainer.Seconds() + expireOffset)
		}
	}
	return expireOffset
}

//Setting the value(Jwt token with exp time) in redis server
func (backend *JWTAuthenticationBackend) SetValueInRedis(tokenString string, token *jwt.Token) error {
	redisConn := redis.Connect()
	fmt.Println("redisConn val inside jwt ====> ", redisConn)
	// if claims, ok := token.Claims.(*jwt.StandardClaims); ok && token.Valid {
	// 	log.Debug(" %v", claims.ExpiresAt)

	claims := token.Claims.(jwt.MapClaims)
	fmt.Println("Claims---------")
	fmt.Println("expires in ", time.Unix(int64(claims["exp"].(float64)), 0))

	return redisConn.SetValue(tokenString, tokenString, claims["exp"]) //backend.getTokenRemainingValidity(claims.ExpiresAt))

	// } else {
	// 	log.Error("Error getting expiry time from token")
	//	return errors.New("Error getting expiry time from token")
	// }
}

//Reading the value form the redis server
func (backend *JWTAuthenticationBackend) ReadValueFromRedis(token string) string {
	redisConn := redis.Connect()
	redisToken, err := redisConn.GetValue(token)
	//fmt.Println("redis get token param : ", token)
	if err != nil {
		if logs.IsDebugEnabled {
			fmt.Println(" Error While Reading Redis Value: ", err.Error())
			return "ErrorInConnection"
		}
	}
	if redisToken == nil {
		fmt.Println("not found in redis[jwt]")
		return "NotFound"
	}
	fmt.Println("found in redis[jwt]")
	fmt.Println("redis get : ", string(redisToken.([]byte)))
	fmt.Println("redis get token param : ", token)
	return "Found"
}

//Remove the key value from the redis server
func (backend *JWTAuthenticationBackend) DeleteValueFromRedis(token string) bool {
	redisConn := redis.Connect()
	redisToken, _ := redisConn.DelValue(token)
	if redisToken == nil {
		return false
	}
	return true
}

//To Load Private Key
func getPrivateKey() *rsa.PrivateKey {
	// privateKeyFile, err := os.Open(settings.Get().PrivateKeyPath)
	// if err != nil {
	// 	panic(err)
	// }

	// pemfileinfo, _ := privateKeyFile.Stat()
	// var size int64 = pemfileinfo.Size()
	// pembytes := make([]byte, size)

	// buffer := bufio.NewReader(privateKeyFile)
	// _, err = buffer.Read(pembytes)

	pvkey := "LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFb3dJQkFBS0NBUUVBNHc1eGhpbDhZRlNMcHRSeHpRc2lKZ1FtN0R4ZlZ4N25FRkFuZFFEdy83YTFWZklmCmhoelpsVVl4NnUrNTdrUDQrSlBocUxNbDloRVBuSmgyRE1QVjR3clFBT1NlNnBESzVVUC94WlF4OHlneTcwbEcKZko2TVZvN21rWEthb2ZLb2JPaGtGSU9ocXRMVS82Q3J6RmwrS2RGSXNEN3B0K0Z4VjZtTW1QYm5BdkROK2hGNQpOd1U2TjYxV0dBWkVSOHo3U1NUZ2F5R3B1SGRVS0NkUHdmdWlVSUVYM0d4aHNrelYvUk9pUytSL05iUVpsc2ZtClFxY0JKNUZ4aE90QVZldmk5czd4NkxMVFNRS29wdXV1blNUVHR1M3lzL2hzNW02QXFOUFBrTEtxcDZSOGlYRjEKTGcwRE1lUWxGSFl3RW8zb1J3ZU1OaGZZUnpDM3VraW9TZitHdXdJREFRQUJBb0lCQURsZW1lS0xNdWpvRTgwWQpXcFN6WG5KNmxCY1dmZ1IyUTIzRXd1TjJWRzVZRE9ObFpQK3U1RzhxS0V5ek82aHZOa1lnbjJEUHV5UzhWTlI5ClZUNk9jTW1JSHR4SzU3aGUwMVV3WkR6WTMvSVBVeWRRdldXWmJkNGxCeTd5NVExTVViQUsyOWF2RjdjZ3hENisKcXduY0J0dXNESkN6cEx3WVUxb1I5ZnRrVHlSWGw4V3pIVVErL1FJTE5uU0NEc1RyUDhKc1ZhVnhiZDZGaEtLbgo1c1N5cU0rZFg3bXR2VkFPY2owT0pTSFppaXQ3Zms1UUc5UGkvNWlQNHBDZFpmNDJzSW1zcisrMkdGT2V6ZkpkCkg1VVUrdWpUZitiNG9HaXJucWdFRFJyU3I1SXl5a2FnV2MwN0QyS0pneVB6cmtmRkR4b0I1Qy9aQzNDNkM5QUEKWHd6ZCtHRUNnWUVBNVNQRGZDTVZCUkZrWUJveEtnYldFRWxxdUdpUE1EU2UrcDZRU2xYMjRVWEZ2OGd6ZHRiVApmMzNkMjd2MmNwSU9XWXltM0VyNUppU0ZxNm9DcjFjZzkrbUxQL3ROYzUwc0hyZEhiOHZSZm4xOTBuYXdGSkhhCmVPZTBiM1plUFV0QXhkZDFIYVpncTRiTm5MWVNiaS8vc3BkSHV1NkUxalpyemNtYnZJbTdQSkVDZ1lFQS9hd3AKcklMTUR2cUh1R05sVnIra2RjR2ZtRnhBOHk5WjF0WkhMZ3FOalBRUWxhT3V5Sm4xY2ZZYklxZ2hNTGprLy9BdQpWUTVnZktMYzJhYkhRYVZRMmRMcVY4NDZlTlF2citjbkxRVXJVcWs0MUladU4wSFRNYnZMSGdPTGtRTmRzVU1zCjFUbW1QZU14aDlYOWNMcXA3bVpvWTVDZVdlV0ZPZTNFSkExZFpJc0NnWUVBa2xiZjN5VU1wSnJ4N3dwclFicngKOVo3ZHdINU9qR3ZlNkpKaDlvZW1UMExmUTFkWnZ0aitaQnIvbVBrWE1SNmtlWDZCaG9sL1MyUGgxcnVTVVdjawowQS9nZGZGS0NyOWpVUTZlV2dEaWY1VW55VVV4dVVGWk5RUk4wUzNZaSs3R3BGT3hJVW1EemFnZklxbUpaY1BUCjJyd1EvSXFlWGF5Tjl2UitPTkFCdTNFQ2dZQUVDbjRQZFhYeXR5TDZXUHNBU3NVLzZ2bXozNlJaTzJQZS9FTGUKQk9VRVhjNzEwMG14Z0dKY2ttTVVSa0ZoR1ZEc2t0THFIL1NCaDhhazRQZERvSEtOUmNMZDZ6Y2JQYVlVMDBYWQpmY0NXN0lNdlA0VDU5RjU4NkZUd0FYWnp0TzRGS09ESjlNVWxMejFXd0ozczhjeExNKzV0eDV2K0twM1lzbVR4CmZoVUN5UUtCZ0RDRWtGZXhycUMyYTFySExoK3B3VHl2bkU0SkNWTnQ3MkZGOEw1MWFFc0c1dEdHRnZUdmdVTjYKSWxSQ1lBU05oVUsvMytodTMzN3VPU29sS1h1MFcrZEZucDEvT0xvNnNVa3VoeFdHeDNZTHdHSnlnalNyT2w1Zgozd0lpa1EwVS9SalJyKy9wSTAveXcvdzNYY3I3aVVqZWk2U0J4a2lJZVpMLzc0OUVjTE5CCi0tLS0tRU5EIFJTQSBQUklWQVRFIEtFWS0tLS0t"
	pKeybyte, err := base64.StdEncoding.DecodeString(pvkey)
	if err != nil {
		fmt.Println("failed on decoding a private key", err)
	}
	data, _ := pem.Decode(pKeybyte)

	// privateKeyFile.Close()

	privateKeyImported, err := x509.ParsePKCS1PrivateKey(data.Bytes)

	if err != nil {
		panic(err)
	}

	return privateKeyImported
}

//To Load Public Key
func getPublicKey() *rsa.PublicKey {
	// publicKeyFile, err := os.Open(settings.Get().PublicKeyPath)
	// if err != nil {
	// 	panic(err)
	// }

	// pemfileinfo, _ := publicKeyFile.Stat()
	// var size int64 = pemfileinfo.Size()
	// pembytes := make([]byte, size)

	// buffer := bufio.NewReader(publicKeyFile)
	// _, err = buffer.Read(pembytes)
	pubkey := "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUE0dzV4aGlsOFlGU0xwdFJ4elFzaQpKZ1FtN0R4ZlZ4N25FRkFuZFFEdy83YTFWZklmaGh6WmxVWXg2dSs1N2tQNCtKUGhxTE1sOWhFUG5KaDJETVBWCjR3clFBT1NlNnBESzVVUC94WlF4OHlneTcwbEdmSjZNVm83bWtYS2FvZktvYk9oa0ZJT2hxdExVLzZDcnpGbCsKS2RGSXNEN3B0K0Z4VjZtTW1QYm5BdkROK2hGNU53VTZONjFXR0FaRVI4ejdTU1RnYXlHcHVIZFVLQ2RQd2Z1aQpVSUVYM0d4aHNrelYvUk9pUytSL05iUVpsc2ZtUXFjQko1RnhoT3RBVmV2aTlzN3g2TExUU1FLb3B1dXVuU1RUCnR1M3lzL2hzNW02QXFOUFBrTEtxcDZSOGlYRjFMZzBETWVRbEZIWXdFbzNvUndlTU5oZllSekMzdWtpb1NmK0cKdXdJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0t"
	pubKeybyte, err := base64.StdEncoding.DecodeString(pubkey)
	if err != nil {
		fmt.Println("failed on decoding a private key", err)
	}
	data, _ := pem.Decode(pubKeybyte)

	// publicKeyFile.Close()

	publicKeyImported, err := x509.ParsePKIXPublicKey(data.Bytes)

	if err != nil {
		panic(err)
	}

	rsaPub, ok := publicKeyImported.(*rsa.PublicKey)

	if !ok {
		panic(err)
	}

	return rsaPub
}

func GetLogger() {
	log = logs.GetLogger()
}
