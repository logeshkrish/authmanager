package authentication

import (
	"encoding/base64"
	jsons "encoding/json"
	"errors"
	"fmt"

	"github.com/bluemeric/authmanager/directory"
	"github.com/bluemeric/authmanager/misc"
	json "github.com/bluemeric/authmanager/utils/json"
	"github.com/gorilla/mux"

	"net/http"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	request "github.com/dgrijalva/jwt-go/request"
)

//To Validate Authorization Token
//Get accountID from the token [from claims["jti"]]
//Get the token from the header and validate it with token.Valid and check it in redis with expiry time
func RequireTokenAuthentication(rw http.ResponseWriter, req *http.Request, method string, next http.HandlerFunc) {
	response := json.New()
	// log.Info("Inside RequireTokenAuthentication")
	if req.Header.Get("Authorization") != "" {
		//Decode the token and get the accountID
		if authUser, err := DoTokenDecode(req.Header.Get("Authorization")); err == nil {
			//Validate the token
			DoValidateToken(rw, req, authUser, method, next)
		} else {
			if err != nil {
				log.Errorln("Failed while decoding JWT token: ", err.Error())
			} else {
				// log.Println("AccountID in Token: ", authUser.AccountID)
				log.Error("AccountID in the request is mismatched with JWT Token")
			}
			response.Put("reason", "Unauthorized")
			rw.WriteHeader(http.StatusForbidden)
			rw.Write([]byte(response.ToString()))
		}
	} else {
		log.Errorln("Request header does not contain auth token ")
		response.Put("reason", "Request header does not contain auth token")
		rw.WriteHeader(http.StatusForbidden)
		rw.Write([]byte(response.ToString()))
	}
}

//To Validate The Redis Token
func DoValidateToken(rw http.ResponseWriter, req *http.Request, authUser AuthUser, method string, next http.HandlerFunc) {
	response := json.New()
	var projects []string
	vars := mux.Vars(req)
	url := directory.GetURL("project", authUser.AccountID, "", "")
	// fmt.Println(url)
	responses, _ := misc.Get(url)
	jsons.Unmarshal([]byte(responses), &projects)
	var avail bool
	for _, project := range projects {
		if project == vars["ProjectID"] {
			avail = true
		}
	}
	if avail == false {
		log.Error("project not found:", vars["ProjectID"])
		response.Put("reason", "the project "+vars["ProjectID"]+" not found")
		rw.WriteHeader(http.StatusForbidden)
		rw.Write([]byte(response.ToString()))
		return
	}
	// var method string
	// method = GetRequestType()
	authBackend := InitJWTAuthenticationBackend()
	// fmt.Println("--------reqMethod----------", req.Method)
	// var extractor request.Extractor = request.AuthorizationHeaderExtractor
	service := "domain"

	split := strings.Split(req.Header.Get("Authorization"), " ")
	// fmt.Println("Autherization header type[token/Bearer]", split[0])
	//fmt.Println(token.Raw)
	//fmt.Println(token.Valid, err, token.Raw)
	var acl AClArray
	var user User

	if split[0] == "token" {
		token, err := jwt.Parse(split[1], func(token *jwt.Token) (interface{}, error) {
			return authBackend.PublicKey, nil
		})
		if err != nil {
			log.Errorln("Unauthorized Access:", err)
			response.Put("reason", "Unauthorized")
			rw.WriteHeader(http.StatusForbidden)
			rw.Write([]byte(response.ToString()))
			return
		}
		// fmt.Println(token.Valid, err)
		if err == nil && token.Valid {
			//fmt.Println("in")
			tokenFromRedis := authBackend.ReadValueFromRedis(token.Raw)
			if tokenFromRedis == "Found" {
				// fmt.Println("found in redis[middleware]")
				sec := map[string]interface{}{}
				if err := jsons.Unmarshal([]byte(authUser.Subject), &sec); err != nil {
					panic(err)
				}

				url := directory.GetURL("aclProject", authUser.AccountID, sec["userID"].(string), vars["ProjectID"])
				// fmt.Println(url)
				responses, err := misc.Get(url)
				// fmt.Println("project acl response ====>>>", string(responses))
				var pusers ProjectUsers
				err = jsons.Unmarshal([]byte(responses), &pusers)
				var projectPerminssion bool
				for _, userid := range pusers.Users {
					if userid == sec["userID"].(string) {
						projectPerminssion = true
					}
				}
				if !projectPerminssion {
					log.Errorln("Unauthorized Access for project:", vars["ProjectID"])
					response.Put("reason", "Unauthorized Access for project "+vars["ProjectID"])
					rw.WriteHeader(http.StatusForbidden)
					rw.Write([]byte(response.ToString()))
				} else {
					url = directory.GetURL("acl", authUser.AccountID, sec["userID"].(string), vars["ProjectID"])
					// fmt.Println(url)
					responses, err = misc.Get(url)
					err = jsons.Unmarshal([]byte(responses), &acl)
					flag := 0
					for _, i := range acl.UserACL {
						if err != nil || len(i.Svid) == 0 {
							log.Errorln(err)
							return
						}
						for _, j := range i.Ruleset.Service {
							if j.Services == service || j.Services == "all" {
								for _, i := range j.Permissions {
									if i == method || i == "All" {
										log.Errorln(i, method)
										flag = 1
										next(rw, req)
									}
								}
							}
						}
						if flag == 1 {
							break
						}
					}

					if flag == 0 {
						log.Errorln("Unauthorized Access for: ", method)
						response.Put("reason", "Unauthorized Access for "+method)
						rw.WriteHeader(http.StatusForbidden)
						rw.Write([]byte(response.ToString()))
						//next(rw, req)
					}
				}
			} else if tokenFromRedis == "NotFound" {
				vars := mux.Vars(req)
				// fmt.Println("not found in redis")
				sec := map[string]interface{}{}
				if err := jsons.Unmarshal([]byte(authUser.Subject), &sec); err != nil {
					panic(err)
				}
				url := directory.GetURL("nonrootuser", authUser.AccountID, sec["userID"].(string), vars["ProjectID"])
				log.Errorln(url)
				responses, err := misc.Get(url)
				if err != nil {
					//fmt.Println(err)
					log.Errorln("Unauthorized Access", err)
					response.Put("reason", "Unauthorized")
					rw.WriteHeader(http.StatusForbidden)
					rw.Write([]byte(response.ToString()))
					return
				}
				err = jsons.Unmarshal([]byte(responses), &user)
				if err != nil || len(user.ID) == 0 {
					log.Errorln("Unauthorized Access", err)
					response.Put("reason", "Unauthorized")
					rw.WriteHeader(http.StatusForbidden)
					rw.Write([]byte(response.ToString()))
					return
				}
				flag := 0
				for _, i := range user.APITokens {
					// fmt.Println(i.Token == split[1])
					if i.Token == split[1] {
						flag = 1
					}
				}
				if flag == 0 {
					log.Errorln("Unauthorized Access : unknown token")
					response.Put("reason", "Unauthorized Access : unknown token")
					rw.WriteHeader(http.StatusForbidden)
					rw.Write([]byte(response.ToString()))
					return
				}
				tokenRequest, tokenReqErr := jwt.Parse(token.Raw, func(token *jwt.Token) (interface{}, error) {
					return authBackend.PublicKey, nil
				})
				if tokenReqErr != nil {
					log.Errorln("Failed on Parsing JWT token Request:", tokenReqErr.Error())
				}
				redisErr := authBackend.SetValueInRedis(token.Raw, tokenRequest)
				if redisErr != nil {
					log.Errorln("Failed on Parsing JWT token Request:", redisErr.Error())
				}
				// fmt.Println("------token added----")
				url = directory.GetURL("acl", authUser.AccountID, sec["userID"].(string), vars["ProjectID"])
				// fmt.Println("--------- ACL URL -------", url)
				responses, err = misc.Get(url)
				err = jsons.Unmarshal([]byte(responses), &acl)
				//fmt.Println(sec)
				flag = 0
				for _, i := range acl.UserACL {
					if err != nil || len(i.Svid) == 0 {
						log.Errorln(err)
						return
					}
					for _, j := range i.Ruleset.Service {
						if j.Services == service || j.Services == "all" {
							for _, i := range j.Permissions {
								if i == method || i == "All" {
									log.Errorln(i, method)
									flag = 1
									next(rw, req)
								}
							}
						}
					}
					if flag == 1 {
						break
					}
				}

				if flag == 0 {
					log.Errorln("Unauthorized Access", token.Valid)
					response.Put("reason", "Unauthorized Access for "+method)
					rw.WriteHeader(http.StatusForbidden)
					rw.Write([]byte(response.ToString()))
					return
				}
				// fmt.Println(req.Method)
			} else if tokenFromRedis == "ErrorInConnection" {
				log.Errorln("Error While Reading Token from Redis")
				response.Put("reason", "Error While Reading Token from Redis")
				rw.WriteHeader(http.StatusInternalServerError)
				rw.Write([]byte(response.ToString()))
			}
		} else {
			log.Errorln("Unauthorized Access", err)
			response.Put("reason", "Unauthorized")
			rw.WriteHeader(http.StatusForbidden)
			rw.Write([]byte(response.ToString()))
		}
	} else { //if split[0] == "Bearer"
		token, err := request.ParseFromRequest(req, request.AuthorizationHeaderExtractor, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
			} else {
				return authBackend.PublicKey, nil
			}
		})
		tokenFromRedis := authBackend.ReadValueFromRedis(token.Raw)
		if err == nil && token.Valid && tokenFromRedis == "Found" {
			sec := map[string]interface{}{}
			//fmt.Println("authUser.Subject in bearer ====> ", authUser.Subject)

			if authUser.Subject != "" {
				if err := jsons.Unmarshal([]byte(authUser.Subject), &sec); err != nil {
					panic(err)
				}
			}
			//sec["userID"] = nil
			if sec["userID"] != nil {
				vars := mux.Vars(req)
				url := directory.GetURL("aclProject", authUser.AccountID, sec["userID"].(string), vars["ProjectID"])
				// fmt.Println(url)
				responses, _ := misc.Get(url)
				// fmt.Println("project acl response ====>>>", string(responses))
				var pusers ProjectUsers
				err = jsons.Unmarshal([]byte(responses), &pusers)
				var projectPerminssion bool
				for _, userid := range pusers.Users {
					if userid == sec["userID"].(string) {
						projectPerminssion = true
					}
				}
				if !projectPerminssion {
					log.Errorln("Unauthorized Access for project ", vars["ProjectID"])
					response.Put("reason", "Unauthorized Access for project "+vars["ProjectID"])
					rw.WriteHeader(http.StatusForbidden)
					rw.Write([]byte(response.ToString()))
				} else {
					url := directory.GetURL("acl", authUser.AccountID, sec["userID"].(string), vars["ProjectID"])
					// fmt.Println(url)
					responses, err := misc.Get(url)
					err = jsons.Unmarshal([]byte(responses), &acl)

					flag := 0
					for _, i := range acl.UserACL {
						if err != nil || len(i.Svid) == 0 {
							log.Errorln(err)
							return
						}
						for _, j := range i.Ruleset.Service {
							if j.Services == service || j.Services == "all" {
								for _, i := range j.Permissions {
									if i == method || i == "All" {
										// fmt.Println(i, method)
										flag = 1
										next(rw, req)
									}
								}
							}
						}
						if flag == 1 {
							break
						}
					}
					if flag == 0 {
						log.Errorln("Unauthorized Access", token.Valid)
						response.Put("reason", "Unauthorized Access for "+method)
						rw.WriteHeader(http.StatusForbidden)
						rw.Write([]byte(response.ToString()))
					}
				}
			} else {
				next(rw, req)
			}
		} else if tokenFromRedis == "ErrorInConnection" {
			log.Errorln("Error While Reading the Token from Redis")
			response.Put("reason", "Error While Reading the Token from Redis")
			rw.WriteHeader(http.StatusInternalServerError)
			rw.Write([]byte(response.ToString()))
		} else {
			log.Errorln("Unauthorized Access", token.Valid)
			response.Put("reason", "Unauthorized")
			rw.WriteHeader(http.StatusForbidden)
			rw.Write([]byte(response.ToString()))
		}
	}
	// else {
	// 	fmt.Println("Unauthorized Access")
	// 	response.Put("reason", "Unauthorized")
	// 	rw.WriteHeader(http.StatusForbidden)
	// 	rw.Write([]byte(response.ToString()))
	// }
}

//Decode Authorization Token, get the accountID and return
//Ex claims value: [middle part of the token]
// {
//    "aud":"sujai.mba2012@gmail.com",
//    "exp":1528874347,
//    "jti":"39376123g6746g48e6gbb8fgbb01893ad630", //accountID
//    "iat":1528870747,
//    "iss":"gopaddle"
// }
func DoTokenDecode(token string) (AuthUser, error) {
	sg := AuthUser{}
	//Split the token and get the middle part (claims) and decode it
	tokenSplit := strings.Split(token, ".")
	if len(tokenSplit) >= 1 {
		payload := tokenSplit[1]
		//fmt.Println("Payload from the token: ", payload)

		data, err := base64.StdEncoding.DecodeString(payload)
		if err != nil {

			//Retrying decoding by adding "=" to the payload
			payload = payload + "="
			if data, err = base64.StdEncoding.DecodeString(payload); err != nil {

				//Retrying decoding by adding "==" to the payload
				payload = payload + "="
				//fmt.Println("Payload from the token: ", payload)
				if data, err = base64.StdEncoding.DecodeString(payload); err != nil {
					log.Errorln("Error in decoding token retry: ", err.Error())
					return sg, err
				}
			}
		}

		//Get the accountID form the claims JSON and return

		claims := string(data[:])
		err = jsons.Unmarshal([]byte(claims), &sg)
		if err != nil {
			log.Errorln(err)
		}
		log.Errorln(" Clims value after decoding the token: ", string(claims))
		//claimsObj := json.ParseString(string(claims))
		timecheck := sg.Exp
		//fmt.Println(sg)
		exptime := timecheck
		now := time.Now().UnixNano() / 1000000000
		if exptime < now {
			log.Errorln(exptime, now)
			//return sg, errors.New("Expired JWT token: " + claimsObj.GetString("exp"))
		} else {
			log.Errorln(exptime, now)
		}
		return sg, nil

	} else {
		log.Errorln("Invalid JWT token: ", token)
		return sg, errors.New("Invalid JWT token: " + token)
	}
}
