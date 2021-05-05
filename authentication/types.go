package authentication

import (
	"github.com/hhkbp2/go-logging"
)

var log logging.Logger

type HttpResponse struct {
	//Http response code
	Code int

	//Http response string
	Response string
}

//AuthUser is
type AuthUser struct {
	Email     string `json:"aud,omitempty"`
	Exp       int64  `json:"exp,omitempty"`
	AccountID string `json:"jti,omitempty"`
	IAT       int64  `json:"iat,omitempty"`
	//UserID    string `json:"userID,omitempty"`
	ISS     string `json:"iss,omitempty"`
	Subject string `json:"sub,omitempty"`
}
type Payload struct {
	User User `bson:"User,omitempty" json:"User,omitempty"`
	ACL  ACL  `bson:"ACL,omitempty" json:"ACL,omitempty"`
}

//User is
type User struct {
	ID        string     `bson:"id,omitempty" json:"id,omitempty"`
	Name      string     `bson:"userName,omitempty" json:"userName,omitempty"`
	APITokens []APIToken `bson:"apiTokens,omitempty" json:"apiTokens,omitempty"`
	UserACL   []UserACL  `bson:"acl,omitempty" json:"acl,omitempty"`
}

//UserACL is
type UserACL struct {
	Svid   string `bson:"aclID,omitempty" json:"aclID,omitempty"`
	Svname string `bson:"aclName,omitempty" json:"aclName,omitempty"`
}

//APIToken os
type APIToken struct {
	Name  string `bson:"name,omitempty" json:"name,omitempty"`
	Token string `bson:"apiToken,omitempty" json:"apiToken,omitempty"`
}

//AClArray -
type AClArray struct {
	UserACL []ACL `bson:"acl,omitempty" json:"acl,omitempty"`
}

//ACL is
type ACL struct {
	Svid    string  `bson:"id,omitempty" json:"id,omitempty"`
	Svname  string  `bson:"name,omitempty" json:"name,omitempty"`
	Ruleset Ruleset `bson:"ruleSets,omitempty" json:"ruleSets,omitempty"`
}

//Ruleset is
type Ruleset struct {
	Service []Service `bson:"services,omitempty" json:"services,omitempty"`
}

//Service is
type Service struct {
	Services    string   `bson:"service,omitempty" json:"service,omitempty"`
	Permissions []string `bson:"permissions,omitempty" json:"permissions,omitempty"`
}
type ProjectUsers struct {
	Users []string `bson:"users,omitempty" json:"users,omitempty"`
}
