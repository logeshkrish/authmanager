package authentication

import (
	"net/http"
)

var requestingto string

//GetRequestType is
func GetRequestType() string {
	return requestingto
}

//AddDomain is
func AddDomain(rw http.ResponseWriter, req *http.Request, next http.HandlerFunc) {
	requestingto = "Domain_Create"
	next(rw, req)
}

//ListDomains is
func ListDomains(rw http.ResponseWriter, req *http.Request, next http.HandlerFunc) {
	requestingto = "Domain_List"
	next(rw, req)

}

//ReadDomain is
func ReadDomain(rw http.ResponseWriter, req *http.Request, next http.HandlerFunc) {
	requestingto = "Domain_Read"
	next(rw, req)
}

//UpdateDomain is
func UpdateDomain(rw http.ResponseWriter, req *http.Request, next http.HandlerFunc) {
	requestingto = "Domain_Update"
	next(rw, req)
}

//DeleteDomain is
func DeleteDomain(rw http.ResponseWriter, req *http.Request, next http.HandlerFunc) {
	requestingto = "Domain_Delete"
	next(rw, req)
}
