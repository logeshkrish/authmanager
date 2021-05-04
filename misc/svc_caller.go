package misc

import (
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

//Get is
func Get(url string) ([]byte, error) {
	response, err := http.Get(url)
	if err != nil {
		fmt.Println(err)
		return []byte(""), errors.New("Error in url or response")
	}
	responseData, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Fatal(err)
		return []byte(""), errors.New("Error in response")

	}
	return responseData, err
}
