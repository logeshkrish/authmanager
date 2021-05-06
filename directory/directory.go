package directory

import (
	"fmt"
	//"gopaddle/core/settings"
	cmd "gopaddle/domainmanager/utils/cmd"
	context "gopaddle/domainmanager/utils/context"
	json "gopaddle/domainmanager/utils/json"
	log "gopaddle/domainmanager/utils/log"
	"io/ioutil"
	"os"
	"strings"
)

var envi string

const config = "./config/profiles-%s.json"
const directory = "./config/service_directory-%s.json"
const error_config = "./config/error_config.json"
const api = "./config/internal_api.json"

func Endpoint(svc string, suffix string) string {
	return EndpointWithSSL(svc, suffix, false)
}

func EndpointWithSSL(svc string, suffix string, ssl bool) string {
	//Get host and port if not found default it to localhost , 8769
	var jobj = json.New()
	ep := context.Instance().Get(svc)
	jobj = json.ParseString(ep)
	ep_host := jobj.GetString("host")
	ep_port := jobj.GetString("port")
	ssl_prefix := ""
	if ssl {
		ssl_prefix = "s"
	}
	return fmt.Sprintf("http%s://%s:%s/%s", ssl_prefix, ep_host, ep_port, suffix)
}

func ErrorFmt(scope string, err_name string, v ...interface{}) string {
	if val := ErrorString(scope, err_name); strings.Contains(val, "%") {
		return fmt.Sprintf(val, v...)
	} else {
		return val
	}
}

func ErrorString(scope string, name string) string {
	err_pool := context.Instance().GetJSON("errors")
	j_err := err_pool.GetJSON(scope)
	if value := j_err.GetString(name); value == "" {
		log.Println("WARN : error is empty ", name)
		return "Unknown Error"
	} else {
		return value
	}
}

func LoadConfig(env string) bool {
	var profile = json.New()
	envi = env
	//Reading Configuration file
	file, err := ioutil.ReadFile(fmt.Sprintf(config, env))
	if err != nil {
		log.Fatal("Configuraiton file not found")
		return false
		os.Exit(0)
	}
	// Retrieving Configuration
	data := json.Parse(file)
	e_config, e := ioutil.ReadFile(error_config)
	if e != nil {
		log.Fatal("Error config not found ", e)
		return false
		os.Exit(0)
	}
	j_err := json.Parse(e_config)
	log.Println(j_err.ToString())
	if len(j_err.GetKeyList()) == 0 {
		log.Fatal("Error config not found ")
		os.Exit(0)
	}
	context.Instance().SetJSON("errors", j_err)
	profile = data.GetJSON("mongodb")
	context.Instance().SetObject("db-endpoint", profile.GetAsStringArray("db-endpoint"))
	context.Instance().Set("db-port", profile.GetString("db-port"))
	context.Instance().Set("db-name", profile.GetString("db-name"))
	context.Instance().Set("user-db", profile.GetString("user-db"))
	context.Instance().Set("db-user", profile.GetString("db-user"))
	context.Instance().Set("db-password", profile.GetString("db-password"))

	//RabbitMQ connection details
	profile = data.GetJSON("rabbitmq")
	context.Instance().Set("mq-protocol", profile.GetString("mq-protocol"))
	context.Instance().Set("mq-user", profile.GetString("mq-user"))
	context.Instance().Set("mq-password", profile.GetString("mq-password"))
	context.Instance().Set("mq-ip", profile.GetString("mq-ip"))
	context.Instance().Set("mq-port", profile.GetString("mq-port"))

	context.Instance().Set("env", env)
	fmt.Println("Environment: ", env)

	//Loading the licensse details to the context
	//Support Licensing
	license_config := data.GetJSON("license")
	context.Instance().SetObject("license", license_config)
	license_con := data.GetJSONArray("licenses")
	context.Instance().SetObject("licenses", license_con)
	//To load the endpoints
	endpoints := data.GetJSON("endpoints")
	context.Instance().SetJSON("endpoints", endpoints)
	context.Instance().SetJSON("env_config_data", profile)

	//Get OS
	osFamily, osName, osVersion := cmd.GetOS()
	context.Instance().Set("osFamily", osFamily)
	context.Instance().Set("osName", osName)
	context.Instance().Set("osVersion", osVersion)

	profile = data.GetJSON("redis")
	context.Instance().Set("redis-port", profile.GetString("redis-port"))
	context.Instance().Set("redis-password", profile.GetString("redis-password"))
	context.Instance().Set("redis-endpoint", profile.GetString("redis-endpoint"))

	//context.Instance().SetJSON("jwt_params", data.GetJSON("jwt_params"))
	//loading the jwt_params key path in settings file
	//fmt.Println("----json-----\n", context.Instance().GetJSON("jwt_params"))
	//settings.LoadSettingsByEnv("jwt_params")

	fmt.Printf("%s/%s\n", context.Instance().Get("db-ip"), context.Instance().Get("db-name"))
	return true
}

func LoadDirectory(env string) bool {
	var config = json.New()
	//Reading Configuration file
	file, err := ioutil.ReadFile(fmt.Sprintf(directory, env))
	if err != nil {
		log.Fatal("Configuraiton file not found")
		return false
		os.Exit(0)
	}
	// Saving Configuration
	config = json.Parse(file)
	key_list := config.GetKeyList()
	for _, key := range key_list {
		profile := config.GetJSON(key)
		context.Instance().Set(key, profile.ToString())
		fmt.Printf("%s:%s\n", key, context.Instance().Get(key))
	}
	return true
}

//GetURL is
func GetURL(collection string, accID string, id string, projectID string) string {
	file, err := ioutil.ReadFile(api)
	if err != nil {
		log.Printf(" %s Configuraiton file not found: %v", api, err)
		return "false"
	}
	// Retrieving Configuration
	var profile = json.New()
	data := json.Parse(file)
	//fmt.Print(data)
	profile = data.GetJSON(collection)
	file, err = ioutil.ReadFile(fmt.Sprintf(config, envi))
	if err != nil {
		log.Fatalf("Configuraiton '%s' file not found", fmt.Sprintf(config, envi))
		return "false"
	}

	//Read Service-Directory file
	directoryFile, err := ioutil.ReadFile(fmt.Sprintf(directory, envi))
	if err != nil {
		log.Fatalf("Configuraiton '%s' file not found", fmt.Sprintf(directory, envi))
		return "false"
	}
	// get usermanager endpoint from Service-Directory file Configuration
	var directoryProfile = json.New()
	directoryData := json.Parse(directoryFile)
	fmt.Println("env ===> ", envi)
	// fmt.Println("directoryData ===> ", directoryData)
	directoryProfile = directoryData.GetJSON("usermanager.ep")
	endpoint := directoryProfile.GetString("host")
	fmt.Println("ACL endpoint ====> ", endpoint)

	url := fmt.Sprintf(profile.GetString("url"), endpoint, directoryProfile.GetString("port"), accID, id, projectID)
	fmt.Println("ACL url from domain manager ==> ", url)
	return url
}

//GetURL is
func GetProjectACLURL(collection string, accID string, id string, projectID string) string {
	file, err := ioutil.ReadFile(api)
	if err != nil {
		log.Printf(" %s Configuraiton file not found: %v", api, err)
		return "false"
	}
	// Retrieving Configuration
	var profile = json.New()
	data := json.Parse(file)
	//fmt.Print(data)
	profile = data.GetJSON(collection)
	file, err = ioutil.ReadFile(fmt.Sprintf(config, envi))
	if err != nil {
		log.Fatalf("Configuraiton '%s' file not found", fmt.Sprintf(config, envi))
		return "false"
	}

	//Read Service-Directory file
	directoryFile, err := ioutil.ReadFile(fmt.Sprintf(directory, envi))
	if err != nil {
		log.Fatalf("Configuraiton '%s' file not found", fmt.Sprintf(directory, envi))
		return "false"
	}
	// get usermanager endpoint from Service-Directory file Configuration
	var directoryProfile = json.New()
	directoryData := json.Parse(directoryFile)
	fmt.Println("env ===> ", envi)
	// fmt.Println("directoryData ===> ", directoryData)
	directoryProfile = directoryData.GetJSON("usermanager.ep")
	endpoint := directoryProfile.GetString("host")
	fmt.Println("ACL endpoint ====> ", endpoint)

	url := fmt.Sprintf(profile.GetString("url"), endpoint, directoryProfile.GetString("port"), accID, projectID)
	fmt.Println("ACL url from domain manager ==> ", url)
	return url
}
