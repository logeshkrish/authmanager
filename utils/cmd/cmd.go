package cmd

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"

	log "github.com/bluemeric/authmanager/utils/log"
	"github.com/pborman/uuid"
)

/*

Command from the Template Engine

<cmd[n]>.<linux>.<name>.<version>

<linux>=`cmd1 ls
		 cmm2 mkdir ps`

*/

var Scripts = getBaseScripts()

var linuxScript = `cwd=readlink /proc/%s/cwd
cmd=cat -A /proc/%s/cmdline
exe=readlink /proc/%s/exe
net=lsof -P -p %s -n | grep IPv
net.once=lsof -P -i  | grep LISTEN
link=lsof -P -i :%s -sTCP:LISTEN
service=lsof -i -sTCP:LISTEN`

func CheckAgentCompatibility() bool {
	if os_family, _, _ := GetOS(); strings.Contains(strings.ToLower(os_family), "linux") {
		return true
	} else if strings.Contains(strings.ToLower(os_family), "windows") {
		return false
	} else if strings.Contains(strings.ToLower(os_family), "darwin") {
		return false
	}
	return false
}

func StringToFile(script string) string {
	var fname = fmt.Sprintf("/tmp/%s.sh", uuid.New())
	ioutil.WriteFile(fname, []byte(script), 0755)
	return fname
}

func ExecuteAsScript(cmd string, param ...string) string {
	fname := StringToFile(cmd)
	params := append([]string{fname}, param...)
	ps := exec.Command("bash", params...)
	data, _ := ps.Output()
	os.Remove(fname)
	return string(data)
}

func ExecuteAsScriptWithError(cmd string, param ...string) (string, string, error) {
	fname := StringToFile(cmd)
	params := append([]string{fname}, param...)
	ps := exec.Command("bash", params...)

	var outb, errb bytes.Buffer
	ps.Stdout = &outb
	ps.Stderr = &errb

	err := ps.Run()
	os.Remove(fname)
	return strings.TrimSpace(outb.String()), strings.TrimSpace(errb.String()), err
}

//Write file
func WriteFile(accID, path, file string, resFile []byte) error {
	if path != "" {
		if errFile := os.MkdirAll(path, 0777); errFile != nil { //Create the folder in name of uuid
			log.Errorln(accID+" Error: ", errFile)
			return errFile
		}
	}
	if errWrite := ioutil.WriteFile(file, resFile, 0644); errWrite != nil {
		return errWrite
	} else {
		return nil
	}
}

func GetOS() (string, string, string) {
	var os_family, os_name, os_ver = "NA", "NA", "NA"
	os := runtime.GOOS
	os_family = os
	if strings.Contains(strings.ToLower(os), "linux") {
		pname := ExecuteAsScript("cat /etc/*-release | egrep \"PRETTY_NAME=\" | cut -d \"=\" -f 2")
		if pname == "" {
			pname = ExecuteAsScript("cat /etc/*-release | uniq")
		}
		regex, _ := regexp.Compile("([0-9]+)\\.?([0-9]*)\\.?([0-9]*)")
		if ver := regex.FindStringSubmatch(pname); len(ver) > 0 {
			os_ver = ver[0]
		}
		if os_det := strings.Split(pname, " "); len(os_det) >= 2 {
			os_name = os_det[0]
			os_name = strings.Replace(os_name, "\"", "", -1)
			//os_ver = os_det[1]
		} else {
			log.Println("Un-Supported OS")
		}
	} else if strings.Contains(strings.ToLower(os), "windows") {
		log.Println("Found Window and Un-Supported")
	} else if strings.Contains(strings.ToLower(os), "darwin") {
		os_name = strings.TrimSpace(ExecuteAsScript("sw_vers -productName"))
		os_ver = strings.TrimSpace(ExecuteAsScript("sw_vers -productVersion"))
		log.Println("Found MacOS and Un-Supported")
	} else {
		log.Println("Type \"main -help\" for help")
	}
	return os_family, os_name, os_ver
}

func GetScript(name string) string {
	//Script cant be empty
	return Scripts[name]
}

func GetScriptf(name string, v ...interface{}) string {
	return fmt.Sprintf(Scripts[name], v...)
}

func GetConfigFile() string {
	return "/etc/mobilizer/agent.conf"
}

func getBaseScripts() map[string]string {
	// log.Printf("Loading Base Scripts for Agent [%s.(%s).(%s)]......", os_family, os_name, os_ver)
	var script string
	if os_family, _, _ := GetOS(); strings.Contains(os_family, "linux") || strings.Contains(os_family, "darwin") {
		script = linuxScript
	}
	return getScripts(script)
}

func getScripts(script string) map[string]string {
	cmd_list := strings.Split(script, "\n")
	m := make(map[string]string)
	for i := 0; i < len(cmd_list); i++ {
		if cmd_sep := strings.Split(cmd_list[i], "="); len(cmd_sep) > 1 {
			key := strings.ToLower(cmd_sep[0])
			cmd := cmd_sep[1]
			m[key] = cmd
		} else {
			log.Println("Unknown Script", cmd_list[i])
		}
	}
	return m
}
