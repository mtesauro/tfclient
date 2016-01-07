// Package tfclient is a library for interacting with the ThreadFix REST API
package tfclient

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"
)

// Name of the config file to hold things like TF url and TF's API key
var configFile string = "tfclient.config"
var apikey string = ""
var tf_url string = ""

// Use to format App Struct's scan.TimeStamp like t := tStamp.Format(shortDate)
// which displays dates as 2013-11-18
const shortDate = "2006-01-02"

func CreateClient() (*http.Client, error) {
	// TODO -  Add a parameter/config value to turn off/on SSL verification
	//        and default to on

	// Read the config file
	_, err := readConfig()
	if err != nil {
		msg := fmt.Sprintf("Problem reading config file\n%s\n", err)
		return nil, errors.New(msg)
	}

	// Create a custom transport so we can turn off SSL verification
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	tfClient := &http.Client{Transport: tr}

	return tfClient, nil
}

func CreateEmptyConfig() error {
	// Create an empty config file in the current working directory as an example
	conf := "./" + configFile

	// Double check that client config doesn't already exist
	_, err := readConfig()
	if err == nil {
		// There is a config already, why have you asked to create one
		msg := fmt.Sprintln("WARN: config file already exists, no need to create one.")
		return errors.New(msg)
	}

	// Create a default config file
	defaultConfig := "# Default tfclient.config file\n"
	defaultConfig += "# please put the values for your ThreadFix installation below\n"
	defaultConfig += "# as these are simple place holders\n"
	defaultConfig += "# NOTE: ThreadFix's REST API URL ends in /rest\n"
	defaultConfig += "tf_url=\"https://localhost:8443/threadfix/rest\"\n"
	defaultConfig += "apikey=\"YourAPIKeyHere\"\n"

	// Write a default config
	fileBytes := []byte(defaultConfig)
	err = ioutil.WriteFile(conf, fileBytes, 0600)
	if err != nil {
		fmt.Println("Unable to write config file")
		fmt.Printf("Please check permissions of %s\n", conf)
		os.Exit(1)
	}

	return nil
}

func readConfig() (bool, error) {
	// Setup an array of configuration locations
	pwd := "./" + configFile
	home := os.Getenv("HOME") + "/.tfclient/" + configFile
	sys := "/etc/tfclient/" + configFile
	locs := [3]string{pwd, home, sys}
	found := false

	// Cycle through the locations, trying to load a config file
	var config = ""
	for _, loc := range locs {
		_, err := os.Stat(loc)
		if err == nil {
			// Config file has been found
			found = true
			config = loc

			//break out of this loop
			break
		}
	}

	if found {
		// Read configuration file to pull out any configured items
		file, err := os.Open(config)
		if err != nil {
			msg := fmt.Sprintf("  Unable to open config file at %s\n  Error message was: %s\n", config, err.Error())
			return found, errors.New(msg)
		}
		defer file.Close()

		reader := bufio.NewReader(file)
		line, err := reader.ReadString('\n')
		for err == nil {
			// Handle lines that are not comments
			if strings.Index(line, "#") != 0 {
				line = strings.Trim(line, " ")

				// Pull out the config values
				if strings.Contains(line, "tf_url=") {
					setConfigVal("tf_url", line)
				}

				if strings.Contains(line, "apikey=") {
					setConfigVal("apikey", line)
				}
			}

			line, err = reader.ReadString('\n')
		}

		return found, nil
	}

	if !found {
		msg := fmt.Sprintf("  Unable to find config file\n\t at %s\n\t or %s\n\t or %s\n", locs[0], locs[1], locs[2])
		return found, errors.New(msg)
	}

	return found, errors.New("Unknown error")
}

func setConfigVal(val string, l string) {
	// Set the config variable base on val in the line 1
	// Config values are expected to be of the form foo="bar"
	switch val {
	case "tf_url":
		v := strings.SplitAfterN(l, "=", 2)
		tf_url = strings.Replace(strings.TrimSpace(v[1]), "\"", "", -1)
	case "apikey":
		v := strings.SplitAfterN(l, "=", 2)
		apikey = strings.Replace(strings.TrimSpace(v[1]), "\"", "", -1)
	}
}

// Helper Functions

func makeRequest(c *http.Client, m string, u string, b io.Reader) (string, error) {
	// Create a request to customize then send
	req, err := http.NewRequest(m, u, b)
	if err != nil {
		msg := fmt.Sprintf("  Error creating new http request: %s\n", err)
		return "", errors.New(msg)
	}

	// Add headers as needed
	req.Header.Add("Accept", "application/json")
	// Content-Type: application/x-www-form-urlencoded
	if b != nil {
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	}

	// Make the request
	resp, err := c.Do(req)
	if err != nil {
		msg := fmt.Sprintf("  Error making the http request: %s\n", err)
		return "", errors.New(msg)
	}

	//Read back the JSON response
	jsonResp, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		msg := fmt.Sprintf("  Error message was: %s\n", err)
		return "", errors.New(msg)
	}

	return string(jsonResp[:]), nil
}

func getFrameworkTypes() [4]string {
	var frmwrkTypes = [4]string{"NONE", "DETECT", "JSP", "SPRING_MVC"}

	return frmwrkTypes
}

func stringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

func getWafTypes() [5]string {
	var wafTypes = [5]string{"mod_security", "Snort", "Imperva SecureSphere",
		"F5 BigIP ASM", "DenyAll rWeb"}

	return wafTypes
}

func prepScanFile(uri string, paramName string, path string) (*http.Request, string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, "", err
	}
	defer file.Close()

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile(paramName, filepath.Base(path))
	if err != nil {
		return nil, "", err
	}
	_, err = io.Copy(part, file)

	err = writer.Close()
	if err != nil {
		return nil, "", err
	}

	// Prep the values required for the return
	header := writer.FormDataContentType()
	req, _ := http.NewRequest("POST", uri, body)

	return req, header, err
}

// Search helper calls

func ShowInSearch(s *Search, show string) {
	// Set the appropriate parameter to true
	switch strings.ToLower(show) {
	case "hidden":
		s.ReqPara["showHidden"] = "true"
	case "false":
		s.ReqPara["showFalsePositive"] = "true"
	case "falsepositive":
		s.ReqPara["showFalsePositive"] = "true"
	case "closed":
		s.ReqPara["showClosed"] = "true"
	case "open":
		s.ReqPara["showOpen"] = "true"
	}

	// TODO -  Add a default case and return an error if show
	// doesn't match any of the cases

}

func NumSearchResults(s *Search, n int) {
	// Set the Number of vulnerabilities to return
	s.SingleParas.NumVulns["value"] = strconv.Itoa(n)
}

func ParamSearch(s *Search, p string) {
	// Set the parameter to search for
	s.SingleParas.Param["value"] = p
}

func PathSearch(s *Search, p string) {
	// Set the path to search for
	s.SingleParas.Path["value"] = p
}

func StartSearch(s *Search, str string) {
	// Parse the string into a Go time struct
	// expecting date as mm/dd/yyyy
	t, _ := time.Parse("01/02/2006", str)
	// TODO - catch this error and try other formats

	// Convert string to miliseconds since the Unix Epoch as expected by Java
	// and the ThreadFix API
	s.SingleParas.Start["value"] = strconv.FormatInt((t.UnixNano() / 1000000), 10)
}

func EndSearch(s *Search, str string) {
	// Parse the string into a Go time struct
	// expecting date as mm/dd/yyyy
	t, _ := time.Parse("01/02/2006", str)
	// ToDo: catch this error and try other formats

	// Convert string to miliseconds since the Unix Epoch as expected by Java
	// and the ThreadFix API
	s.SingleParas.End["value"] = strconv.FormatInt((t.UnixNano() / 1000000), 10)
}

func NumMergedSearch(s *Search, n int) {
	// Set the Number of vulnerabilities to return
	s.SingleParas.NumMerged["value"] = strconv.Itoa(n)
}

func TeamIdSearch(s *Search, t ...int) {
	// Create a comma seperated list for the teams value
	var val string
	for i, _ := range t {
		val = val + "," + strconv.Itoa(t[i])
	}

	// Set Teams search by slicing off the initial comma
	s.MultiParas.Teams["value"] = val[1:]
}

func AppIdSearch(s *Search, a ...int) {
	// Create a comman seperated list for the apps value
	var val string
	for i, _ := range a {
		val = val + "," + strconv.Itoa(a[i])
	}

	// Set Apps search by slicing off the initial comma
	s.MultiParas.Apps["value"] = val[1:]
}

func CweIdSearch(s *Search, c ...int) {
	// Create a comman seperated list for the cwe value
	var val string
	for i, _ := range c {
		val = val + "," + strconv.Itoa(c[i])
	}

	// Set CWE search by slicing off the initial comma
	s.MultiParas.Cwe["value"] = val[1:]
}

func ScannerSearch(s *Search, sc ...string) {
	// Create a comman seperated list of scanners
	var val string
	for i, _ := range sc {
		val = val + "," + sc[i]
	}

	// Set CWE search by slicing off the initial comma
	s.MultiParas.Scanner["value"] = val[1:]
}

func SeveritySearch(s *Search, sev ...int) {
	// Severity values are sent as
	// 1 = Info, 2 = Low, 3 = Medium, 4 = High, 5 = Critical

	// Create a comman seperated list for the severity value
	var val string
	for i, _ := range sev {
		val = val + "," + strconv.Itoa(sev[i])
	}

	// Set severity search by slicing off the initial comma
	s.MultiParas.Severity["value"] = val[1:]
}

// Team API calls

func CreateTeam(c *http.Client, name string) (string, error) {
	// Set URL for this API call
	u := tf_url + "/teams/new?apiKey=" + apikey

	// Prep data to be POST'ed and make request
	var postStr = []byte("name=" + url.QueryEscape(name))
	jsonResp, err := makeRequest(c, "POST", u, bytes.NewBuffer(postStr))
	if err != nil {
		msg := fmt.Sprintf("  Error calling CreateTeam API\n%s", err)
		return "", errors.New(msg)
	}

	return jsonResp, nil
}

func GetTeams(c *http.Client) (string, error) {
	// Set URL for this API call
	u := tf_url + "/teams?apiKey=" + apikey

	// Make the request
	jsonResp, err := makeRequest(c, "GET", u, nil)
	if err != nil {
		msg := fmt.Sprintf("  Error calling GetTeam API\n%s", err)
		return "", errors.New(msg)
	}

	return jsonResp, nil
}

func LookupTeamId(c *http.Client, id int) (string, error) {
	// Set URL for this API call
	u := tf_url + "/teams/" + strconv.Itoa(id) + "?apiKey=" + apikey

	// Make the request
	jsonResp, err := makeRequest(c, "GET", u, nil)
	if err != nil {
		msg := fmt.Sprintf("  Error calling LookupTeamID API\n%s", err)
		return "", errors.New(msg)
	}

	return jsonResp, nil
}

func LookupTeamName(c *http.Client, name string) (string, error) {
	// Set URL for this API call
	u := tf_url + "/teams/lookup?name=" + url.QueryEscape(name) +
		"&apiKey=" + apikey

	// Make the request
	jsonResp, err := makeRequest(c, "GET", u, nil)
	if err != nil {
		msg := fmt.Sprintf("  Error calling LookupTeamName API\n%s", err)
		return "", errors.New(msg)
	}

	return jsonResp, nil
}

// Application API calls

func CreateApplication(c *http.Client, n string, aUrl string, t int) (string, error) {
	// Set URL for this API call
	u := tf_url + "/teams/" + strconv.Itoa(t) + "/applications/new?apiKey=" + apikey

	// Prep data to be POST'ed and make request
	var postStr = []byte("name=" + url.QueryEscape(n) + "&url=" + url.QueryEscape(aUrl))
	jsonResp, err := makeRequest(c, "POST", u, bytes.NewBuffer(postStr))
	if err != nil {
		msg := fmt.Sprintf("  Error calling CreateApplication API\n%s", err)
		return "", errors.New(msg)
	}

	return jsonResp, nil
}

func LookupAppId(c *http.Client, id int) (string, error) {
	// Set URL for this API call
	u := tf_url + "/applications/" + strconv.Itoa(id) + "?apiKey=" + apikey

	// Make the request
	jsonResp, err := makeRequest(c, "GET", u, nil)
	if err != nil {
		msg := fmt.Sprintf("  Error calling LookupAppID API\n%s", err)
		return "", errors.New(msg)
	}

	return jsonResp, nil
}

func LookupAppName(c *http.Client, name string, t string) (string, error) {
	// Set URL for this API call
	u := tf_url + "/applications/" + url.QueryEscape(t) + "/lookup?name=" +
		url.QueryEscape(name) + "&apiKey=" + apikey

	// WORK AROUND
	// Convert + to %20 to work around a bug in TF which causes lookup failures when
	// "+" is used instead of %20 when URL encoding.  Go defaults to URL encoding
	// to "+" so these calls are broken but only for Lookup Applicaiton by name
	// as this work around is not needed for Lookup Team by name
	u = strings.Replace(u, "+", "%20", -1)

	// Make the request
	jsonResp, err := makeRequest(c, "GET", u, nil)
	if err != nil {
		msg := fmt.Sprintf("  Error calling LookupAppName API\n%s", err)
		return "", errors.New(msg)
	}

	return jsonResp, nil
}

func SetAppParams(c *http.Client, appId int, frmwrk string, rUrl string) (string, error) {
	// Set URL for this API call
	u := tf_url + "/applications/" + strconv.Itoa(appId) +
		"/setParameters?apiKey=" + apikey

	// Check that framework is among the supported frameworks
	fTypes := getFrameworkTypes()
	if !(stringInSlice(frmwrk, fTypes[:])) {
		// Thow an error when invalid framework type is used
		msg := fmt.Sprintf("Invalid Framework type used when setting App parameters\n  Valid frameworks are %v+\n", fTypes)
		return "", errors.New(msg)
	}

	// Prep data to be POST'ed and make request
	var postStr = []byte("framework=" + url.QueryEscape(frmwrk) +
		"&repositoryUrl=" + url.QueryEscape(rUrl))
	jsonResp, err := makeRequest(c, "POST", u, bytes.NewBuffer(postStr))
	if err != nil {
		msg := fmt.Sprintf("  Error calling SetAppParams API\n%s", err)
		return "", errors.New(msg)
	}

	return jsonResp, nil
}

func SetWaf(c *http.Client, appId int, wafId int) (string, error) {
	//Set URL for this API call
	u := tf_url + "/applications/" + strconv.Itoa(appId) + "/setWaf?wafId=" +
		strconv.Itoa(wafId) + "&apiKey=" + apikey

	// Oddly, this is an empty post so send nil insteall of a buffer
	jsonResp, err := makeRequest(c, "POST", u, nil)
	if err != nil {
		msg := fmt.Sprintf("  Error calling SetWAF API\n%s", err)
		return "", errors.New(msg)
	}

	return jsonResp, nil
}

func SetUrl(c *http.Client, appId int, aUrl string) (string, error) {
	//Set URL for this API call
	u := tf_url + "/applications/" + strconv.Itoa(appId) +
		"/addUrl?apiKey=" + apikey

	var postStr = []byte("url=" + url.QueryEscape(aUrl))
	jsonResp, err := makeRequest(c, "POST", u, bytes.NewBuffer(postStr))
	if err != nil {
		msg := fmt.Sprintf("  Error calling SetAppParams API\n%s", err)
		return "", errors.New(msg)
	}

	return jsonResp, nil
}

func ScanUpload(c *http.Client, appId int, path string) (string, error) {
	//Set URL for this API call
	u := tf_url + "/applications/" + strconv.Itoa(appId) + "/upload?apiKey=" + apikey

	// Convert the file into a multipart HTTP POST body
	request, header, err := prepScanFile(u, "file", path)
	if err != nil {
		msg := fmt.Sprintf("  Error converting file to multipart post\n%s", err)
		return "", errors.New(msg)
	}
	request.Header.Add("Content-Type", header)
	request.Header.Del("Accept-Encoding")

	resp, err := c.Do(request)
	if err != nil {
		msg := fmt.Sprintf("  Error uploading scan file\n%s", err)
		return "", errors.New(msg)
	}

	//Read back the JSON response
	jsonResp, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		msg := fmt.Sprintf("  Error reading upload response\n%s", err)
		return "", errors.New(msg)
	}

	return string(jsonResp[:]), nil
}

// WAF API calls

func CreateWaf(c *http.Client, n string, wType string) (string, error) {
	// Set URL for this API call
	u := tf_url + "/wafs/new?apiKey=" + apikey

	// Check that framework is among the supported frameworks
	wafTypes := getWafTypes()
	if !(stringInSlice(wType, wafTypes[:])) {
		// Return an err when this happens
		msg := fmt.Sprintf("Invalid WAF type used when creating a WAF\n  Valid WAFs are %v+\n", wafTypes)
		return "", errors.New(msg)
	}

	// Prep data to be POST'ed and make request
	var postStr = []byte("name=" + url.QueryEscape(n) + "&type=" + url.QueryEscape(wType))
	jsonResp, err := makeRequest(c, "POST", u, bytes.NewBuffer(postStr))
	if err != nil {
		msg := fmt.Sprintf("  Error calling CreateWAF API\n%s", err)
		return "", errors.New(msg)
	}

	return jsonResp, nil
}

func LookupWafId(c *http.Client, id int) (string, error) {
	// Set URL for this API call
	u := tf_url + "/wafs/" + strconv.Itoa(id) + "?apiKey=" + apikey

	// Make the request
	jsonResp, err := makeRequest(c, "GET", u, nil)
	if err != nil {
		msg := fmt.Sprintf("  Error calling LookupWAFId API\n%s", err)
		return "", errors.New(msg)
	}

	return jsonResp, nil
}

func LookupWafName(c *http.Client, name string) (string, error) {
	// Set URL for this API call
	u := tf_url + "/wafs/lookup?name=" + url.QueryEscape(name) +
		"&apiKey=" + apikey

	// Make the request
	jsonResp, err := makeRequest(c, "GET", u, nil)
	if err != nil {
		msg := fmt.Sprintf("  Error calling LookupWAFName API\n%s", err)
		return "", errors.New(msg)
	}

	return jsonResp, nil
}

func GetWafs(c *http.Client) (string, error) {
	// Set URL for this API call
	u := tf_url + "/wafs?apiKey=" + apikey

	// Make the request
	jsonResp, err := makeRequest(c, "GET", u, nil)
	if err != nil {
		msg := fmt.Sprintf("  Error calling GetWAFs API\n%s", err)
		return "", errors.New(msg)
	}

	return jsonResp, nil
}

func VulnSearch(c *http.Client, s *Search) (string, error) {
	//Set URL for this API call
	u := tf_url + "/vulnerabilities?apiKey=" + apikey

	// Create the needed POST string
	qry := "&"
	// Required parameters
	for i, v := range s.ReqPara {
		qry = qry + i + "=" + v + "&"
	}

	//Single value parameters
	if len(s.SingleParas.NumVulns["value"]) > 0 {
		qry = qry + s.SingleParas.NumVulns["name"] + "=" +
			s.SingleParas.NumVulns["value"] + "&"
	}
	if len(s.SingleParas.Param["value"]) > 0 {
		qry = qry + s.SingleParas.Param["name"] + "=" +
			url.QueryEscape(s.SingleParas.Param["value"]) + "&"
	}
	if len(s.SingleParas.Path["value"]) > 0 {
		qry = qry + s.SingleParas.Path["name"] + "=" +
			url.QueryEscape(s.SingleParas.Path["value"]) + "&"
	}
	if len(s.SingleParas.Start["value"]) > 0 {
		qry = qry + s.SingleParas.Start["name"] + "=" +
			s.SingleParas.Start["value"] + "&"
	}
	if len(s.SingleParas.End["value"]) > 0 {
		qry = qry + s.SingleParas.End["name"] + "=" +
			s.SingleParas.End["value"] + "&"
	}
	if len(s.SingleParas.NumMerged["value"]) > 0 {
		qry = qry + s.SingleParas.NumMerged["name"] + "=" +
			s.SingleParas.NumMerged["value"] + "&"
	}

	// Handle Multi-value parameters
	// Insert count of multi-parameter Teams search items
	if len(s.MultiParas.Teams["value"]) > 0 {
		vals := strings.Split(s.MultiParas.Teams["value"], ",")
		count := 0

		for _, item := range vals {
			para := strings.Replace(s.MultiParas.Teams["name"], "~", strconv.Itoa(count), 1)
			qry = qry + para + "=" + url.QueryEscape(item) + "&"
			count++
		}
	}

	// Insert count of multi-parameter Apps search items
	if len(s.MultiParas.Apps["value"]) > 0 {
		vals := strings.Split(s.MultiParas.Apps["value"], ",")
		count := 0
		for _, item := range vals {
			para := strings.Replace(s.MultiParas.Apps["name"], "~", strconv.Itoa(count), 1)
			qry = qry + para + "=" + url.QueryEscape(item) + "&"
			count++
		}
	}

	// Insert count of multi-parameter CWE search items
	if len(s.MultiParas.Cwe["value"]) > 0 {
		vals := strings.Split(s.MultiParas.Cwe["value"], ",")
		count := 0
		for _, item := range vals {
			para := strings.Replace(s.MultiParas.Cwe["name"], "~", strconv.Itoa(count), 1)
			qry = qry + para + "=" + url.QueryEscape(item) + "&"
			count++
		}
	}

	// Insert count of multi-parameter scanner search items
	if len(s.MultiParas.Scanner["value"]) > 0 {
		vals := strings.Split(s.MultiParas.Scanner["value"], ",")
		count := 0
		for _, item := range vals {
			para := strings.Replace(s.MultiParas.Scanner["name"], "~", strconv.Itoa(count), 1)
			qry = qry + para + "=" + url.QueryEscape(item) + "&"
			count++
		}
	}

	// Insert count of multi-parameter severity search items
	if len(s.MultiParas.Severity["value"]) > 0 {
		vals := strings.Split(s.MultiParas.Severity["value"], ",")
		count := 0
		for _, item := range vals {
			para := strings.Replace(s.MultiParas.Severity["name"], "~", strconv.Itoa(count), 1)
			qry = qry + para + "=" + url.QueryEscape(item) + "&"
			count++
		}
	}

	// Slice to strip off beginning and ending &
	var postStr = []byte(qry[1:(len(qry) - 1)])
	jsonResp, err := makeRequest(c, "POST", u, bytes.NewBuffer(postStr))
	if err != nil {
		msg := fmt.Sprintf("  Error calling Search API\n%s", err)
		return "", errors.New(msg)
	}

	return jsonResp, nil
}

// Functions to parse JSON into normalized structs

func MakeTeamStruct(t *TeamResp, b string) error {
	// Parse the sent JSON body from the API
	var raw map[string]interface{}
	if err := json.Unmarshal([]byte(b), &raw); err != nil {
		msg := fmt.Sprintf("  Error parsing Search JSON\n%s", err)
		return errors.New(msg)
	}

	// Setup the values in the initial struct
	t.Success = raw["success"].(bool)
	t.RespCode = int(raw["responseCode"].(float64))
	t.Msg = raw["message"].(string)

	// Setup a struct for Team based on the type
	// resulting from unmarshall'ing the JSON
	tType := reflect.TypeOf(raw["object"])
	var obj []interface{}
	if strings.Contains(tType.String(), "map") {
		// Single instance of Team provided
		o := raw["object"].(map[string]interface{})
		obj = []interface{}{o}
	} else {
		// Multiple instances of Team provided
		obj = raw["object"].([]interface{})
	}
	teamSt := make(map[int]Team)
	// Cycle through the object returned from the TF API for this call
	for i, v := range obj {
		// Create a map of Team info
		tm := v.(map[string]interface{})

		// Step into the Applications map
		apps := tm["applications"].([]interface{})
		appSt := make(map[int]AppT)
		for i, v := range apps {
			// Create a map of applications
			app := v.(map[string]interface{})

			// Step into the App Criticality map
			crit := app["applicationCriticality"].(map[string]interface{})
			critSt := AppCrit{
				int(crit["id"].(float64)),
				crit["name"].(string),
			}

			// Make sure App URL is provided to avoid an interface conversion error
			url := ""
			if reflect.TypeOf(app["url"]) != nil {
				// App URL was actually set
				url = app["url"].(string)
			}

			appSt[i] = AppT{
				Id:        int(app["id"].(float64)),
				Name:      app["name"].(string),
				Url:       url,
				CritLevel: critSt,
			}

		}

		teamSt[i] = Team{
			int(tm["id"].(float64)),
			int(tm["infoVulnCount"].(float64)),
			int(tm["lowVulnCount"].(float64)),
			int(tm["mediumVulnCount"].(float64)),
			int(tm["highVulnCount"].(float64)),
			int(tm["criticalVulnCount"].(float64)),
			int(tm["totalVulnCount"].(float64)),
			tm["name"].(string),
			appSt,
		}
	}

	t.Tm = teamSt

	return nil
}

func MakeAppStruct(a *AppResp, b string) error {
	// Parse the sent JSON body from the API
	var raw map[string]interface{}
	if err := json.Unmarshal([]byte(b), &raw); err != nil {
		msg := fmt.Sprintf("  Error parsing Search JSON\n%s", err)
		return errors.New(msg)
	}

	// Setup the values in the initial struct
	a.Success = raw["success"].(bool)
	a.RespCode = int(raw["responseCode"].(float64))
	a.Msg = raw["message"].(string)

	// Error out if success from TF is false as API errored on the request
	// Send back TF's message as the Go error message
	if a.Success == false {
		msg := fmt.Sprintf("  Error from ThreadFix API\n\t  %s", a.Msg)
		return errors.New(msg)
	}

	// Setup a struct for App based on the type
	// resulting from unmarshall'ing the JSON
	tType := reflect.TypeOf(raw["object"])
	var obj []interface{}
	if strings.Contains(tType.String(), "map") {
		// Single instance of Team provided
		o := raw["object"].(map[string]interface{})
		obj = []interface{}{o}
	} else {
		// Multiple instances of Team provided
		obj = raw["object"].([]interface{})
	}
	appSt := make(map[int]App)
	// Cycle through the object returned from the TF API for this call
	for i, v := range obj {
		// Create a map of App info
		app := v.(map[string]interface{})

		// Step into the App Criticality map
		crit := app["applicationCriticality"].(map[string]interface{})
		critSt := AppCrit{
			int(crit["id"].(float64)),
			crit["name"].(string),
		}

		// Step into the Team level map
		team := app["organization"].(map[string]interface{})
		teamSt := TeamA{
			int(team["id"].(float64)),
			team["name"].(string),
		}

		// WAF doesn't have to be set - provide some sane values if nothing was returned
		wafSt := WafA{Id: 0, Name: "None"}
		if reflect.TypeOf(app["waf"]) != nil {
			waf := app["waf"].(map[string]interface{})
			wafSt.Id = int(waf["id"].(float64))
			wafSt.Name = waf["name"].(string)
		}

		// Step into the Scans level map
		scans := app["scans"].([]interface{})
		scansSt := make(map[int]Scan)
		for i, v := range scans {
			scan := v.(map[string]interface{})

			// http://play.golang.org/p/r5kBJHPDUb
			// Convert Mills provided by TF into something useful
			// Note: There is likely a difference based on timezone of the
			// TF server vs local time where this is run
			rawTime := int64(scan["importTime"].(float64))
			tStamp := time.Unix(0, rawTime*int64(time.Millisecond))

			// Create the map of Scans
			scansSt[i] = Scan{
				int(scan["id"].(float64)),
				tStamp,
				int(scan["numberClosedVulnerabilities"].(float64)),
				int(scan["numberNewVulnerabilities"].(float64)),
				int(scan["numberOldVulnerabilities"].(float64)),
				int(scan["numberResurfacedVulnerabilities"].(float64)),
				int(scan["numberTotalVulnerabilities"].(float64)),
				int(scan["numberRepeatResults"].(float64)),
				int(scan["numberRepeatFindings"].(float64)),
				int(scan["numberInfoVulnerabilities"].(float64)),
				int(scan["numberLowVulnerabilities"].(float64)),
				int(scan["numberMediumVulnerabilities"].(float64)),
				int(scan["numberHighVulnerabilities"].(float64)),
				int(scan["numberCriticalVulnerabilities"].(float64)),
				scan["scannerName"].(string),
			}

		}

		// App URL in JSON isn't always set
		appUrl := ""
		if reflect.TypeOf(app["url"]) != nil {
			// App URL was actually set
			appUrl = app["url"].(string)
		}

		// uniqueID in JSON isn't always set
		uniq := ""
		if reflect.TypeOf(app["uniqueId"]) != nil {
			// UniqID was actually set
			uniq = app["uniqueId"].(string)
		}

		// Create a App struct based on the above
		appSt[i] = App{
			int(app["id"].(float64)),
			app["name"].(string),
			appUrl,
			uniq,
			int(app["infoVulnCount"].(float64)),
			int(app["lowVulnCount"].(float64)),
			int(app["mediumVulnCount"].(float64)),
			int(app["highVulnCount"].(float64)),
			int(app["criticalVulnCount"].(float64)),
			int(app["totalVulnCount"].(float64)),
			critSt,
			scansSt,
			teamSt,
			wafSt,
		}

	}

	a.Ap = appSt

	return nil
}

func MakeUploadStruct(u *UpldResp, b string) error {
	// Parse the sent JSON body from the API
	var raw map[string]interface{}
	if err := json.Unmarshal([]byte(b), &raw); err != nil {
		msg := fmt.Sprintf("  Error parsing Upload response JSON.  Error was: %s", err)
		return errors.New(msg)
	}

	// Setup the values in the initial struct
	u.Success = raw["success"].(bool)
	u.RespCode = int(raw["responseCode"].(float64))
	u.Msg = raw["message"].(string)

	// Return early if the upload returns success as false
	if u.Success != true {
		// Create an empty UploadResp struct and return early
		emptySt := make(map[int]UpldInfo)
		u.Upload = emptySt
		msg := fmt.Sprintf("Empty Upload struct - success was false in JSON response from TF")
		return errors.New(msg)
	}

	// Setup a struct for Upld based on the type
	// resulting from unmarshall'ing the JSON
	uType := reflect.TypeOf(raw["object"])
	var obj []interface{}
	if strings.Contains(uType.String(), "map") {
		// Single instance of Upload provided
		o := raw["object"].(map[string]interface{})
		obj = []interface{}{o}
	} else {
		// Multiple instances of Upload provided
		obj = raw["object"].([]interface{})
	}

	upldSt := make(map[int]UpldInfo)
	// Cycle through the object returned from the TF API for this call
	for i, v := range obj {
		// Create a map of Upload info
		up := v.(map[string]interface{})

		// Step into the Findings level map
		finds := up["findings"].([]interface{})
		findSt := make(map[int]*Finding)
		for i, v := range finds {
			f := v.(map[string]interface{})

			s := f["surfaceLocation"].(map[string]interface{})
			// Check for nil
			param := ""
			if reflect.TypeOf(s["surfaceLocation"]) != nil {
				// surfaceLocation was actually set
				param = s["surfaceLocation"].(string)
			}
			surfSt := SurfLoc{
				int(s["id"].(float64)),
				param,
				s["path"].(string),
			}

			// The following items are not always set in the JSON response
			lDesc := ""
			if reflect.TypeOf(f["longDescription"]) != nil {
				// longDescription was actually set
				lDesc = f["longDescription"].(string)
			}
			aStr := ""
			if reflect.TypeOf(f["attackString"]) != nil {
				// attackString was actually set
				aStr = f["attackString"].(string)
			}
			aResq := ""
			if reflect.TypeOf(f["attackRequest"]) != nil {
				// attackRequest was actually set
				aResq = f["attackRequest"].(string)
			}
			aResp := ""
			if reflect.TypeOf(f["attackResponse"]) != nil {
				// attackResponse was actually set
				aResp = f["attackResponse"].(string)
			}
			dId := ""
			if reflect.TypeOf(f["displayId"]) != nil {
				// displayId was actually set
				dId = f["displayId"].(string)
			}
			sFL := ""
			if reflect.TypeOf(f["sourceFileLocation"]) != nil {
				// sourceFileLocation was actually set
				sFL = f["sourceFileLocation"].(string)
			}

			// Step into the DataFlows map if its not nil
			dFlowsSt := make(map[int]DataFlow)
			if reflect.TypeOf(f["dataFlowElements"]) != nil {
				// dataFlowElements was actually set
				dFlows := f["dataFlowElements"].([]interface{})
				for idx, val := range dFlows {
					d := val.(map[string]interface{})
					var dfId, lNum, cNum int
					var sP, l string
					for iDF, vDF := range d {
						switch iDF {
						case "id":
							dfId = int(vDF.(float64))
						case "lineNumber":
							lNum = int(vDF.(float64))
						case "columnNumber":
							cNum = int(vDF.(float64))
						case "sourceFileName":
							sP = vDF.(string)
						case "lineText":
							l = vDF.(string)
						}
					}
					dFlowsSt[idx] = DataFlow{
						dfId,
						lNum,
						cNum,
						sP,
						l,
					}
				}
			}

			dep := ""
			if reflect.TypeOf(f["dependency"]) != nil {
				// dependency was actually set
				dep = f["dependency"].(string)
			}

			findSt[i] = &Finding{
				int(f["id"].(float64)),
				lDesc,
				aStr,
				aResq,
				aResp,
				f["nativeId"].(string),
				dId,
				sFL,
				dFlowsSt,
				f["calculatedUrlPath"].(string),
				f["calculatedFilePath"].(string),
				dep,
				f["vulnerabilityType"].(string),
				f["severity"].(string),
				surfSt,
			}
		}

		// Convert sent importTime to a Go time struct
		rawTime := int64(up["importTime"].(float64))
		tStamp := time.Unix(0, rawTime*int64(time.Millisecond))

		// Create a App struct based on the above
		upldSt[i] = UpldInfo{
			int(up["id"].(float64)),
			tStamp,
			int(up["numberClosedVulnerabilities"].(float64)),
			int(up["numberNewVulnerabilities"].(float64)),
			int(up["numberOldVulnerabilities"].(float64)),
			int(up["numberResurfacedVulnerabilities"].(float64)),
			int(up["numberTotalVulnerabilities"].(float64)),
			int(up["numberRepeatResults"].(float64)),
			int(up["numberRepeatFindings"].(float64)),
			int(up["numberInfoVulnerabilities"].(float64)),
			int(up["numberLowVulnerabilities"].(float64)),
			int(up["numberMediumVulnerabilities"].(float64)),
			int(up["numberHighVulnerabilities"].(float64)),
			int(up["numberCriticalVulnerabilities"].(float64)),
			up["scannerName"].(string),
			findSt,
		}

	}

	u.Upload = upldSt

	return nil
}

func CreateSearchStruct() Search {
	// Seeminly required fields which are sent every time by the Java Client
	r := map[string]string{
		"showHidden":        "false",
		"showFalsePositive": "false",
		"showClosed":        "false",
		"showOpen":          "false",
	}

	// Fill in the defaults for the single and multi parameter structs
	sp := SinglePara{
		map[string]string{"name": "numberVulnerabilities", "value": ""}, // NumVulns
		map[string]string{"name": "parameter", "value": ""},             // Param
		map[string]string{"name": "path", "value": ""},                  // Path
		map[string]string{"name": "startDate", "value": ""},             // Start
		map[string]string{"name": "endDate", "value": ""},               // End
		map[string]string{"name": "numberMerged", "value": ""},          // NumMerged
	}

	// Create maps of multiparameter search items and use ~ (tilda) as a place
	// holder so it can be replaced with a count of number of multi-parameters items
	// in VulnSearch function.  Numbering starts with 0 and is an int increasing by 1
	mp := MultiPara{
		map[string]string{"name": "teams%5B~%5D.id", "value": ""},                   // Teams
		map[string]string{"name": "applications%5B~%5D.id", "value": ""},            // Apps
		map[string]string{"name": "genericVulnerabilities%5B~%5D.id", "value": ""},  // Cwe
		map[string]string{"name": "channelTypes%5B~%5D.name", "value": ""},          // Scammer
		map[string]string{"name": "genericSeverities%5B~%5D.intValue", "value": ""}, // Severity
	}

	// Create the Search Struct
	s := Search{
		r,  // ReqPara
		sp, // SinglePara
		mp, // MultiPara
	}

	return s

}

func MakeSearchStruct(s *SrchResp, b string) error {
	// Parse the sent JSON body from the API
	var raw map[string]interface{}
	if err := json.Unmarshal([]byte(b), &raw); err != nil {
		msg := fmt.Sprintf("  Error parsing Search JSON\n%s", err)
		return errors.New(msg)
	}

	// Setup the values in the initial struct
	s.Success = raw["success"].(bool)
	s.RespCode = int(raw["responseCode"].(float64))
	s.Msg = raw["message"].(string)

	// Setup a struct for Upld based on the type
	// resulting from unmarshall'ing the JSON
	sType := reflect.TypeOf(raw["object"])
	var obj []interface{}
	if strings.Contains(sType.String(), "map") {
		// Single instance of Upload provided
		o := raw["object"].(map[string]interface{})
		obj = []interface{}{o}
	} else {
		// Multiple instances of Upload provided
		obj = raw["object"].([]interface{})
	}

	resSt := make(map[int]Result)
	// Cycle through the object returned from the TF API for this call
	for i, v := range obj {
		// Create a map of the results returned
		re := v.(map[string]interface{})

		// Step into Docs map
		docs := make(map[int]string)
		d := re["documents"].([]interface{})
		for i, v := range d {
			docs[i] = v.(string)
		}

		// Step into Comments map
		vComm := make(map[int]string)
		c := re["vulnerabilityComments"].([]interface{})
		for i, v := range c {
			vComm[i] = v.(string)
		}

		// Step into Apps map
		app := re["app"].(map[string]interface{})
		var appSt AppT

		// Check to see if App URL is empty
		aUrl := ""
		if reflect.TypeOf(app["url"]) != nil {
			// App URL was actually set
			aUrl = app["url"].(string)
		}

		// Step into the App Criticality map
		crit := app["applicationCriticality"].(map[string]interface{})
		critSt := AppCrit{
			int(crit["id"].(float64)),
			crit["name"].(string),
		}

		// Create a new AppT struct
		appSt = AppT{
			int(app["id"].(float64)),
			app["name"].(string),
			aUrl,
			critSt,
		}

		// Step into TeamU map
		team := re["team"].(map[string]interface{})
		teamSt := TeamS{
			int(team["id"].(float64)),
			team["name"].(string),
		}

		// Step into Generic Severiy map
		sev := re["genericSeverity"].(map[string]interface{})
		sevSt := Sev{
			int(sev["id"].(float64)),
			sev["name"].(string),
			int(sev["intValue"].(float64)),
		}

		// Step into the CWE map
		cwe := re["genericVulnerability"].(map[string]interface{})
		cweSt := CWE{
			int(cwe["id"].(float64)),
			cwe["name"].(string),
			int(cwe["displayId"].(float64)),
		}

		// Step into Scanners/channelNames map
		scnrs := make(map[int]string)
		s := re["channelNames"].([]interface{})
		for i, v := range s {
			scnrs[i] = v.(string)
		}

		// Step into the Findings map
		find := re["findings"].([]interface{})
		findSt := make(map[int]*Finding)

		for i, v := range find {
			f := v.(map[string]interface{})

			// create the surface location struct
			s := f["surfaceLocation"].(map[string]interface{})
			// Check for nil
			param := ""
			if reflect.TypeOf(s["surfaceLocation"]) != nil {
				// surfaceLocation was actually set
				param = s["surfaceLocation"].(string)
			}
			path := ""
			if reflect.TypeOf(s["path"]) != nil {
				// path was actually set
				path = s["path"].(string)
			}
			surfSt := SurfLoc{
				int(s["id"].(float64)),
				param,
				path,
			}

			// The following items are not always set in the JSON response
			lDesc := ""
			if reflect.TypeOf(f["longDescription"]) != nil {
				// longDescription was actually set
				lDesc = f["longDescription"].(string)
			}
			aStr := ""
			if reflect.TypeOf(f["attackString"]) != nil {
				// attackString was actually set
				aStr = f["attackString"].(string)
			}
			aResq := ""
			if reflect.TypeOf(f["attackRequest"]) != nil {
				// attackRequest was actually set
				aResq = f["attackRequest"].(string)
			}
			aResp := ""
			if reflect.TypeOf(f["attackResponse"]) != nil {
				// attackResponse was actually set
				aResp = f["attackResponse"].(string)
			}
			natId := ""
			if reflect.TypeOf(f["nativeId"]) != nil {
				// nativeID was actually set
				natId = f["nativeId"].(string)
			}
			dId := ""
			if reflect.TypeOf(f["displayId"]) != nil {
				// displayId was actually set
				dId = f["displayId"].(string)
			}
			sFL := ""
			if reflect.TypeOf(f["sourceFileLocation"]) != nil {
				// sourceFileLocation was actually set
				sFL = f["sourceFileLocation"].(string)
			}

			// Step into the DataFlows map
			dFlows := f["dataFlowElements"].([]interface{})
			dFlowsSt := make(map[int]DataFlow)
			for idx, val := range dFlows {
				d := val.(map[string]interface{})
				var dfId, lNum, cNum int
				var sP, l string
				for iDF, vDF := range d {
					switch iDF {
					case "id":
						dfId = int(vDF.(float64))
					case "lineNumber":
						lNum = int(vDF.(float64))
					case "columnNumber":
						cNum = int(vDF.(float64))
					case "sourceFileName":
						sP = vDF.(string)
					case "lineText":
						l = ""
						if reflect.TypeOf(vDF) != nil {
							// lineText was actually set
							l = vDF.(string)
						}
					}
				}
				dFlowsSt[idx] = DataFlow{
					dfId,
					lNum,
					cNum,
					sP,
					l,
				}
			}

			cUP := ""
			if reflect.TypeOf(f["calculatedUrlPath"]) != nil {
				// calculated URL path was actually set
				cUP = f["calculatedUrlPath"].(string)
			}
			cFP := ""
			if reflect.TypeOf(f["calculatedFilePath"]) != nil {
				// calculated file path was actually set
				cFP = f["calculatedFilePath"].(string)
			}
			dep := ""
			if reflect.TypeOf(f["dependency"]) != nil {
				// dependency was actually set
				dep = f["dependency"].(string)
			}
			vType := ""
			if reflect.TypeOf(f["vulnerabilityType"]) != nil {
				// vulnerability type was actually set
				vType = f["vulnerabilityType"].(string)
			}
			sev := ""
			if reflect.TypeOf(f["severity"]) != nil {
				// severity was actually set
				sev = f["severity"].(string)
			}

			// Create a new Finding struct
			findSt[i] = &Finding{
				int(f["id"].(float64)),
				lDesc,
				aStr,
				aResq,
				aResp,
				natId,
				dId,
				sFL,
				dFlowsSt,
				cUP,
				cFP,
				dep,
				vType,
				sev,
				surfSt,
			}

		}

		// Check for those values which may be null from the API
		var deft DefectSt
		if reflect.TypeOf(re["defect"]) != nil {
			de := re["defect"].(map[string]interface{})
			var dId int
			var nId, st, dU, im string
			for dI, dV := range de {
				switch dI {
				case "id":
					dId = int(dV.(float64))
				case "nativeId":
					nId = dV.(string)
				case "status":
					st = dV.(string)
				case "defectURL":
					dU = dV.(string)
				case "bugImageName":
					im = dV.(string)
				}
			}
			deft = DefectSt{
				dId,
				nId,
				st,
				dU,
				im,
			}
		}

		cfp := ""
		if reflect.TypeOf(re["calculatedFilePath"]) != nil {
			// calculatedFilePath was actually set
			cfp = re["calculatedFilePath"].(string)
		}
		dep := ""
		if reflect.TypeOf(re["dependency"]) != nil {
			// dependency is was actually set
			dep = re["dependency"].(string)
		}
		parm := ""
		if reflect.TypeOf(re["parameter"]) != nil {
			// parameter is was actually set
			parm = re["parameter"].(string)
		}
		path := ""
		if reflect.TypeOf(re["path"]) != nil {
			// path is was actually set
			parm = re["path"].(string)
		}

		resSt[i] = Result{
			int(re["id"].(float64)),
			deft,
			cfp,
			re["active"].(bool),
			re["isFalsePositive"].(bool),
			re["hidden"].(bool),
			docs,
			vComm,
			dep,
			parm,
			path,
			appSt,
			re["vulnId"].(string),
			teamSt,
			scnrs,
			sevSt,
			cweSt,
			findSt,
		}
	}

	// Add the last piece of the search results struct
	s.Results = resSt

	return nil
}
