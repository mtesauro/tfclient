// tfClient
// a temporary app to help develop a package to interact with the
// ThreadFix REST API
package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
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

const APIKEY = "7dx5LHFksAChi0QL6XuoNIPqDjKBn2IxmW4mtqLFg"
const TF_URL = "http://10.25.81.84/threadfix/rest"

// Use to format App Struct's scan.TimeStamp like t := tStamp.Format(shortDate)
// which displays dates like 2013-11-18
const shortDate = "2006-01-02"

// Team "Created by Go!" => id = 3
// App  "Go Appz" under team 3 => id = 3

func main() {
	// Set the types of

	// Create a custom transport so we can turn off SSL verification
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	tfClient := &http.Client{Transport: tr}

	fmt.Println("\n")
	// Comment out function calls after they are working
	//tBody := getTeams(tfClient)
	//tBody := lookupTeamId(tfClient, 1)
	//tBody := lookupTeamName(tfClient, "Example Team")
	//tBody := createTeam(tfClient, "Created by Go!")
	//fmt.Println(tBody)
	// Setup Team struct to hold the data we received
	//var team TeamResp
	//makeTeamStruct(&team, tBody)
	//aBody := createApplication(tfClient, "Pickle Express", "http://en.wikipedia.org/wiki/Pickle", 3)
	aBody := lookupAppId(tfClient, 3)
	// BUG FOUND: encoding space as "+" causes lookup failures while %20 works
	//aBody := lookupAppName(tfClient, "noappspaces", "nospaces")
	//aBody := lookupAppName(tfClient, "Go Appz", "Created by Go!")
	// BUG FOUND
	//aBody := setAppParams(tfClient, 4, "NONE", "http://www.repository2.com")
	//aBody := setUrl(tfClient, 4, "https://appseclive.org")
	// Call this after creating at least 1 waf
	//aBody := setWaf(tfClient, 4, 1)
	// Read in a file from disk and create a io.Reader to pass
	// STOPPED HERE TO DEBUG
	//aBody, _ := scanUpload(tfClient, 5, "./examples/ThreadFix-from-CM.xml")
	fmt.Println(aBody)
	var app AppResp
	makeAppStruct(&app, aBody)
	//waf := createWaf(tfClient, "example waf", "")
	// {"id":1,"name":"example waf","wafTypeName":"mod_security","applications":null}
	//waf := lookupWafId(tfClient, 1)
	//waf := lookupWafName(tfClient, "example waf")
	//waf := getWafs(tfClient)
	//fmt.Println(waf)
	// NEEDS MORE WORK
	//vulns := vulnSearch(tfClient)
	//fmt.Println(vulns)
	// json.MarshalIndent(team, "", " ")
	// fmt.Printf("JSON was\n\n%s", json.MarshalIndent(team, "", " "))
	// The easiest way to do this is with MarshalIndent, which will let you specify how you would like it indented via the indent argument. Thus, json.MarshalIndent(data, "", " ") will pretty-print using four spaces for indentation.

	fmt.Println("\n")

}

// Helper Functions1

func makeRequest(c *http.Client, m string, u string, b io.Reader) string {
	// Create a request to customize then send
	req, err := http.NewRequest(m, u, b)
	if err != nil {
		fmt.Printf("Error creating request: %s\n", err)
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
		fmt.Printf("Error has occured: %s", err)
	}

	//Read back the JSON response
	jsonResp, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		fmt.Printf("Error has occured: %s", err)
	}

	return string(jsonResp[:])
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

func createSearchMaps() (map[string]string, map[string]map[string]string) {
	// Seeminly required fields which are sent every time by the Java Client
	r := map[string]string{
		"showHidden":        "false",
		"showFalsePositive": "false",
		"showClosed":        "false",
		"showOpen":          "false",
	}

	// Optional fields - map of 'normal' name to what was sent by the Java Client
	// plus if the parameter is sent one time or (if single is false) multiple times
	o := map[string]map[string]string{
		"teams":     map[string]string{"tfname": "teams%5B0%5D.id", "single": "false"},
		"apps":      map[string]string{"tfname": "applications%5B0%5D.id", "single": "false"},
		"cwe":       map[string]string{"tfname": "genericVulnerabilities%5B0%5D.id", "single": "false"},
		"scanner":   map[string]string{"tfname": "channelTypes%5B0%5D.name", "single": "false"},
		"severity":  map[string]string{"tfname": "genericSeverities%5B0%5D.intValue", "single": "false"},
		"numVulns":  map[string]string{"tfname": "numberVulnerabilities", "single": "true"},
		"param":     map[string]string{"tfname": "parameter", "single": "true"},
		"path":      map[string]string{"tfname": "path", "single": "true"},
		"start":     map[string]string{"tfname": "startDate", "single": "true"},
		"end":       map[string]string{"tfname": "endDate", "single": "true"},
		"numMerged": map[string]string{"tfname": "numberMerged", "single": "true"},
	}

	return r, o
}

// Team API calls

func createTeam(c *http.Client, name string) string {
	// Set URL for this API call
	u := TF_URL + "/teams/new?apiKey=" + APIKEY

	// Prep data to be POST'ed and make request
	var postStr = []byte("name=" + url.QueryEscape(name))
	jsonResp := makeRequest(c, "POST", u, bytes.NewBuffer(postStr))

	return jsonResp
}

func getTeams(c *http.Client) string {
	// Set URL for this API call
	u := TF_URL + "/teams?apiKey=" + APIKEY

	// Make the request
	jsonResp := makeRequest(c, "GET", u, nil)

	return jsonResp
}

func lookupTeamId(c *http.Client, id int) string {
	// Set URL for this API call
	u := TF_URL + "/teams/" + strconv.Itoa(id) + "?apiKey=" + APIKEY

	// Make the request
	jsonResp := makeRequest(c, "GET", u, nil)

	return jsonResp
}

func lookupTeamName(c *http.Client, name string) string {
	// Set URL for this API call
	u := TF_URL + "/teams/lookup?name=" + url.QueryEscape(name) +
		"&apiKey=" + APIKEY

	// Make the request
	jsonResp := makeRequest(c, "GET", u, nil)

	return jsonResp
}

// Application API calls

func createApplication(c *http.Client, n string, aUrl string, t int) string {
	// Set URL for this API call
	u := TF_URL + "/teams/" + strconv.Itoa(t) + "/applications/new?apiKey=" + APIKEY

	// Prep data to be POST'ed and make request
	var postStr = []byte("name=" + url.QueryEscape(n) + "&url=" + url.QueryEscape(aUrl))
	jsonResp := makeRequest(c, "POST", u, bytes.NewBuffer(postStr))

	return jsonResp
}

func lookupAppId(c *http.Client, id int) string {
	// Set URL for this API call
	u := TF_URL + "/applications/" + strconv.Itoa(id) + "?apiKey=" + APIKEY

	// Make the request
	jsonResp := makeRequest(c, "GET", u, nil)

	return jsonResp
}

func lookupAppName(c *http.Client, name string, t string) string {
	// Set URL for this API call
	u := TF_URL + "/applications/" + url.QueryEscape(t) + "/lookup?name=" +
		url.QueryEscape(name) + "&apiKey=" + APIKEY

	// WORK AROUND
	// Convert + to %20 to work around a bug in TF which causes lookup failures when
	// "+" is used instead of %20 when URL encoding.  Go defaults to URL encoding
	// to "+" so these calls are broken but only for Lookup Applicaiton by name
	// as this work around is not needed for Lookup Team by name
	u = strings.Replace(u, "+", "%20", -1)

	// Make the request
	jsonResp := makeRequest(c, "GET", u, nil)

	return jsonResp
}

func setAppParams(c *http.Client, appId int, frmwrk string, rUrl string) string {
	// Set URL for this API call
	u := TF_URL + "/applications/" + strconv.Itoa(appId) +
		"/setParameters?apiKey=" + APIKEY

	// Check that framework is among the supported frameworks
	fTypes := getFrameworkTypes()
	if !(stringInSlice(frmwrk, fTypes[:])) {
		// FIX ME - return an err when this happens
		fmt.Println("Invalid Framework type used when setting App parameters\n")
		os.Exit(0)
	}

	// Prep data to be POST'ed and make request
	var postStr = []byte("framework=" + url.QueryEscape(frmwrk) +
		"&repositoryUrl=" + url.QueryEscape(rUrl))
	jsonResp := makeRequest(c, "POST", u, bytes.NewBuffer(postStr))

	return jsonResp
}

func setWaf(c *http.Client, appId int, wafId int) string {
	//Set URL for this API call
	u := TF_URL + "/applications/" + strconv.Itoa(appId) + "/setWaf?wafId=" +
		strconv.Itoa(wafId) + "&apiKey=" + APIKEY

	// Oddly, this is an empty post so send nil insteall of a buffer
	jsonResp := makeRequest(c, "POST", u, nil)

	return jsonResp
}

func setUrl(c *http.Client, appId int, aUrl string) string {
	//Set URL for this API call
	u := TF_URL + "/applications/" + strconv.Itoa(appId) +
		"/addUrl?apiKey=" + APIKEY

	//-X POST --data 'url=http://www.example-url.com'
	//https://host.com:8443/threadfix/rest/applications/3/addUrl?apiKey=Your-key-here
	var postStr = []byte("url=" + url.QueryEscape(aUrl))
	jsonResp := makeRequest(c, "POST", u, bytes.NewBuffer(postStr))

	return jsonResp
}

func scanUpload(c *http.Client, appId int, path string) (string, error) {
	var err error = nil
	//Set URL for this API call
	u := TF_URL + "/applications/" + strconv.Itoa(appId) + "/upload?apiKey=" + APIKEY

	// Convert the file into a multipart HTTP POST body
	request, header, err := prepScanFile(u, "file", path)
	if err != nil {
		log.Fatal(err)
	}
	request.Header.Add("Content-Type", header)
	request.Header.Del("Accept-Encoding")

	resp, err := c.Do(request)
	if err != nil {
		fmt.Printf("Error has occured: %s", err)
	}

	//Read back the JSON response
	jsonResp, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		fmt.Printf("Error has occured: %s", err)
	}

	return string(jsonResp[:]), err
}

// WAF API calls

func createWaf(c *http.Client, n string, wType string) string {
	// Set URL for this API call
	u := TF_URL + "/wafs/new?apiKey=" + APIKEY

	// Check that framework is among the supported frameworks
	wafTypes := getWafTypes()
	if !(stringInSlice(wType, wafTypes[:])) {
		// FIX ME - return an err when this happens
		fmt.Println("Invalid WAF type used when creating a new WAF\n")
		os.Exit(0)
	}

	// Prep data to be POST'ed and make request
	var postStr = []byte("name=" + url.QueryEscape(n) + "&type=" + url.QueryEscape(wType))
	jsonResp := makeRequest(c, "POST", u, bytes.NewBuffer(postStr))

	return jsonResp
}

func lookupWafId(c *http.Client, id int) string {
	// Set URL for this API call
	u := TF_URL + "/wafs/" + strconv.Itoa(id) + "?apiKey=" + APIKEY

	// Make the request
	jsonResp := makeRequest(c, "GET", u, nil)

	return jsonResp
}

func lookupWafName(c *http.Client, name string) string {
	// Set URL for this API call
	u := TF_URL + "/wafs/lookup?name=" + url.QueryEscape(name) +
		"&apiKey=" + APIKEY

	// Make the request
	jsonResp := makeRequest(c, "GET", u, nil)

	return jsonResp
}

func getWafs(c *http.Client) string {
	// Set URL for this API call
	u := TF_URL + "/wafs?apiKey=" + APIKEY

	// Make the request
	jsonResp := makeRequest(c, "GET", u, nil)

	return jsonResp
}

func vulnSearch(c *http.Client) string {
	//Set URL for this API call
	u := TF_URL + "/vulnerabilities?apiKey=" + APIKEY

	// Create the needed POST string
	//req, opt = createSearchMaps()
	//showOpen=false&showClosed=false&showFalsePositive=false&showHidden=false
	var postStr = []byte("showOpen=false&showClosed=false&showFalsePositive=true&showHidden=false")
	jsonResp := makeRequest(c, "POST", u, bytes.NewBuffer(postStr))

	return jsonResp
}

// Functions to parse JSON into normalized structs

func makeTeamStruct(t *TeamResp, b string) {
	// Parse the sent JSON body from the API
	var raw map[string]interface{}
	if err := json.Unmarshal([]byte(b), &raw); err != nil {
		// Add some proper error handling here - maybe return an error
		panic(err)
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
		for _, v := range apps {
			// Create a map of applications
			app := v.(map[string]interface{})

			// Step into the App Criticality map
			crit := app["applicationCriticality"].(map[string]interface{})
			critSt := AppCrit{
				int(crit["id"].(float64)),
				crit["name"].(string),
			}

			appSt[i] = AppT{
				Id:        int(app["id"].(float64)),
				Name:      app["name"].(string),
				Url:       app["url"].(string),
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
	fmt.Printf("\n\nteamSt type is %+v \n", reflect.TypeOf(t))
	fmt.Printf("\n\nteamSt contains %+v \n", t)
}

func makeAppStruct(a *AppResp, b string) {
	// Parse the sent JSON body from the API
	var raw map[string]interface{}
	if err := json.Unmarshal([]byte(b), &raw); err != nil {
		// Add some proper error handling here - maybe return an error
		panic(err)
	}

	// Setup the values in the initial struct
	a.Success = raw["success"].(bool)
	a.RespCode = int(raw["responseCode"].(float64))
	a.Msg = raw["message"].(string)
	fmt.Printf("Early Value of Struct %+v \n\n", a)

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
			fmt.Printf("Scan contains: \n  %+v \n", scan)

			// http://play.golang.org/p/r5kBJHPDUb
			// Convert Mills provided by TF into something useful
			// Note: There is likely differenced based on timezone of the
			// TF server vs local time where this is run
			rawTime := int64(scan["importTime"].(float64))
			tStamp := time.Unix(0, rawTime*int64(time.Millisecond))
			fmt.Printf("\nrawTime is %v\n", rawTime)
			fmt.Printf("\nFormatted is %v\n", tStamp.Format(shortDate))
			fmt.Printf("\ntStamp is %v\n", tStamp)

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

			fmt.Print("Arbitrary use of i with %v\n", i)

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
			app["url"].(string),
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
	fmt.Printf("teamSt type is %+v \n", reflect.TypeOf(a))
	fmt.Printf("teamSt contains %+v \n", a)
}
