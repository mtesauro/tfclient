// structs.go
package main

import "time"

// Data structures to handle JSON responses from ThreadFix API as documented at
// https://github.com/denimgroup/threadfix/wiki/Threadfix-REST-Interface
// Based on JSON responses from ThreadFix 2.1.2 Official release

///////////////////////////////////////////////////////////
// Struct for both JSON responses for various Team calls //
///////////////////////////////////////////////////////////

type TeamResp struct {
	Msg      string       `json:"message"`
	Success  bool         `json:"success"`
	RespCode int          `json:"responseCode"`
	Tm       map[int]Team `json:"object"`
}

type Team struct {
	Id      int          `json:"id"`
	NumInfo int          `json:"infoVulnCount"`
	NumLow  int          `json:"lowVulnCount"`
	NumMed  int          `json:"mediumVulnCount"`
	NumHigh int          `json:"highVulnCount"`
	NumCrit int          `json:"criticalVulnCount"`
	Total   int          `json:"totalVulnCount"`
	Name    string       `json:"name"`
	Apps    map[int]AppT `json:applications`
}

type AppT struct {
	Id        int     `json:"id"`
	Name      string  `json:"name"`
	Url       string  `json:"url"`
	CritLevel AppCrit `json:"applicationCriticality"`
}

type AppCrit struct {
	Id   int    `json:"id"`
	Name string `json:"name"`
}

///////////////////////////////////////////////////////////////////
// Struct for both JSON responses for various Applications calls //
///////////////////////////////////////////////////////////////////

type AppResp struct {
	Msg      string      `json:"message"`
	Success  bool        `json:"success"`
	RespCode int         `json:"responseCode"`
	Ap       map[int]App `json:"object"`
}

type App struct {
	Id        int          `json:"id"`
	Name      string       `json:"name"`
	Url       string       `json:"url"`
	UniqId    string       `json:"uniqueId`
	NumInfo   int          `json:"infoVulnCount"`
	NumLow    int          `json:"lowVulnCount"`
	NumMed    int          `json:"mediumVulnCount"`
	NumHigh   int          `json:"highVulnCount"`
	NumCrit   int          `json:"criticalVulnCount"`
	Total     int          `json:"totalVulnCount"`
	CritLevel AppCrit      `json:"applicationCriticality"`
	Scans     map[int]Scan `json:"scans"`
	Team      TeamA        `json:"organization"`
	Waf       WafA         `json:"waf"`
}

// AppCrit struct reused from Team Struct

type Scan struct {
	Id         int       `json:"id"`
	TimeStamp  time.Time `json:"importTime"`
	NumClose   int       `json:"numberClosedVulnerabilities"`
	NumNew     int       `json:"numberNewVulnerabilities"`
	NumOld     int       `json:"numberOldVulnerabilities"`
	NumResurf  int       `json:"numberResurfacedVulnerabilities"`
	Total      int       `json:"numberTotalVulnerabilities"`
	NumRepeatR int       `json:"numberRepeatResults"`
	NumRepeatF int       `json:"numberRepeatFindings"`
	NumInfo    int       `json:"numberInfoVulnerabilities"`
	NumLow     int       `json:"numberLowVulnerabilities"`
	NumMed     int       `json:"numberMediumVulnerabilities"`
	NumHigh    int       `json:"numberHighVulnerabilities"`
	NumCrit    int       `json:"numberCriticalVulnerabilities"`
	ScanName   string    `json:"scannerName"`
}

type TeamA struct {
	Id   int    `json:"id"`
	Name string `json:"name"`
}

type WafA struct {
	Id   int    `json:"id"`
	Name string `json`
}

/////////////////////////////////////////////////////////////
// Struct for the JSON responses from the Upload Scan call //
/////////////////////////////////////////////////////////////

type UpldResp struct {
	Msg      string           `json:"message"`
	Success  bool             `json:"success"`
	RespCode int              `json:"responseCode"`
	Upload   map[int]UpldInfo `json:"object"`
}

type UpldInfo struct {
	Id            int              `json:"id"`
	ImportTime    time.Time        `json:"importTime"`
	NumClosed     int              `json:numberClosedVulnerabilities`
	NumNew        int              `json:"numberNewVulnerabilities"`
	NumOld        int              `json:"numberOldVulnerabilities"`
	NumResurf     int              `json:"numberResurfacedVulnerabilities"`
	NumTotal      int              `json:"numberTotalVulnerabilities"`
	NumRepeatRes  int              `json:"numberRepeatResults"`
	NumRepeatFind int              `json:"numberRepeatFindings"`
	NumInfo       int              `json:"numberInfoVulnerabilities"`
	NumLow        int              `json:"numberLowVulnerabilities"`
	NumMed        int              `json:"numberMediumVulnerabilities"`
	NumHigh       int              `json:"numberHighVulnerabilities"`
	NumCrit       int              `json:"numberCriticalVulnerabilities"`
	Scanner       string           `json:"scannerName"`
	Findings      map[int]*Finding `json:"findings"`
}

type Finding struct {
	Id           int            `json:"id"`
	LongDesc     string         `json:"longDescription"`    // null
	AttString    string         `json:"attackString"`       // ""
	AttReq       string         `json:"attackRequest"`      // null
	AttResp      string         `json:"attackResponse"`     // null
	NativeId     string         `json:"nativeId"`           // "7a978638a89516db5aa9d74efcc9a094"
	DisplId      string         `json:"displayId"`          // null
	SrcFileLoc   string         `json:"sourceFileLocation"` // null
	DataFlow     map[int]string `json:"dataFlowElements"`   // null
	CalcUrlPath  string         `json:"calculatedUrlPath"`  // "/"
	CalcFilePath string         `json:"calculatedFilePath"` // ""
	Depend       string         `json:"dependency"`         // null,
	VulnType     string         `json:"vulnerabilityType"`  // "Web Browser XSS Protection Not Enabled"
	Severity     string         `json:"severity"`           // "1"
	Loc          SurfLoc        `json:"surfaceLocation"`
}

type SurfLoc struct {
	Id    int    `json:"id"`
	Param string `json:"parameter"` // null
	Path  string `json:"path"`      // ""
}

//////////////////////////////////////////////////////////////////////////
// Struct for the JSON responses from the Vulnerability Search API call //
//////////////////////////////////////////////////////////////////////////

type SrchResp struct {
	Msg      string         `json:"message"`
	Success  bool           `json:"success"`
	RespCode int            `json:"responseCode"`
	Results  map[int]Result `json:"object"`
}

type Result struct {
	Id           int              `json:"id"`
	Defect       string           `json:"defect"`                // null
	CalcFilePath string           `json:"calculatedFilePath"`    // null
	Active       bool             `json:"active"`                // true
	FalsPositive bool             `json:"isFalsePositive"`       // false
	Hidden       bool             `json:"hidden"`                // false
	Docs         map[int]string   `json:"documents"`             // []
	VulnComment  map[int]string   `json:"vulnerabilityComments"` // []
	Depend       string           `json:"dependency"`            // null
	Param        string           `json:"parameter"`             // null
	Path         string           `json:"path"`                  // "/"
	Apps         AppT             `json:app`                     // reusing AppT struct from Teams call above
	VulnId       string           `json:"vulnId"`                // "10"
	Team         TeamU            `json:"team"`
	Scanners     map[int]string   `json:"channelNames"`
	CweVuln      CWE              `json:"genericVulnerability"`
	Findings     map[int]*Finding `json:"findings"`
}

// AppT and the internal CritLevel struct are defined under the Teams API call above

type TeamU struct {
	Id   int    `json:"id"`
	Name string `json:"name"`
}

type CWE struct {
	Id     int    `json:"id"`
	Name   string `json:"name"`
	DispId string `json:"displayId"`
}

// Finding and the internal SurfLoc struct are defined under the Upload Scan call above

///////////////////////////////////////////////////////////////////////////////////
// Struct for the items that can be queried in the Vulnerability Search API call //
///////////////////////////////////////////////////////////////////////////////////

type Search struct {
	ReqPara     map[string]string // Required for every request
	SingleParas SinglePara
	MultiParas  MultiPara
}

type SinglePara struct {
	NumVulns  map[string]string
	Param     map[string]string
	Path      map[string]string
	Start     map[string]string
	End       map[string]string
	NumMerged map[string]string
}

type MultiPara struct {
	Teams    map[string]string
	Apps     map[string]string
	Cwe      map[string]string
	Scanner  map[string]string
	Severity map[string]string
}
