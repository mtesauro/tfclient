// structs.go
package main

import "time"

// Data structures to handle JSON responses from ThreadFix API as documented at
// https://github.com/denimgroup/threadfix/wiki/Threadfix-REST-Interface
// Based on JSON responses from ThreadFix 2.1.2 Official release

// Struct for both JSON responses for various Team calls

// Team API call's JSON response to calls to Create Team, Lookup Team by (id | name)
//{
//  "message": "",
//  "success": true,
//  "responseCode": -1,
//  "object": {
//    "id": 1,
//    "infoVulnCount": 128,
//    "lowVulnCount": 63,
//    "mediumVulnCount": 42,
//    "highVulnCount": 18,
//    "criticalVulnCount": 17,
//    "totalVulnCount": 268,
//    "name": "Example Team",
//    "applications": [
//      {
//        "id": 1,
//        "name": "TF Demo App",
//        "url": "http://tftarget",
//        "applicationCriticality": {
//          "id": 2,
//          "name": "Medium"
//        }
//      }
//    ]
//  }
//}
// Team API call's JSON response to call to All Teams
//{
//  "message": "",
//  "success": true,
//  "responseCode": -1,
//  "object": [
//    {
//      "id": 1,
//      "infoVulnCount": 128,
//      "lowVulnCount": 63,
//      "mediumVulnCount": 42,
//      "highVulnCount": 18,
//      "criticalVulnCount": 17,
//      "totalVulnCount": 268,
//      "name": "Example Team",
//      "applications": [
//        {
//          "id": 1,
//          "name": "TF Demo App",
//          "url": "http://tftarget",
//          "applicationCriticality": {
//            "id": 2,
//            "name": "Medium"
//          }
//        }
//      ]
//    },
//    {
//      "id": 2,
//      "infoVulnCount": 0,
//      "lowVulnCount": 46402,
//      "mediumVulnCount": 6425,
//      "highVulnCount": 213,
//      "criticalVulnCount": 6,
//      "totalVulnCount": 53046,
//      "name": "Import Team",
//      "applications": [
//        {
//          "id": 2,
//          "name": "Pearson Imports",
//          "url": "http://test.actaspire.org/",
//          "applicationCriticality": {
//            "id": 2,
//            "name": "Medium"
//          }
//        }
//      ]
//    },
//    {
//      "id": 3,
//      "infoVulnCount": 1075,
//      "lowVulnCount": 231,
//      "mediumVulnCount": 117,
//      "highVulnCount": 48,
//      "criticalVulnCount": 0,
//      "totalVulnCount": 1471,
//      "name": "Created by Go!",
//      "applications": [
//        {
//          "id": 3,
//          "name": "Go Appz",
//          "url": "https://golang.org",
//          "applicationCriticality": {
//            "id": 1,
//            "name": "Low"
//          }
//        },
//        {
//          "id": 4,
//          "name": "Mo Go Sho Nuff",
//          "url": "https://appseclive.org",
//          "applicationCriticality": {
//            "id": 1,
//            "name": "Low"
//          }
//        },
//        {
//          "id": 5,
//          "name": "Pickle Express",
//          "url": "http://en.wikipedia.org/wiki/Pickle",
//          "applicationCriticality": {
//            "id": 1,
//            "name": "Low"
//          }
//        }
//      ]
//    },
//    {
//      "id": 4,
//      "infoVulnCount": 0,
//      "lowVulnCount": 0,
//      "mediumVulnCount": 0,
//      "highVulnCount": 0,
//      "criticalVulnCount": 0,
//      "totalVulnCount": 0,
//      "name": "nospaces",
//      "applications": [
//        {
//          "id": 6,
//          "name": "noappspaces",
//          "url": "http://mtesauro.com",
//          "applicationCriticality": {
//            "id": 2,
//            "name": "Medium"
//          }
//        }
//      ]
//    }
//  ]
//}

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

// Struct for both JSON responses for various Applications calls

// Applications API call's JSON response to calls to Create App, Lookup App by (id | name)
//{
//  "message": "",
//  "success": true,
//  "responseCode": -1,
//  "object": {
//    "id": 3,
//    "name": "Go Appz",
//    "url": "https://golang.org",
//    "uniqueId": null,
//    "applicationCriticality": {
//      "id": 1,
//      "name": "Low"
//    },
//    "scans": [
//      {
//        "id": 54,
//        "importTime": 1384804367000,
//        "numberClosedVulnerabilities": 0,
//        "numberNewVulnerabilities": 29,
//        "numberOldVulnerabilities": 0,
//        "numberResurfacedVulnerabilities": 0,
//        "numberTotalVulnerabilities": 29,
//        "numberRepeatResults": 0,
//        "numberRepeatFindings": 0,
//        "numberInfoVulnerabilities": 25,
//        "numberLowVulnerabilities": 0,
//        "numberMediumVulnerabilities": 0,
//        "numberHighVulnerabilities": 4,
//        "numberCriticalVulnerabilities": 0,
//        "scannerName": "Burp Suite"
//      }
//    ],
//    "infoVulnCount": 25,
//    "lowVulnCount": 0,
//    "mediumVulnCount": 0,
//    "highVulnCount": 4,
//    "criticalVulnCount": 0,
//    "totalVulnCount": 29,
//    "waf": {
//      "id": 1,
//      "name": "Example-WAF"
//    },
//    "organization": {
//      "id": 3,
//      "name": "Created by Go!"
//    }
//  }
//}

// Applications API call's JSON response to a call to All Applicatons
// Not documented at https://github.com/denimgroup/threadfix/wiki/ThreadFix-REST-Interface
// FIXME - find out if calling /rest/applications/ gives a list of all apps.

// If found, put All Apps JSON response here

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

// Applications API call's JSON response to a call to Upload Scan - handled separate from other App calls
//{
//  "message": "",
//  "success": true,
//  "responseCode": -1,
//  "object": {
//    "id": 7,
//    "importTime": 1415655196000,
//    "numberClosedVulnerabilities": 0,
//    "numberNewVulnerabilities": 0,
//    "numberOldVulnerabilities": 0,
//    "numberResurfacedVulnerabilities": 0,
//    "numberTotalVulnerabilities": 0,
//    "numberRepeatResults": 0,
//    "numberRepeatFindings": 0,
//    "numberInfoVulnerabilities": 0,
//    "numberLowVulnerabilities": 0,
//    "numberMediumVulnerabilities": 0,
//    "numberHighVulnerabilities": 0,
//    "numberCriticalVulnerabilities": 0,
//    "findings": [
//      {
//        "id": 135,
//        "longDescription": null,
//        "attackString": "",
//        "attackRequest": null,
//        "attackResponse": null,
//        "nativeId": "7a978638a89516db5aa9d74efcc9a094",
//        "displayId": null,
//        "surfaceLocation": {
//          "id": 135,
//          "parameter": null,
//          "path": ""
//        },
//        "sourceFileLocation": null,
//        "dataFlowElements": null,
//        "calculatedUrlPath": "/",
//        "calculatedFilePath": "",
//        "dependency": null,
//        "vulnerabilityType": "Web Browser XSS Protection Not Enabled",
//        "severity": "1"
//      },
//      {
//        "id": 136,
//        "longDescription": null,
//        "attackString": "",
//        "attackRequest": null,
//        "attackResponse": null,
//        "nativeId": "2d0a7b83d71dc4b5fcbabd8d7b3845d8",
//        "displayId": null,
//        "surfaceLocation": {
//          "id": 136,
//          "parameter": null,
//          "path": ""
//        },
//        "sourceFileLocation": null,
//        "dataFlowElements": null,
//        "calculatedUrlPath": "/",
//        "calculatedFilePath": "",
//        "dependency": null,
//        "vulnerabilityType": "X-Content-Type-Options header missing",
//        "severity": "1"
//      },
//      {
//        "id": 137,
//        "longDescription": null,
//        "attackString": "",
//        "attackRequest": null,
//        "attackResponse": null,
//        "nativeId": "7f00f27977d40aca399a12363ab05dfe",
//        "displayId": null,
//        "surfaceLocation": {
//          "id": 137,
//          "parameter": null,
//          "path": ""
//        },
//        "sourceFileLocation": null,
//        "dataFlowElements": null,
//        "calculatedUrlPath": "/",
//        "calculatedFilePath": "",
//        "dependency": null,
//        "vulnerabilityType": "X-Frame-Options header not set",
//        "severity": "0"
//      }
//    ],
//    "scannerName": "OWASP Zed Attack Proxy"
//  }
//}
