// structs.go
package main

import "time"

// Data structures to handle JSON responses from ThreadFix API as documented at
// https://github.com/denimgroup/threadfix/wiki/Threadfix-REST-Interface
// Based on JSON responses from ThreadFix 2.1.2 Official release

// Struct for both JSON responses for various Team calls

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

// Struct for the JSON responses from the upload scan call

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
	Scaner        string           `json:"scannerName"`
	Findings      map[int]*Finding `json:"findings"`
}

type Finding struct {
	Id           int     `json:"id"`
	LongDesc     string  `json:"longDescription"`    //null
	AttString    string  `json:"attackString"`       //""
	AttReq       string  `json:"attackRequest"`      //null
	AttResp      string  `json:"attackResponse"`     //null
	NativeId     string  `json:"nativeId"`           //"7a978638a89516db5aa9d74efcc9a094"
	DisplId      string  `json:"displayId"`          //null
	SrcFileLoc   string  `json:"sourceFileLocation"` //null
	DataFlowElem string  `json:"dataFlowElements"`   //null
	CalcUrlPath  string  `json:"calculatedUrlPath"`  //"/"
	CalcFilePath string  `json:"calculatedFilePath"` //""
	Depend       string  `json:"dependency"`         //null,
	VulnType     string  `json:"vulnerabilityType"`  //"Web Browser XSS Protection Not Enabled"
	Severity     string  `json:"severity"`           //"1"
	Loc          SurfLoc `json:"surfaceLocation"`
}

type SurfLoc struct {
	Id    int    `json:"id"`
	Param string `json:"parameter"` //null
	Path  string `json:"path"`      //""
}

// Struct for the JSON responses from the Vulnerability Search API call

type Search struct {
	Msg      string         `json:"message"`
	Success  bool           `json:"success"`
	RespCode int            `json:"responseCode"`
	Results  map[int]Result `json:"object"`
}

type Result struct {
	Id int `json:"id"`
}

//    {
//      "id": 10,
//      "defect": null,
//      "calculatedFilePath": null,
//      "active": true,
//      "isFalsePositive": false,
//      "hidden": false,
//      "documents": [],
//      "vulnerabilityComments": [],
//      "dependency": null,
//      "parameter": null,
//      "path": "/"
//      "app": {
//        "id": 1,
//        "name": "TF Demo App",
//        "url": "http://tftarget",
//        "applicationCriticality": {
//          "id": 2,
//          "name": "Medium"
//        }
//      },
//      "team": {
//        "id": 1,
//        "name": "Example Team"
//      },
//      "vulnId": "10",
//      "channelNames": [
//        "IBM Rational AppScan"
//      ],
//      "genericVulnerability": {
//        "id": 531,
//        "name": "Information Exposure Through Test Code",
//        "displayId": 531
//      },
//      "genericSeverity": {
//        "id": 4,
//        "name": "Low",
//        "intValue": 2
//      },

//      "findings": [
//        {
//          "id": 10,
//          "longDescription": null,
//          "attackString": "path: cookie /demo/ -> /test.php",
//          "attackRequest": "GET /test.php HTTP/1.0\nAccept: */*\nAccept-Language: en-US\nUser-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Win32)\nHost: tftarget\n\n\nHTTP/1.1 200 OK\nContent-Length: 76677\nDate: Mon, 10 Feb 2014 14:45:17 GMT\nServer: Apache/2.2.19 (Win32) PHP/5.3.6\nX-Powered-By: PHP/5.3.6\nConnection: close\nContent-Type: text/html\n\n<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Transitional//EN\" \"DTD/xhtml1-transitional.dtd\">\n<html><head>\n<style type=\"text/css\">\nbody {background-color: #ffffff; color: #000000;}\nbody, td, th, h1, h2 {font-family: sans-serif;}\npre {margin: 0px; font-family: monospace;}\na:link {color: #000099; text-decoration: none; background-color: #ffffff;}\na:hover {text-decoration: underline;}\ntable {border-collapse: collapse;}\n.center {text-align: center;}\n.center table { margin-left: auto; margin-right: auto; text-align: left;}\n.center th { text-align: center !important; }\ntd, th { border: 1px solid #000000; font-size: 75%; vertical-align: baseline;}\nh1 {font-size: 150%;}\nh2 {font-size: 125%;}\n.p {text-align: left;}\n.e {background-color: #ccccff; font-weight: bold; color: #000000;}\n.h {background-color: #9999cc; font-weight: bold; color: #000000;}\n.v {background-color: #cccccc; color: #000000;}\n.vr {background-color: #cccccc; text-align: right; color: #000000;}\nimg {float: right; border: 0px;}\nhr {width: 600px; background-color: #cccccc; border: 0px; height: 1px; color: #000000;}\n</style>\n<title>phpinfo()</title><meta name=\"ROBOTS\" content=\"NOINDEX,NOFOLLOW,NOARCHIVE\" /></head>\n<body><div class=\"center\">\n<table border=\"0\" cellpadding=\"3\" width=\"600\">\n<tr class=\"h\"><td>\n<a href=\"http://www.php.net/\"><img border=\"0\" src=\"/test.php?=PHPE9568F34-D428-11d2-A769-00AA001ACF42\" alt=\"PHP Logo\" /></a><h1 class=\"p\">PHP Version 5.3.6</h1>\n</td></tr>\n</table><br />\n<table border=\"0\" cellpadding=\"3\" width=\"600\">\n<tr><td class=\"e\">System </td><td class=\"v\">Windows NT TFTARGET 6.1 build 7600 (Unknow Windows version Enterprise Edition) i586 </td></tr>\n<tr><td class=\"e\">Build Date </td><td class=\"v\">Mar 17 2011 10:34:15 </td></tr>\n<tr><td class=\"e\">Compiler </td><td class=\"v\">MSVC9 (Visual C++ 2008) </td></tr>\n<tr><td class=\"e\">Architecture </td><td class=\"v\">x86 </td></tr>\n<tr><td class=\"e\">Configure Command </td><td class=\"v\">cscript /nologo configure.js  &quot;--enable-snapshot-build&quot; &quot;--disable-isapi&quot; &quot;--enable-debug-pack&quot; &quot;--disable-isapi&quot; &quot;--without-mssql&quot; &quot;--without-pdo-mssql&quot; &quot;--without-pi3web&quot; &quot;--with-pdo-oci=D:\\php-sdk\\oracle\\instantclient10\\sdk,shared&quot; &quot;--with-oci8=D:\\php-sdk\\oracle\\instantclient10\\sdk,shared&quot; &quot;--with-oci8-11g=D:\\php-sdk\\oracle\\instantclient11\\sdk,shared&quot; &quot;--enable-object-out-dir=../obj/&quot; &quot;--enable-com-dotnet&quot; &quot;--with-mcrypt=static&quot; </td></tr>\n<tr><td class=\"e\">Server API </td><td class=\"v\">Apache 2.0 Handler </td></tr>\n<tr><td class=\"e\">Virtual Directory Support </td><td class=\"v\">enabled </td></tr>\n<tr><td class=\"e\">Configuration File (php.ini) Path </td><td class=\"v\">C:\\Windows </td></tr>\n<tr><td class=\"e\">Loaded Configuration File </td><td class=\"v\">C:\\PHP\\php.ini </td></tr>\n<tr><td class=\"e\">Scan this dir for additional .ini files </td><td class=\"v\">(none) </td></tr>\n<tr><td class=\"e\">Additional .ini files parsed </td><td class=\"v\">(none) </td></tr>\n<tr><td class=\"e\">PHP API </td><td class=\"v\">20090626 </td></tr>\n<tr><td class=\"e\">PHP Extension </td><td class=\"v\">20090626 </td></tr>\n<tr><td class=\"e\">Zend Extension </td><td class=\"v\">220090626 </td></tr>\n<tr><td class=\"e\">Zend Extension Build </td><td class=\"v\">API220090626,TS,VC9 </td></tr>\n<tr><td class=\"e\">PHP Extension Build </td><td class=\"v\">API20090626,TS,VC9 </td></tr>\n<tr><td class=\"e\">Debug Build </td><td class=\"v\">no </td></tr>\n<tr><td class=\"e\">Thread Safety </td><td class=\"v\">enabled </td></tr>\n<tr><td class=\"e\">Zend Memory Manager </td><td class=\"v\">enabled </td></tr>\n<tr><td class=\"e\">Zend Multibyte Support </td><td class=\"v\">disabled </td></tr>\n<tr><td class=\"e\">IPv6 Support </td><td class=\"v\">enabled </td></tr>\n<tr><td class=\"e\">Registered PHP Streams </td><td class=\"v\">php, file, glob, data, http, ftp, zip, compress.zlib, compress.bzip2, https, ftps, phar   </td></tr>\n<tr><td class=\"e\">Registered Stream Socket Transports </td><td class=\"v\">tcp, udp, ssl, sslv3, sslv2, tls </td></tr>\n<tr><td class=\"e\">Registered Stream Filters </td><td class=\"v\">convert.iconv.*, mcrypt.*, mdecrypt.*, string.rot13, string.toupper, string.tolower, string.strip_tags, convert.*, consumed, dechunk, zlib.*, bzip2.* </td></tr>\n</table><br />\n<table border=\"0\" cellpadding=\"3\" width=\"600\">\n<tr class=\"v\"><td>\n<a href=\"http://www.zend.com/\"><img border=\"0\" src=\"/test.php?=PHPE9568F35-D428-11d2-A769-00AA001ACF42\" alt=\"Zend logo\" /></a>\nThis program makes use of the Zend Scripting Language Engine:<br />Zend&nbsp;Engine&nbsp;v2.3.0,&nbsp;Copyright&nbsp;(c)&nbsp;1998-2011&nbsp;Zend&nbsp;Technologies<br /></td></tr>\n</table><br />\n<hr />\n<h1><a href=\"/test.php?=PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000\">PHP Credits</a></h1>\n<hr />\n<h1>Configuration</h1>\n<h2><a name=\"module_apache2handler\">apache2handler</a></h2>\n<table border=\"0\" cellpadding=\"3\" width=\"600\">\n<tr><td class=\"e\">Apache Version </td><td class=\"v\">Apache/2.2.19 (Win32) PHP/5.3.6 </td></tr>\n<tr><td class=\"e\">Apache API Version </td><td class=\"v\">20051115 </td></tr>\n<tr><td class=\"e\">Server Administrator </td><td class=\"v\">admin@denimgroup.com </td></tr>\n<tr><td class=\"e\">Hostname:Port </td><td class=\"v\">192.168.1.30:0 </td></tr>\n<tr><td class=\"e\">Max Requests </td><td class=\"v\">Per Child: 0 - Keep Alive: on - Max Per Connection: 100 </td></tr>\n<tr><td class=\"e\">Timeouts </td><td class=\"v\">Connection: 300 - Keep-Alive: 5 </td></tr>\n<tr><td class=\"e\">Virtual Server </td><td class=\"v\">No </td></tr>\n<tr><td class=\"e\">Server Root </td><td class=\"v\">C:/Program Files (x86)/Apache Software Foundation/Apache2.2 </td></tr>\n<tr><td class=\"e\">Loaded Modules </td><td class=\"v\">core mod_win32 mpm_winnt http_core mod_so mod_actions mod_alias mod_asis mod_auth_basic mod_authn_default mod_authn_file mod_authz_default mod_authz_groupfile mod_authz_host mod_authz_user mod_autoindex mod_cgi mod_dir mod_env mod_include mod_isapi mod_log_config mod_mime mod_negotiation mod_setenvif mod_php5 </td></tr>\n</table><br />\n<table border=\"0\" cellpadding=\"3\" width=\"600\">\n<tr class=\"h\"><th>Directive</th><th>Local Value</th><th>Master Value</th></tr>\n<tr><td class=\"e\">engine</td><td class=\"v\">1</td><td class=\"v\">1</td></tr>\n<tr><td class=\"e\">last_modified</td><td class=\"v\">0</td><td class=\"v\">0</td></tr>\n<tr><td class=\"e\">xbithack</td><td class=\"v\">0</td><td class=\"v\">0</td></tr>\n</table><br />\n<h2>Apache Environment</h2>\n<table border=\"0\" cellpadding=\"3\" width=\"600\">\n<tr class=\"h\"><th>Variable</th><th>Value</th></tr>\n<tr><td class=\"e\">HTTP_ACCEPT </td><td class=\"v\">*/* </td></tr>\n<tr><td class=\"e\">HTTP_ACCEPT_LANGUAGE </td><td class=\"v\">en-US </td></tr>\n<tr><td class=\"e\">HTTP_USER_AGENT </td><td class=\"v\">Mozilla/4.0 (compatible; MSIE 6.0; Win32) </td></tr>\n<tr><td class=\"e\">HTTP_HOST </td><td class=\"v\">tftarget </td></tr>\n<tr><td class=\"e\">PATH </td><td class=\"v\">C:\\Program Files (x86)\\PHP\\;C:\\Windows\\system32;C:\\Windows;C:\\Windows\\System32\\Wbem;C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\;c:\\Program Files (x86)\\Microsoft SQL Server\\100\\Tools\\Binn\\;c:\\Program Files (x86)\\Microsoft SQL Server\\100\\DTS\\Binn\\;c:\\Program Files (x86)\\Microsoft SQL Server\\100\\Tools\\Binn\\VSShell\\Common7\\IDE\\;C:\\Program Files (x86)\\MySQL\\MySQL Server 5.5\\bin;C:\\Program Files (x86)\\OpenLDAP\\kfw\\Binary;C:\\Program Files (x86)\\MIT\\Kerberos\\bin;C:\\PHP\\;C:\\Program Files (x86)\\OpenSSH\\bin </td></tr>\n<tr><td class=\"e\">SystemRoot </td><td class=\"v\">C:\\Windows </td></tr>\n<tr><td class=\"e\">COMSPEC </td><td class=\"v\">C:\\Windows\\system32\\cmd.exe </td></tr>\n<tr><td class=\"e\">PATHEXT </td><td class=\"v\">.COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC </td></tr>\n<tr><td class=\"e\">WINDIR </td><td class=\"v\">C:\\Windows </td></tr>\n<tr><td class=\"e\">SERVER_SIGNATURE </td><td class=\"v\"><i>no value</i> </td></tr>\n<tr><td class=\"e\">SERVER_SOFTWARE </td><td class=\"v\">Apache/2.2.19 (Win32) PHP/5.3.6 </td></tr>\n<tr><td class=\"e\">SERVER_NAME </td><td class=\"v\">tftarget </td></tr>\n<tr><td class=\"e\">SERVER_ADDR </td><td class=\"v\">10.2.10.111 </td></tr>\n<tr><td class=\"e\">SERVER_PORT </td><td class=\"v\">80 </td></tr>\n<tr><td class=\"e\">REMOTE_ADDR </td><td class=\"v\">10.2.1.48 </td></tr>\n<tr><td class=\"e\">DOCUMENT_ROOT </td><td class=\"v\">C:/Program Files (x86)/Apache Software Foundation/Apache2.2/htdocs </td></tr>\n<tr><td class=\"e\">SERVER_ADMIN </td><td class=\"v\">admin@denimgroup.com </td></tr>\n<tr><td class=\"e\">SCRIPT_FILENAME </td><td class=\"v\">C:/Program Files (x86)/Apache Software Foundation/Apache2.2/htdocs/test.php </td></tr>\n<tr><td class=\"e\">REMOTE_PORT </td><td class=\"v\">3029 </td></tr>\n<tr><td class=\"e\">GATEWAY_INTERFACE </td><td class=\"v\">CGI/1.1 </td></tr>\n<tr><td class=\"e\">SERVER_PROTOCOL </td><td class=\"v\">HTTP/1.0 </td></tr>\n<tr><td class=\"e\">REQUEST_METHOD </td><td class=\"v\">GET </td></tr>\n<tr><td class=\"e\">QUERY_STRING </td><td class=\"v\"><i>no value</i> </td></tr>\n<tr><td class=\"e\">REQUEST_URI </td><td class=\"v\">/test.php </td></tr>\n<tr><td class=\"e\">SCRIPT_NAME </td><td class=\"v\">/test.php </td></tr>\n</table><br />\n<h2>HTTP Headers Information</h2>\n<table border=\"0\" cellpadding=\"3\" width=\"600\">\n<tr class=\"h\"><th colspan=\"2\">HTTP Request Headers</th></tr>\n<tr><td class=\"e\">HTTP Request </td><td class=\"v\">GET /test.php HTTP/1.0 </td></tr>\n<tr><td class=\"e\">Accept </td><td class=\"v\">*/* </td></tr>\n<tr><td class=\"e\">Accept-Language </td><td class=\"v\">en-US </td></tr>\n<tr><td class=\"e\">User-Agent </td><td class=\"v\">Mozilla/4.0 (compatible; MSIE 6.0; Win32) </td></tr>\n<tr><td class=\"e\">Host </td><td class=\"v\">tftarget </td></tr>\n<tr class=\"h\"><th colspan=\"2\">HTTP Response Headers</th></tr>\n<tr><td class=\"e\">X-Powered-By </td><td class=\"v\">PHP/5.3.6 </td></tr>\n<tr><td class=\"e\">Connection </td><td class=\"v\">close </td></tr>\n<tr><td class=\"e\">Content-Type </td><td class=\"v\">text/html </td></tr>\n</table><br />\n<h2><a name=\"module_bcmath\">bcmath</a></h2>\n<table border=\"0\" cellpadding=\"3\" width=\"600\">\n<tr><td class=\"e\">BCMath support </td><td class=\"v\">enabled </td></tr>\n</table><br />\n<table border=\"0\" cellpadding=\"3\" width=\"600\">\n<tr class=\"h\"><th>Directive</th><th>Local Value</th><th>Master Value</th></tr>\n<tr><td class=\"e\">bcmath.scale</td><td class=\"v\">0</td><td class=\"v\">0</td></tr>\n</table><br />\n<h2><a name=\"module_bz2\">bz2</a></h2>\n<table border=\"0\" cellpadding=\"3\" width=\"600\">\n<tr><td class=\"e\">BZip2 Support </td><td class=\"v\">Enabled </td></tr>\n<tr><td class=\"e\">Stream Wrapper support </td><td class=\"v\">compress.bzip2:// </td></tr>\n<tr><td class=\"e\">Stream Filter support </td><td class=\"v\">bzip2.decompress, bzip2.compress </td></tr>\n<tr><td class=\"e\">BZip2 Version </td><td class=\"v\">1.0.6, 6-Sept-2010 </td></tr>\n</table><br />\n<h2><a name=\"module_calendar\">calendar</a></h2>\n<table border=\"0\" cellpadding=\"3\" width=\"600\">\n<tr><td class=\"e\">Calendar support </td><td class=\"v\">enabled </td></tr>\n</table><br />\n<h2><a name=\"module_com_dotnet\">com_dotnet</a></h2>\n<table border=\"0\" cellpadding=\"3\" width=\"600\">\n<tr class=\"h\"><th>COM support</th><th>enabled</th></tr>\n<tr class=\"h\"><th>DCOM support</th><th>disabled</th></tr>\n<tr class=\"h\"><th>.Net support</th><th>enabled</th></tr>\n</table><br />\n<table border=\"0\" cellpadding=\"3\" width=\"600\">\n<tr class=\"h\"><th>Directive</th><th>Local Value</th><th>Master Value</th></tr>\n<tr><td class=\"e\">com.allow_dcom</td><td class=\"v\">0</td><td class=\"v\">0</td></tr>\n<tr><td class=\"e\">com.autoregister_casesensitive</td><td class=\"v\">1</td><td class=\"v\">1</td></tr>\n<tr><td class=\"e\">com.autoregister_typelib</td><td class=\"v\">0</td><td class=\"v\">0</td></tr>\n<tr><td class=\"e\">com.autoregister_verbose</td><td class=\"v\">0</td><td class=\"v\">0</td></tr>\n<tr><td class=\"e\">com.code_page</td><td class=\"v\"><i>no value</i></td><td class=\"v\"><i>no value</i></td></tr>\n<tr><td class=\"e\">com.typelib_file</td><td class=\"v\"><i>no value</i></td><td class=\"v\"><i>no value</i></td></tr>\n</table><br />\n<h2><a name=\"module_Core\">Core</a></h2>\n<table border=\"0\" cellpadding=\"3\" width=\"600\">\n<tr><td class=\"e\">PHP Version </td><td class=\"v\">5.3.6 </td></tr>\n</table><br />\n<table border=\"0\" cellpadding=\"3\" width=\"600\">\n<tr class=\"h\"><th>Directive</th><th>Local Value</th><th>Master Value</th></tr>\n<tr><td class=\"e\">allow_call_time_pass_reference</td><td class=\"v\">Off</td><td class=\"v\">Off</td></tr>\n<tr><td class=\"e\">allow_url_fopen</td><td class=\"v\">On</td><td class=\"v\">On</td></tr>\n<tr><td class=\"e\">allow_url_include</td><td class=\"v\">Off</td><td class=\"v\">Off</td></tr>\n<tr><td class=\"e\">always_populate_raw_post_data</td><td class=\"v\">Off</td><td class=\"v\">Off</td></tr>\n<tr><td class=\"e\">arg_separator.input</td><td class=\"v\">&amp;</td><td class=\"v\">&amp;</td></tr>\n<tr><td class=\"e\">arg_separator.output</td><td class=\"v\">&amp;</td><td class=\"v\">&amp;</td></tr>\n<tr><td class=\"e\">asp_tags</td><td class=\"v\">Off</td><td class=\"v\">Off</td></tr>\n<tr><td class=\"e\">auto_append_file</td><td class=\"v\"><i>no value</i></td><td class=\"v\"><i>no value</i></td></tr>\n<tr><td class=\"e\">auto_globals_jit</td><td class=\"v\">On</td><td class=\"v\">On</td></tr>\n<tr><td class=\"e\">auto_prepend_file</td><td class=\"v\"><i>no value</i></td><td class=\"v\"><i>no value</i></td></tr>\n<tr><td class=\"e\">browscap</td><td class=\"v\"><i>no value</i></td><td class=\"v\"><i>no value</i></td></tr>\n<tr><td class=\"e\">default_charset</td><td class=\"v\"><i>no value</i></td><td class=\"v\"><i>no value</i></td></tr>\n<tr><td class=\"e\">default_mimetype</td><td class=\"v\">text/html</td><td class=\"v\">text/html</td></tr>\n<tr><td class=\"e\">define_syslog_variables</td><td class=\"v\">Off</td><td class=\"v\">Off</td></tr>\n<tr><td class=\"e\">disable_classes</td><td class=\"v\"><i>no value</i></td><td class=\"v\"><i>no value</i></td></tr>\n<tr><td class=\"e\">disable_functions</td><td class=\"v\"><i>no value</i></td><td class=\"v\"><i>no value</i></td></tr>\n<tr><td class=\"e\">display_errors</td><td class=\"v\">On</td><td class=\"v\">On</td></tr>\n<tr><td class=\"e\">display_startup_errors</td><td class=\"v\">Off</td><td class=\"v\">Off</td></tr>\n<tr><td class=\"e\">doc_root</td><td class=\"v\"><i>no value</i></td><td class=\"v\"><i>no value</i></td></tr>\n<tr><td class=\"e\">docref_ext</td><td class=\"v\"><i>no value</i></td><td class=\"v\"><i>no value</i></td></tr>\n<tr><td class=\"e\">docref_root</td><td class=\"v\"><i>no value</i></td><td class=\"v\"><i>no value</i></td></tr>\n<tr><td class=\"e\">enable_dl</td><td class=\"v\">Off</td><td class=\"v\">Off</td></tr>\n<tr><td class=\"e\">error_append_string</td><td class=\"v\"><i>no value</i></td><td class=\"v\"><i>no value</i></td></tr>\n<tr><td class=\"e\">error_log</td><td class=\"v\">C:\\Windows\\temp\\php-errors.log</td><td class=\"v\">C:\\Windows\\temp\\php-errors.log</td></tr>\n<tr><td class=\"e\">error_prepend_string</td><td class=\"v\"><i>no value</i></td><td class=\"v\"><i>no value</i></td></tr>\n<tr><td class=\"e\">error_reporting</td><td class=\"v\">22527</td><td class=\"v\">22527</td></tr>\n<tr><td class=\"e\">exit_on_timeout</td><td class=\"v\">Off</td><td class=\"v\">Off</td></tr>\n<tr><td class=\"e\">expose_php</td><td class=\"v\">On</td><td class=\"v\">On</td></tr>\n<tr><td class=\"e\">extension_dir</td><td class=\"v\">C:\\PHP\\ext</td><td class=\"v\">C:\\PHP\\ext</td></tr>\n<tr><td class=\"e\">file_uploads</td><td class=\"v\">On</td><td class=\"v\">On</td></tr>\n<tr><td class=\"e\">highlight.bg</td><td class=\"v\"><font style=\"color: #FFFFFF\">#FFFFFF</font></td><td class=\"v\"><font style=\"color: #FFFFFF\">#FFFFFF</font></td></tr>\n<tr><td class=\"e\">highlight.comment</td><td class=\"v\"><font style=\"color: #FF8000\">#FF8000</font></td><td class=\"v\"><font style=\"color: #FF8000\">#FF8000</font></td></tr>\n<tr><td class=\"e\">highlight.default</td><td class=\"v\"><font style=\"color: #0000BB\">#0000BB</font></td><td class=\"v\"><font style=\"color: #0000BB\">#0000BB</font></td></tr>\n<tr><td class=\"e\">highlight.html</td><td class=\"v\"><font style=\"color: #000000\">#000000</font></td><td class=\"v\"><font style=\"color: #000000\">#000000</font></td></tr>\n<tr><td class=\"e\">highlight.keyword</td><td class=\"v\"><font style=\"color: #007700\">#007700</font></td><td class=\"v\"><font style=\"color: #007700\">#007700</font></td></tr>\n<tr><td class=\"e\">highlight.string</td><td class=\"v\"><font style=\"color: #DD0000\">#DD0000</font></td><td class=\"v\"><font style=\"color: #DD0000\">#DD0000</font></td></tr>\n<tr><td class=\"e\">html_errors</td><td class=\"v\">Off</td><td class=\"v\">Off</td></tr>\n<tr><td class=\"e\">ignore_repeated_errors</td><td class=\"v\">Off</td><td class=\"v\">Off</td></tr>\n<tr><td class=\"e\">ignore_repeated_source</td><td class=\"v\">Off</td><td class=\"v\">Off</td></tr>\n<tr><td class=\"e\">ignore_user_abort</td><td class=\"v\">Off</td><td class=\"v\">Off</td></tr>\n<tr><td class=\"e\">implicit_flush</td><td class=\"v\">Off</td><td class=\"v\">Off</td></tr>\n<tr><td class=\"e\">include_path</td><td class=\"v\">.;C:\\php\\pear</td><td class=\"v\">.;C:\\php\\pear</td></tr>\n<tr><td class=\"e\">log_errors</td><td class=\"v\">On</td><td class=\"v\">On</td></tr>\n<tr><td class=\"e\">log_errors_max_len</td><td class=\"v\">1024</td><td class=\"v\">1024</td></tr>\n<tr><td class=\"e\">magic_quotes_gpc</td><td class=\"v\">Off</td><td class=\"v\">Off</td></tr>\n<tr><td class=\"e\">magic_quotes_runtime</td><td class=\"v\">Off</td><td class=\"v\">Off</td></tr>\n<tr><td class=\"e\">magic_quotes_sybase</td><td class=\"v\">Off</td><td class=\"v\">Off</td></tr>\n<tr><td class=\"e\">mail.add_x_header</td><td class=\"v\">On</td><td class=\"v\">On</td></tr>\n<tr><td class=\"e\">mail.force_extra_parameters</td><td class=\"v\"><i>no value</i></td><td class=\"v\"><i>no value</i></td></tr>\n<tr><td class=\"e\">mail.log</td><td class=\"v\"><i>no value</i></td><td class=\"v\"><i>no value</i></td></tr>\n<tr><td class=\"e\">max_execution_time</td><td class=\"v\">30</td><td class=\"v\">30</td></tr>\n<tr><td class=\"e\">max_file_uploads</td><td class=\"v\">20</td><td class=\"v\">20</td></tr>\n<tr><td class=\"e\">max_input_nesting_level</td><td class=\"v\">64</td><td class=\"v\">64</td></tr>\n<tr><td class=\"e\">max_input_time</td><td class=\"v\">60</td><td class=\"v\">60</td></tr>\n<tr><td class=\"e\">memory_limit</td><td class=\"v\">128M</td><td class=\"v\">128M</td></tr>\n<tr><td class=\"e\">open_basedir</td><td class=\"v\"><i>no value</i></td><td class=\"v\"><i>no value</i></td></tr>\n<tr><td class=\"e\">output_buffering</td><td class=\"v\">4096</td><td class=\"v\">4096</td></tr>\n<tr><td class=\"e\">output_handler</td><td class=\"v\"><i>no value</i></td><td class=\"v\"><i>no value</i></td></tr>\n<tr><td class=\"e\">post_max_size</td><td class=\"v\">8M</td><td class=\"v\">8M</td></tr>\n<tr><td class=\"e\">precision</td><td class=\"v\">14</td><td class=\"v\">14</td></tr>\n<tr><td class=\"e\">realpath_cache_size</td><td class=\"v\">16K</td><td class=\"v\">16K</td></tr>\n<tr><td class=\"e\">realpath_cache_ttl</td><td class=\"v\">120</td><td class=\"v\">120</td></tr>\n<tr><td class=\"e\">register_argc_argv</td><td class=\"v\">Off</td><td class=\"v\">Off</td></tr>\n<tr><td class=\"e\">register_globals</td><td class=\"v\">Off</td><td class=\"v\">Off</td></tr>\n<tr><td class=\"e\">register_long_arrays</td><td class=\"v\">Off</td><td class=\"v\">Off</td></tr>\n<tr><td class=\"e\">report_memleaks</td><td class=\"v\">On</td><td class=\"v\">On</td></tr>\n<tr><td class=\"e\">report_zend_debug</td><td class=\"v\">On</td><td class=\"v\">On</td></tr>\n<tr><td class=\"e\">request_order</td><td class=\"v\">GP</td><td class=\"v\">GP</td></tr>\n<tr><td class=\"e\">safe_mode</td><td class=\"v\">Off</td><td class=\"v\">Off</td></tr>\n<tr><td class=\"e\">safe_mode_exec_dir</td><td class=\"v\"><i>no value</i></td><td class=\"v\"><i>no value</i></td></tr>\n<tr><td class=\"e\">safe_mode_gid</td><td class=\"v\">Off</td><td class=\"v\">Off</td></tr>\n<tr><td class=\"e\">safe_mode_include_dir</td><td class=\"v\"><i>no value</i></td><td class=\"v\"><i>no value</i></td></tr>\n<tr><td class=\"e\">sendmail_from</td><td class=\"v\"><i>no value</i></td><td class=\"v\"><i>no value</i></td></tr>\n<tr><td class=\"e\">sendmail_path</td><td class=\"v\"><i>no value</i></td><td class=\"v\"><i>no value</i></td></tr>\n<tr><td class=\"e\">serialize_precision</td><td class=\"v\">17</td><td class=\"v\">17</td></tr>\n<tr><td class=\"e\">short_open_tag</td><td class=\"v\">Off</td><td class=\"v\">Off</td></tr>\n<tr><td class=\"e\">SMTP</td><td class=\"v\">localhost</td><td class=\"v\">localhost</td></tr>\n<tr><td class=\"e\">smtp_port</td><td class=\"v\">25</td><td class=\"v\">25</td></tr>\n<tr><td class=\"e\">sql.safe_mode</td><td class=\"v\">Off</td><td class=\"v\">Off</td></tr>\n<tr><td class=\"e\">track_errors</td><td class=\"v\">Off</td><td class=\"v\">Off</td></tr>\n<tr><td class=\"e\">unserialize_callback_func</td><td class=\"v\"><i>no value</i></td><td class=\"v\"><i>no value</i></td></tr>\n<tr><td class=\"e\">upload_max_filesize</td><td class=\"v\">2M</td><td class=\"v\">2M</td></tr>\n<tr><td class=\"e\">upload_tmp_dir</td><td class=\"v\">C:\\Windows\\Temp</td><td class=\"v\">C:\\Windows\\Temp</td></tr>\n<tr><td class=\"e\">user_dir</td><td class=\"v\"><i>no value</i></td><td class=\"v\"><i>no value</i></td></tr>\n<tr><td class=\"e\">user_ini.cache_ttl</td><td class=\"v\">300</td><td class=\"v\">300</td></tr>\n<tr><td class=\"e\">user_ini.filename</td><td class=\"v\">.user.ini</td><td class=\"v\">.user.ini</td></tr>\n<tr><td class=\"e\">variables_order</td><td class=\"v\">GPCS</td><td class=\"v\">GPCS</td></tr>\n<tr><td class=\"e\">xmlrpc_error_number</td><td class=\"v\">0</td><td class=\"v\">0</td></tr>\n<tr><td class=\"e\">xmlrpc_errors</td><td class=\"v\">Off</td><td class=\"v\">Off</td></tr>\n<tr><td class=\"e\">y2k_compliance</td><td class=\"v\">On</td><td class=\"v\">On</td></tr>\n<tr><td class=\"e\">zend.enable_gc</td><td class=\"v\">On</td><td class=\"v\">On</td></tr>\n</table><br />\n<h2><a name=\"module_ctype\">ctype</a></h2>\n<table border=\"0\" cellpadding=\"3\" width=\"600\">\n<tr><td class=\"e\">ctype functions </td><td class=\"v\">enabled </td></tr>\n</table><br />\n<h2><a name=\"module_curl\">curl</a></h2>\n<table border=\"0\" cellpadding=\"3\" width=\"600\">\n<tr><td class=\"e\">cURL support </td><td class=\"v\">enabled </td></tr>\n<tr><td class=\"e\">cURL Information </td><td class=\"v\">7.21.2 </td></tr>\n<tr><td class=\"e\">Age </td><td class=\"v\">3 </td></tr>\n<tr><td class=\"e\">Features </td></tr>\n<tr><td class=\"e\">AsynchDNS </td><td class=\"v\">Yes </td></tr>\n<tr><td class=\"e\">Debug </td><td class=\"v\">No </td></tr>\n<tr><td class=\"e\">GSS-Negotiate </td><td class=\"v\">No </td></tr>\n<tr><td class=\"e\">IDN </td><td class=\"v\">No </td></tr>\n<tr><td class=\"e\">IPv6 </td><td class=\"v\">Yes </td></tr>\n<tr><td class=\"e\">Largefile </td><td class=\"v\">Yes </td></tr>\n<tr><td class=\"e\">NTLM </td><td class=\"v\">Yes </td></tr>\n<tr><td class=\"e\">SPNEGO </td><td class=\"v\">No </td></tr>\n<tr><td class=\"e\">SSL </td><td class=\"v\">Yes </td></tr>\n<tr><td class=\"e\">SSPI </td><td class=\"v\">Yes </td></tr>\n<tr><td class=\"e\">krb4 </td><td class=\"v\">No </td></tr>\n<tr><td class=\"e\">libz </td><td class=\"v\">Yes </td></tr>\n<tr><td class=\"e\">CharConv </td><td class=\"v\">No </td></tr>\n<tr><td class=\"e\">Protocols </td><td class=\"v\">dict, file, ftp, ftps, gopher, http, https, imap, imaps, ldap, pop3, pop3s, rtsp, scp, sftp, smtp, smtps, telnet, tftp </td></tr>\n<tr><td class=\"e\">Host </td><td class=\"v\">i386-pc-win32 </td></tr>\n<tr><td class=\"e\">SSL Version </td><td class=\"v\">OpenSSL/0.9.8r </td></tr>\n<tr><td class=\"e\">ZLib Version </td><td class=\"v\">1.2.3 </td></tr>\n<tr><td class=\"e\">libSSH Version </td><td class=\"v\">libssh2/1.2.7 </td></tr>\n</table><br />\n<h2><a name=\"module_date\">date</a></h2>\n<table border=\"0\" cellpadding=\"3\" width=\"600\">\n<tr><td class=\"e\">date/time support </td><td class=\"v\">enabled </td></tr>\n<tr><td class=\"e\">&quot;Olson&quot; Timezone Database Version </td><td class=\"v\">2011.4 </td></tr>\n<tr><td class=\"e\">Timezone Database </td><td class=\"v\">internal </td></tr>\n<tr><td class=\"e\">Default timezone </td><td class=\"v\">America/Chicago </td></tr>\n</table><br />\n<table border=\"0\" cellpadding=\"3\" width=\"600\">\n<tr class=\"h\"><th>Directive</th><th>Local Value</th><th>Master Value</th></tr>\n<tr><td class=\"e\">date.default_latitude</td><td class=\"v\">31.7667</td><td class=\"v\">31.7667</td></tr>\n<tr><td class=\"e\">date.default_longitude</td><td class=\"v\">35.2333</td><td class=\"v\">35.2333</td></tr>\n<tr><td class=\"e\">date.sunrise_zenith</td><td class=\"v\">90.583333</td><td class=\"v\">90.583333</td></tr>\n<tr><td class=\"e\">date.sunset_zenith</td><td class=\"v\">90.583333</td><td class=\"v\">90.583333</td></tr>\n<tr><td class=\"e\">date.timezone</td><td class=\"v\">America/Chicago</td><td class=\"v\">America/Chicago</td></tr>\n</table><br />\n<h2><a name=\"module_dom\">dom</a></h2>\n<table border=\"0\" cellpadding=\"3\" width=\"600\">\n<tr><td class=\"e\">DOM/XML </td><td class=\"v\">enabled </td></tr>\n<tr><td class=\"e\">DOM/XML API Version </td><td class=\"v\">20031129 </td></tr>\n<tr><td class=\"e\">libxml Version </td><td class=\"v\">2.7.7 </td></tr>\n<tr><td class=\"e\">HTML Support </td><td class=\"v\">enabled </td></tr>\n<tr><td class=\"e\">XPath Support </td><td class=\"v\">enabled </td></tr>\n<tr><td class=\"e\">XPointer Support </td><td class=\"v\">enabled </td></tr>\n<tr><td class=\"e\">Schema Support </td><td class=\"v\">enabled </td></tr>\n<tr><td class=\"e\">RelaxNG Support </td><td class=\"v\">enabled </td></tr>\n</table><br />\n<h2><a name=\"module_ereg\">ereg</a></h2>\n<table border=\"0\" cellpadding=\"3\" width=\"600\">\n<tr><td class=\"e\">Regex Library </td><td class=\"v\">Bundled library enabled </td></tr>\n</table><br />\n<h2><a name=\"module_exif\">exif</a></h2>\n<table border=\"0\" cellpadding=\"3\" width=\"600\">\n<tr><td class=\"e\">EXIF Support </td><td class=\"v\">enabled </td></tr>\n<tr><td class=\"e\">EXIF Version </td><td class=\"v\">1.4 $Id: exif.c 308362 2011-02-15 14:02:26Z pajoye $ </td></tr>\n<tr><td class=\"e\">Supported EXIF Version </td><td class=\"v\">0220 </td></tr>\n<tr><td class=\"e\">Supported filetypes </td><td class=\"v\">JPEG,TIFF </td></tr>\n</table><br />\n<table border=\"0\" cellpadding=\"3\" width=\"600\">\n<tr class=\"h\"><th>Directive</th><th>Local Value</th><th>Master Value</th></tr>\n<tr><td class=\"e\">exif.decode_jis_intel</td><td class=\"v\">JIS</td><td class=\"v\">JIS</td></tr>\n<tr><td class=\"e\">exif.decode_jis_motorola</td><td class=\"v\">JIS</td><td class=\"v\">JIS</td></tr>\n<tr><td class=\"e\">exif.decode_unicode_intel</td><td class=\"v\">UCS-2LE</td><td class=\"v\">UCS-2LE</td></tr>\n<tr><td class=\"e\">exif.decode_unicode_motorola</td><td class=\"v\">UCS-2BE</td><td class=\"v\">UCS-2BE</td></tr>\n<tr><td class=\"e\">exif.encode_jis</td><td class=\"v\"><i>no value</i></td><td class=\"v\"><i>no value</i></td></tr>\n<tr><td class=\"e\">exif.encode_unicode</td><td class=\"v\">ISO-8859-15</td><td class=\"v\">ISO-8859-15</td></tr>\n</table><br />\n<h2><a name=\"module_filter\">filter</a></h2>\n<table border=\"0\" cellpadding=\"3\" width=\"600\">\n<tr><td class=\"e\">Input Validation and Filtering </td><td class=\"v\">enabled </td></tr>\n<tr><td class=\"e\">Revision </td><td class=\"v\">$Revision: 306939 $ </td></tr>\n</table><br />\n<table border=\"0\" cellpadding=\"3\" width=\"600\">\n<tr class=\"h\"><th>Directive</th><th>Local Value</th><th>Master Value</th></tr>\n<tr><td class=\"e\">filter.default</td><td class=\"v\">unsafe_raw</td><td class=\"v\">unsafe_raw</td></tr>\n<tr><td class=\"e\">filter.default_flags</td><td class=\"v\"><i>no value</i></td><td class=\"v\"><i>no value</i></td></tr>\n</table><br />\n<h2><a name=\"module_ftp\">ftp</a></h2>\n<table border=\"0\" cellpadding=\"3\" width=\"600\">\n<tr><td class=\"e\">FTP support </td><td class=\"v\">enabled </td></tr>\n</table><br />\n<h2><a name=\"module_gd\">gd</a></h2>\n<table border=\"0\" cellpadding=\"3\" width=\"600\">\n<tr><td class=\"e\">GD Support </td><td class=\"v\">enabled </td></tr>\n<tr><td class=\"e\">GD Version </td><td class=\"v\">bundled (2.0.34 compatible) </td></tr>\n<tr><td class=\"e\">FreeType Support </td><td class=\"v\">enabled </td></tr>\n<tr><td class=\"e\">FreeType Linkage </td><td class=\"v\">with freetype </td></tr>\n<tr><td class=\"e\">FreeType Version </td><td class=\"v\">2.4.3 </td></tr>\n<tr><td class=\"e\">GIF Read Support </td><td class=\"v\">enabled </td></tr>\n<tr><td class=\"e\">GIF Create Support </td><td class=\"v\">enabled </td></tr>\n<tr><td class=\"e\">JPEG Support </td><td class=\"v\">enabled </td></tr>\n<tr><td class=\"e\">libJPEG Version </td><td class=\"v\">6b </td></tr>\n<tr><td class=\"e\">PNG Support </td><td class=\"v\">enabled </td></tr>\n<tr><td class=\"e\">libPNG Version </td><td class=\"v\">1.2.44 </td></tr>\n<tr><td class=\"e\">WBMP Support </td><td class=\"v\">enabled </td></tr>\n<tr><td class=\"e\">XBM Support </td><td class=\"v\">enabled </td></tr>\n</table><br />\n<table border=\"0\" cellpadding=\"3\" width=\"600\">\n<tr class=\"h\"><th>Directive</th><th>Local Value</th><th>Master Value</th></tr>\n<tr><td class=\"e\">gd.jpeg_ignore_warning</td><td class=\"v\">0</td><td class=\"v\">0</td></tr>\n</table><br />\n<h2><a name=\"module_gettext\">gettext</a></h2>\n<table border=\"0\" cellpadding=\"3\" width=\"600\">\n<tr><td class=\"e\">GetText Support </td><td class=\"v\">enabled </td></tr>\n</table><br />\n<h2><a name=\"module_gmp\">gmp</a></h2>\n<table border=\"0\" cellpadding=\"3\" width=\"600\">\n<tr><td class=\"e\">gmp support </td><td class=\"v\">enabled </td></tr>\n<tr><td class=\"e\">MPIR version </td><td class=\"v\">1.3.1 </td></tr>\n</table><br />\n<h2><a name=\"module_hash\">hash</a></h2>\n<table border=\"0\" cellpadding=\"3\" width=\"600\">\n<tr><td class=\"e\">hash support </td><td class=\"v\">enabled </td></tr>\n<tr><td class=\"e\">Hashing Engines </td><td class=\"v\">md2 md4 md5 sha1 sha224 sha256 sha384 sha512 ripemd128 ripemd160 ripemd256 ripemd320 whirlpool tiger128,3 tiger160,3 tiger192,3 tiger128,4 tiger160,4 tiger192,4 snefru snefru256 gost adler32 crc32 crc32b salsa10 salsa20 haval128,3 haval160,3 haval192,3 haval224,3 haval256,3 haval128,4 haval160,4 haval192,4 haval224,4 haval256,4 haval128,5 haval160,5 haval192,5 haval224,5 haval256,5  </td></tr>\n</table><br />\n<h2><a name=\"module_iconv\">iconv</a></h2>\n<table border=\"0\" cellpadding=\"3\" width=\"600\">\n<tr><td class=\"e\">iconv support </td><td class=\"v\">enabled </td></tr>\n<tr><td class=\"e\">iconv implementation </td><td class=\"v\">&quot;libiconv&quot; </td></tr>\n<tr><td class=\"e\">iconv library version </td><td class=\"v\">1.11 </td></tr>\n</table><br />\n<table border=\"0\" cellpadding=\"3\" width=\"600\">\n<tr class=\"h\"><th>Directive</th><th>Local Value</th><th>Master Value</th></tr>\n<tr><td class=\"e\">iconv.input_encoding</td><td class=\"v\">ISO-8859-1</td><td class=\"v\">ISO-8859-1</td></tr>\n<tr><td class=\"e\">iconv.internal_encoding</td><td class=\"v\">ISO-8859-1</td><td class=\"v\">ISO-8859-1</td></tr>\n<tr><td class=\"e\">iconv.output_encoding</td><td class=\"v\">ISO-8859-1</td><td class=\"v\">ISO-8859-1</td></tr>\n</table><br />\n<h2><a name=\"module_imap\">imap</a></h2>\n<table border=\"0\" cellpadding=\"3\" width=\"600\">\n<tr><td class=\"e\">IMAP c-Client Version </td><td class=\"v\">2007e </td></tr>\n<tr><td class=\"e\">SSL Support </td><td class=\"v\">enabled </td></tr>\n</table><br />\n<h2><a name=\"module_json\">json</a></h2>\n<table border=\"0\" cellpadding=\"3\" width=\"600\">\n<tr><td class=\"e\">json support </td><td class=\"v\">enabled </td></tr>\n<tr><td class=\"e\">json version </td><td class=\"v\">1.2.1 </td></tr>\n</table><br />\n<h2><a name=\"module_ldap\">ldap</a></h2>\n<table border=\"0\" cellpadding=\"3\" width=\"600\">\n<tr><td class=\"e\">LDAP Support </td><td class=\"v\">enabled </td></tr>\n<tr><td class=\"e\">RCS Version </td><td class=\"v\">$Id: ldap.c 306939 2011-01-01 02:19:59Z felipe $ </td></tr>\n<tr><td class=\"e\">Total Links </td><td class=\"v\">0/unlimited </td></tr>\n<tr><td class=\"e\">API Version </td><td class=\"v\">3001 </td></tr>\n<tr><td class=\"e\">Vendor Name </td><td class=\"v\">OpenLDAP </td></tr>\n<tr><td class=\"e\">Vendor Version </td><td class=\"v\">20319 </td></tr>\n<tr><td class=\"e\">SASL Support </td><td class=\"v\">Enabled </td></tr>\n</table><br />\n<table border=\"0\" cellpadding=\"3\" width=\"600\">\n<tr class=\"h\"><th>Directive</th><th>Local Value</th><th>Master Value</th></tr>\n<tr><td class=\"e\">ldap.max_links</td><td class=\"v\">Unlimited</td><td class=\"v\">Unlimited</td></tr>\n</table><br />\n<h2><a name=\"module_libxml\">libxml</a></h2>\n<table border=\"0\" cellpadding=\"3\" width=\"600\">\n<tr><td class=\"e\">libXML support </td><td class=\"v\">active </td></tr>\n<tr><td class=\"e\">libXML Compiled Version </td><td class=\"v\">2.7.7 </td></tr>\n<tr><td class=\"e\">libXML Loaded Version </td><td class=\"v\">20707 </td></tr>\n<tr><td class=\"e\">libXML streams </td><td class=\"v\">enabled </td></tr>\n</table><br />\n<h2><a name=\"module_mbstring\">mbstring</a></h2>\n<table border=\"0\" cellpadding=\"3\" width=\"600\">\n<tr><td class=\"e\">Multibyte Support </td><td class=\"v\">enabled </td></tr>\n<tr><td class=\"e\">Multibyte string engine </td><td class=\"v\">libmbfl </td></tr>\n<tr><td class=\"e\">HTTP input encoding translation </td><td class=\"v\">disabled </td></tr>\n</table><br />\n<table border=\"0\" cellpadding=\"3\" width=\"600\">\n<tr class=\"h\"><th>mbstring extension makes use of \"streamable kanji code filter and converter\", which is distributed under the GNU Lesser General Public License version 2.1.</th></tr>\n</table><br />\n<table border=\"0\" cellpadding=\"3\" width=\"600\">\n<tr><td class=\"e\">Multibyte (japanese) regex support </td><td class=\"v\">enabled </td></tr>\n<tr><td class=\"e\">Multibyte regex (oniguruma) version </td><td class=\"v\">4.7.1 </td></tr>\n</table><br />\n<table border=\"0\" cellpadding=\"3\" width=\"600\">\n<tr class=\"h\"><th>Directive</th><th>Local Value</th><th>Master Value</th></tr>\n<tr><td class=\"e\">mbstring.detect_order</td><td class=\"v\"><i>no value</i></td><td class=\"v\"><i>no value</i></td></tr>\n<tr><td class=\"e\">mbstring.encoding_translation</td><td class=\"v\">Off</td><td class=\"v\">Off</td></tr>\n<tr><td class=\"e\">mbstring.func_overload</td><td class=\"v\">0</td><td class=\"v\">0</td></tr>\n<tr><td class=\"e\">mbstring.http_input</td><td class=\"v\">pass</td><td class=\"v\">pass</td></tr>\n<tr><td class=\"e\">mbstring.http_output</td><td class=\"v\">pass</td><td class=\"v\">pass</td></tr>\n<tr><td class=\"e\">mbstring.http_output_conv_mimetypes</td><td class=\"v\">^(text/|application/xhtml\\+xml)</td><td class=\"v\">^(text/|application/xhtml\\+xml)</td></tr>\n<tr><td class=\"e\">mbstring.internal_encoding</td><td class=\"v\"><i>no value</i></td><td class=\"v\"><i>no value</i></td></tr>\n<tr><td class=\"e\">mbstring.language</td><td class=\"v\">neutral</td><td class=\"v\">neutral</td></tr>\n<tr><td class=\"e\">mbstring.strict_detection</td><td class=\"v\">Off</td><td class=\"v\">Off</td></tr>\n<tr><td class=\"e\">mbstring.substitute_character</td><td class=\"v\"><i>no value</i></td><td class=\"v\"><i>no value</i></td></tr>\n</table><br />\n<h2><a name=\"module_mcrypt\">mcrypt</a></h2>\n<table border=\"0\" cellpadding=\"3\" width=\"600\">\n<tr class=\"h\"><th>mcrypt support</th><th>enabled</th></tr>\n<tr class=\"h\"><th>mcrypt_filter support</th><th>enabled</th></tr>\n<tr><td class=\"e\">Version </td><td class=\"v\">2.5.8 </td></tr>\n<tr><td class=\"e\">Api No </td><td class=\"v\">20021217 </td></tr>\n<tr><td class=\"e\">Supported ciphers </td><td class=\"v\">cast-128 gost rijndael-128 twofish cast-256 loki97 rijndael-192 saferplus wake blowfish-compat des rijndael-256 serpent xtea blowfish enigma rc2 tripledes arcfour  </td></tr>\n<tr><td class=\"e\">Supported modes </td><td class=\"v\">cbc cfb ctr ecb ncfb nofb ofb stream  </td></tr>\n</table><br />\n<table border=\"0\" cellpadding=\"3\" width=\"600\">\n<tr class=\"h\"><th>Directive</th><th>Local Value</th><th>Master Value</th></tr>\n<tr><td class=\"e\">mcrypt.algorithms_dir</td><td class=\"v\"><i>no value</i></td><td class=\"v\"><i>no value</i></td></tr>\n<tr><td class=\"e\">mcrypt.modes_dir</td><td class=\"v\"><i>no value</i></td><td class=\"v\"><i>no value</i></td></tr>\n</table><br />\n<h2><a name=\"module_mhash\">mhash</a></h2>\n<table border=\"0\" cellpadding=\"3\" width=\"600\">\n<tr><td class=\"e\">MHASH support </td><td class=\"v\">Enabled </td></tr>\n<tr><td class=\"e\">MHASH API Version </td><td class=\"v\">Emulated Support </td></tr>\n</table><br />\n<h2><a name=\"module_mysql\">mysql</a></h2>\n<table border=\"0\" cellpadding=\"3\" width=\"600\">\n<tr class=\"h\"><th>MySQL Support</th><th>enabled</th></tr>\n<tr><td class=\"e\">Active Persistent Links </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">Active Links </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">Client API version </td><td class=\"v\">mysqlnd 5.0.8-dev - 20102224 - $Revision: 308673 $ </td></tr>\n</table><br />\n<table border=\"0\" cellpadding=\"3\" width=\"600\">\n<tr class=\"h\"><th>Directive</th><th>Local Value</th><th>Master Value</th></tr>\n<tr><td class=\"e\">mysql.allow_local_infile</td><td class=\"v\">On</td><td class=\"v\">On</td></tr>\n<tr><td class=\"e\">mysql.allow_persistent</td><td class=\"v\">On</td><td class=\"v\">On</td></tr>\n<tr><td class=\"e\">mysql.connect_timeout</td><td class=\"v\">60</td><td class=\"v\">60</td></tr>\n<tr><td class=\"e\">mysql.default_host</td><td class=\"v\"><i>no value</i></td><td class=\"v\"><i>no value</i></td></tr>\n<tr><td class=\"e\">mysql.default_password</td><td class=\"v\"><i>no value</i></td><td class=\"v\"><i>no value</i></td></tr>\n<tr><td class=\"e\">mysql.default_port</td><td class=\"v\"><i>no value</i></td><td class=\"v\"><i>no value</i></td></tr>\n<tr><td class=\"e\">mysql.default_socket</td><td class=\"v\"><i>no value</i></td><td class=\"v\"><i>no value</i></td></tr>\n<tr><td class=\"e\">mysql.default_user</td><td class=\"v\"><i>no value</i></td><td class=\"v\"><i>no value</i></td></tr>\n<tr><td class=\"e\">mysql.max_links</td><td class=\"v\">Unlimited</td><td class=\"v\">Unlimited</td></tr>\n<tr><td class=\"e\">mysql.max_persistent</td><td class=\"v\">Unlimited</td><td class=\"v\">Unlimited</td></tr>\n<tr><td class=\"e\">mysql.trace_mode</td><td class=\"v\">Off</td><td class=\"v\">Off</td></tr>\n</table><br />\n<h2><a name=\"module_mysqli\">mysqli</a></h2>\n<table border=\"0\" cellpadding=\"3\" width=\"600\">\n<tr class=\"h\"><th>MysqlI Support</th><th>enabled</th></tr>\n<tr><td class=\"e\">Client API library version </td><td class=\"v\">mysqlnd 5.0.8-dev - 20102224 - $Revision: 308673 $ </td></tr>\n<tr><td class=\"e\">Active Persistent Links </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">Inactive Persistent Links </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">Active Links </td><td class=\"v\">0 </td></tr>\n</table><br />\n<table border=\"0\" cellpadding=\"3\" width=\"600\">\n<tr class=\"h\"><th>Directive</th><th>Local Value</th><th>Master Value</th></tr>\n<tr><td class=\"e\">mysqli.allow_local_infile</td><td class=\"v\">On</td><td class=\"v\">On</td></tr>\n<tr><td class=\"e\">mysqli.allow_persistent</td><td class=\"v\">On</td><td class=\"v\">On</td></tr>\n<tr><td class=\"e\">mysqli.default_host</td><td class=\"v\"><i>no value</i></td><td class=\"v\"><i>no value</i></td></tr>\n<tr><td class=\"e\">mysqli.default_port</td><td class=\"v\">3306</td><td class=\"v\">3306</td></tr>\n<tr><td class=\"e\">mysqli.default_pw</td><td class=\"v\"><i>no value</i></td><td class=\"v\"><i>no value</i></td></tr>\n<tr><td class=\"e\">mysqli.default_socket</td><td class=\"v\"><i>no value</i></td><td class=\"v\"><i>no value</i></td></tr>\n<tr><td class=\"e\">mysqli.default_user</td><td class=\"v\"><i>no value</i></td><td class=\"v\"><i>no value</i></td></tr>\n<tr><td class=\"e\">mysqli.max_links</td><td class=\"v\">Unlimited</td><td class=\"v\">Unlimited</td></tr>\n<tr><td class=\"e\">mysqli.max_persistent</td><td class=\"v\">Unlimited</td><td class=\"v\">Unlimited</td></tr>\n<tr><td class=\"e\">mysqli.reconnect</td><td class=\"v\">Off</td><td class=\"v\">Off</td></tr>\n</table><br />\n<h2><a name=\"module_mysqlnd\">mysqlnd</a></h2>\n<table border=\"0\" cellpadding=\"3\" width=\"600\">\n<tr class=\"h\"><th>mysqlnd</th><th>enabled</th></tr>\n<tr><td class=\"e\">Version </td><td class=\"v\">mysqlnd 5.0.8-dev - 20102224 - $Revision: 308673 $ </td></tr>\n<tr><td class=\"e\">Compression </td><td class=\"v\">supported </td></tr>\n<tr><td class=\"e\">SSL </td><td class=\"v\">supported </td></tr>\n<tr><td class=\"e\">Command buffer size </td><td class=\"v\">4096 </td></tr>\n<tr><td class=\"e\">Read buffer size </td><td class=\"v\">32768 </td></tr>\n<tr><td class=\"e\">Read timeout </td><td class=\"v\">31536000 </td></tr>\n<tr><td class=\"e\">Collecting statistics </td><td class=\"v\">Yes </td></tr>\n<tr><td class=\"e\">Collecting memory statistics </td><td class=\"v\">No </td></tr>\n<tr><td class=\"e\">Tracing </td><td class=\"v\">n/a </td></tr>\n</table><br />\n<table border=\"0\" cellpadding=\"3\" width=\"600\">\n<tr class=\"h\"><th>Client statistics</th><th> </th></tr>\n<tr><td class=\"e\">bytes_sent </td><td class=\"v\">53655 </td></tr>\n<tr><td class=\"e\">bytes_received </td><td class=\"v\">112893 </td></tr>\n<tr><td class=\"e\">packets_sent </td><td class=\"v\">3054 </td></tr>\n<tr><td class=\"e\">packets_received </td><td class=\"v\">3445 </td></tr>\n<tr><td class=\"e\">protocol_overhead_in </td><td class=\"v\">13780 </td></tr>\n<tr><td class=\"e\">protocol_overhead_out </td><td class=\"v\">12216 </td></tr>\n<tr><td class=\"e\">bytes_received_ok_packet </td><td class=\"v\">4708 </td></tr>\n<tr><td class=\"e\">bytes_received_eof_packet </td><td class=\"v\">6480 </td></tr>\n<tr><td class=\"e\">bytes_received_rset_header_packet </td><td class=\"v\">4820 </td></tr>\n<tr><td class=\"e\">bytes_received_rset_field_meta_packet </td><td class=\"v\">55583 </td></tr>\n<tr><td class=\"e\">bytes_received_rset_row_packet </td><td class=\"v\">11517 </td></tr>\n<tr><td class=\"e\">bytes_received_prepare_response_packet </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">bytes_received_change_user_packet </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">packets_sent_command </td><td class=\"v\">1167 </td></tr>\n<tr><td class=\"e\">packets_received_ok </td><td class=\"v\">428 </td></tr>\n<tr><td class=\"e\">packets_received_eof </td><td class=\"v\">720 </td></tr>\n<tr><td class=\"e\">packets_received_rset_header </td><td class=\"v\">360 </td></tr>\n<tr><td class=\"e\">packets_received_rset_field_meta </td><td class=\"v\">1023 </td></tr>\n<tr><td class=\"e\">packets_received_rset_row </td><td class=\"v\">554 </td></tr>\n<tr><td class=\"e\">packets_received_prepare_response </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">packets_received_change_user </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">result_set_queries </td><td class=\"v\">341 </td></tr>\n<tr><td class=\"e\">non_result_set_queries </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">no_index_used </td><td class=\"v\">339 </td></tr>\n<tr><td class=\"e\">bad_index_used </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">slow_queries </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">buffered_sets </td><td class=\"v\">341 </td></tr>\n<tr><td class=\"e\">unbuffered_sets </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">ps_buffered_sets </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">ps_unbuffered_sets </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">flushed_normal_sets </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">flushed_ps_sets </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">ps_prepared_never_executed </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">ps_prepared_once_executed </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">rows_fetched_from_server_normal </td><td class=\"v\">213 </td></tr>\n<tr><td class=\"e\">rows_fetched_from_server_ps </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">rows_buffered_from_client_normal </td><td class=\"v\">213 </td></tr>\n<tr><td class=\"e\">rows_buffered_from_client_ps </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">rows_fetched_from_client_normal_buffered </td><td class=\"v\">213 </td></tr>\n<tr><td class=\"e\">rows_fetched_from_client_normal_unbuffered </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">rows_fetched_from_client_ps_buffered </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">rows_fetched_from_client_ps_unbuffered </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">rows_fetched_from_client_ps_cursor </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">rows_affected_normal </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">rows_affected_ps </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">rows_skipped_normal </td><td class=\"v\">213 </td></tr>\n<tr><td class=\"e\">rows_skipped_ps </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">copy_on_write_saved </td><td class=\"v\">639 </td></tr>\n<tr><td class=\"e\">copy_on_write_performed </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">command_buffer_too_small </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">connect_success </td><td class=\"v\">360 </td></tr>\n<tr><td class=\"e\">connect_failure </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">connection_reused </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">reconnect </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">pconnect_success </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">active_connections </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">active_persistent_connections </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">explicit_close </td><td class=\"v\">360 </td></tr>\n<tr><td class=\"e\">implicit_close </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">disconnect_close </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">in_middle_of_command_close </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">explicit_free_result </td><td class=\"v\">341 </td></tr>\n<tr><td class=\"e\">implicit_free_result </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">explicit_stmt_close </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">implicit_stmt_close </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">mem_emalloc_count </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">mem_emalloc_amount </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">mem_ecalloc_count </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">mem_ecalloc_amount </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">mem_erealloc_count </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">mem_erealloc_amount </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">mem_efree_count </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">mem_efree_amount </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">mem_malloc_count </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">mem_malloc_amount </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">mem_calloc_count </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">mem_calloc_amount </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">mem_realloc_count </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">mem_realloc_amount </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">mem_free_count </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">mem_free_amount </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">mem_estrndup_count </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">mem_strndup_count </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">mem_estndup_count </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">mem_strdup_count </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">proto_text_fetched_null </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">proto_text_fetched_bit </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">proto_text_fetched_tinyint </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">proto_text_fetched_short </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">proto_text_fetched_int24 </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">proto_text_fetched_int </td><td class=\"v\">213 </td></tr>\n<tr><td class=\"e\">proto_text_fetched_bigint </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">proto_text_fetched_decimal </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">proto_text_fetched_float </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">proto_text_fetched_double </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">proto_text_fetched_date </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">proto_text_fetched_year </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">proto_text_fetched_time </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">proto_text_fetched_datetime </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">proto_text_fetched_timestamp </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">proto_text_fetched_string </td><td class=\"v\">426 </td></tr>\n<tr><td class=\"e\">proto_text_fetched_blob </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">proto_text_fetched_enum </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">proto_text_fetched_set </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">proto_text_fetched_geometry </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">proto_text_fetched_other </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">proto_binary_fetched_null </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">proto_binary_fetched_bit </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">proto_binary_fetched_tinyint </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">proto_binary_fetched_short </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">proto_binary_fetched_int24 </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">proto_binary_fetched_int </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">proto_binary_fetched_bigint </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">proto_binary_fetched_decimal </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">proto_binary_fetched_float </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">proto_binary_fetched_double </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">proto_binary_fetched_date </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">proto_binary_fetched_year </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">proto_binary_fetched_time </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">proto_binary_fetched_datetime </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">proto_binary_fetched_timestamp </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">proto_binary_fetched_string </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">proto_binary_fetched_blob </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">proto_binary_fetched_enum </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">proto_binary_fetched_set </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">proto_binary_fetched_geometry </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">proto_binary_fetched_other </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">init_command_executed_count </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">init_command_failed_count </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">com_quit </td><td class=\"v\">360 </td></tr>\n<tr><td class=\"e\">com_init_db </td><td class=\"v\">68 </td></tr>\n<tr><td class=\"e\">com_query </td><td class=\"v\">360 </td></tr>\n<tr><td class=\"e\">com_field_list </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">com_create_db </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">com_drop_db </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">com_refresh </td><td class=\"v\">0 </td></tr>\n<tr><td class=\"e\">com_shutdown </td><td ...\n",
//          "attackResponse": null,
//          "nativeId": "7748f5e0070dc48d9741c0b159a63fbf",
//          "displayId": null,
//          "surfaceLocation": {
//            "id": 10,
//            "parameter": null,
//            "path": "/"
//          },
//          "sourceFileLocation": null,
//          "dataFlowElements": [],
//          "calculatedUrlPath": "/",
//          "calculatedFilePath": "",
//          "dependency": null,
//          "severity": "Low",
//          "vulnerabilityType": "Application Test Script Detected"
//        }
//      ],
//    },

// Next finding block

//    {
//      "id": 84,
//      "defect": null,
//      "genericVulnerability": {
//        "id": 200,
//        "name": "Information Exposure",
//        "displayId": 200
//      },
//      "genericSeverity": {
//        "id": 5,
//        "name": "Info",
//        "intValue": 1
//      },
//      "calculatedFilePath": null,
//      "active": true,
//      "isFalsePositive": false,
//      "hidden": false,
//      "findings": [
//        {
//          "id": 94,
//          "longDescription": null,
//          "attackString": null,
//          "attackRequest": "TRACE / HTTP/1.0Host: tftargetCookie: 274ef754a182e499",
//          "attackResponse": "HTTP/1.1 200 OKDate: Mon, 18 Nov 2013 19:43:06 GMTServer: Apache/2.2.19 (Win32) PHP/5.3.6Connection: closeContent-Type: message/httpTRACE / HTTP/1.0Host: tftargetCookie: 274ef754a182e499",
//          "nativeId": "4563171744274440192",
//          "displayId": null,
//          "surfaceLocation": {
//            "id": 94,
//            "parameter": null,
//            "path": "/"
//          },
//          "sourceFileLocation": null,
//          "dataFlowElements": [],
//          "calculatedUrlPath": "/",
//          "calculatedFilePath": "",
//          "dependency": null,
//          "severity": "Information",
//          "vulnerabilityType": "TRACE method is enabled"
//        }
//      ],
//      "documents": [],
//      "vulnerabilityComments": [],
//      "dependency": null,
//      "app": {
//        "id": 1,
//        "name": "TF Demo App",
//        "url": "http://tftarget",
//        "applicationCriticality": {
//          "id": 2,
//          "name": "Medium"
//        }
//      },
//      "team": {
//        "id": 1,
//        "name": "Example Team"
//      },
//      "vulnId": "84",
//      "channelNames": [
//        "Burp Suite"
//      ],
//      "parameter": null,
//      "path": "/"
//    },
//    {
//      "id": 122,
//      "defect": null,
//      "genericVulnerability": {
//        "id": 16,
//        "name": "Configuration",
//        "displayId": 16
//      },
//      "genericSeverity": {
//        "id": 5,
//        "name": "Info",
//        "intValue": 1
//      },
//      "calculatedFilePath": null,
//      "active": true,
//      "isFalsePositive": false,
//      "hidden": false,
//      "findings": [
//        {
//          "id": 180,
//          "longDescription": null,
//          "attackString": null,
//          "attackRequest": null,
//          "attackResponse": null,
//          "nativeId": "97c2b085f9e5a6384faea49396d6f39a",
//          "displayId": null,
//          "surfaceLocation": {
//            "id": 180,
//            "parameter": null,
//            "path": "/"
//          },
//          "sourceFileLocation": null,
//          "dataFlowElements": [],
//          "calculatedUrlPath": "/",
//          "calculatedFilePath": "",
//          "dependency": null,
//          "severity": "0",
//          "vulnerabilityType": "New 'X-*' header value seen"
//        }
//      ],
//      "documents": [],
//      "vulnerabilityComments": [],
//      "dependency": null,
//      "app": {
//        "id": 1,
//        "name": "TF Demo App",
//        "url": "http://tftarget",
//        "applicationCriticality": {
//          "id": 2,
//          "name": "Medium"
//        }
//      },
//      "team": {
//        "id": 1,
//        "name": "Example Team"
//      },
//      "vulnId": "122",
//      "channelNames": [
//        "Skipfish"
//      ],
//      "parameter": null,
//      "path": "/"
//    },
//    {
//      "id": 136,
//      "defect": null,
//      "genericVulnerability": {
//        "id": 548,
//        "name": "Information Exposure Through Directory Listing",
//        "displayId": 548
//      },
//      "genericSeverity": {
//        "id": 5,
//        "name": "Info",
//        "intValue": 1
//      },
//      "calculatedFilePath": null,
//      "active": true,
//      "isFalsePositive": false,
//      "hidden": false,
//      "findings": [
//        {
//          "id": 195,
//          "longDescription": null,
//          "attackString": null,
//          "attackRequest": null,
//          "attackResponse": null,
//          "nativeId": "9d885f462c770e164bbdf7ce27ccdc18",
//          "displayId": null,
//          "surfaceLocation": {
//            "id": 195,
//            "parameter": null,
//            "path": "/"
//          },
//          "sourceFileLocation": null,
//          "dataFlowElements": [],
//          "calculatedUrlPath": "/",
//          "calculatedFilePath": "",
//          "dependency": null,
//          "severity": "0",
//          "vulnerabilityType": "Directory listing enabled"
//        }
//      ],
//      "documents": [],
//      "vulnerabilityComments": [],
//      "dependency": null,
//      "app": {
//        "id": 1,
//        "name": "TF Demo App",
//        "url": "http://tftarget",
//        "applicationCriticality": {
//          "id": 2,
//          "name": "Medium"
//        }
//      },
//      "team": {
//        "id": 1,
//        "name": "Example Team"
//      },
//      "vulnId": "136",
//      "channelNames": [
//        "Skipfish"
//      ],
//      "parameter": null,
//      "path": "/"
//    },
//    {
//      "id": 154,
//      "defect": null,
//      "genericVulnerability": {
//        "id": 16,
//        "name": "Configuration",
//        "displayId": 16
//      },
//      "genericSeverity": {
//        "id": 5,
//        "name": "Info",
//        "intValue": 1
//      },
//      "calculatedFilePath": null,
//      "active": true,
//      "isFalsePositive": false,
//      "hidden": false,
//      "findings": [
//        {
//          "id": 214,
//          "longDescription": null,
//          "attackString": null,
//          "attackRequest": null,
//          "attackResponse": null,
//          "nativeId": "466a171d35086a558614201a750edcb4",
//          "displayId": null,
//          "surfaceLocation": {
//            "id": 214,
//            "parameter": null,
//            "path": "/"
//          },
//          "sourceFileLocation": null,
//          "dataFlowElements": [],
//          "calculatedUrlPath": "/",
//          "calculatedFilePath": "",
//          "dependency": null,
//          "severity": "0",
//          "vulnerabilityType": "New 'Server' header value seen"
//        }
//      ],
//      "documents": [],
//      "vulnerabilityComments": [],
//      "dependency": null,
//      "app": {
//        "id": 1,
//        "name": "TF Demo App",
//        "url": "http://tftarget",
//        "applicationCriticality": {
//          "id": 2,
//          "name": "Medium"
//        }
//      },
//      "team": {
//        "id": 1,
//        "name": "Example Team"
//      },
//      "vulnId": "154",
//      "channelNames": [
//        "Skipfish"
//      ],
//      "parameter": null,
//      "path": "/"
//    },
//    {
//      "id": 215,
//      "defect": null,
//      "genericVulnerability": {
//        "id": 200,
//        "name": "Information Exposure",
//        "displayId": 200
//      },
//      "genericSeverity": {
//        "id": 5,
//        "name": "Info",
//        "intValue": 1
//      },
//      "calculatedFilePath": null,
//      "active": true,
//      "isFalsePositive": false,
//      "hidden": false,
//      "findings": [
//        {
//          "id": 292,
//          "longDescription": null,
//          "attackString": null,
//          "attackRequest": "OPTIONS / HTTP/1.1\nUser-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; SV1; .NET CLR 1.1.4322)\nAccept: */*\nPragma: no-cache\nHost: 10.2.10.73\nX-Scan-Memo: Category=\"Audit\"; Function=\"createStateRequestFromAttackDefinition\"; SID=\"B33E3E3EA5FE9F8615ED9138A91C69D1\"; PSID=\"71EA7BFD4D5506343757C24752102E39\"; SessionType=\"AuditAttack\"; CrawlType=\"None\"; AttackType=\"Other\"; OriginatingEngineID=\"65cee7d3-561f-40dc-b5eb-c0b8c2383fcb\"; AttackSequence=\"0\"; AttackParamDesc=\"\"; AttackParamIndex=\"0\"; AttackParamSubIndex=\"0\"; CheckId=\"10282\"; Engine=\"Request+Modify\"; Retry=\"False\"; SmartMode=\"NonServerSpecificOnly\"; ThreadId=\"281\"; ThreadType=\"AuditDBReaderSessionDrivenAudit\"; \nConnection: Keep-Alive\nCookie: CustomCookie=WebInspect76485ZX827111B5A04946A888F05845D0ACC5A8Y3511\n\n",
//          "attackResponse": null,
//          "nativeId": "2c110b0fb66373f286565f5f0c46f130",
//          "displayId": null,
//          "surfaceLocation": {
//            "id": 292,
//            "parameter": null,
//            "path": "/"
//          },
//          "sourceFileLocation": null,
//          "dataFlowElements": [],
//          "calculatedUrlPath": "/",
//          "calculatedFilePath": "",
//          "dependency": null,
//          "severity": "0",
//          "vulnerabilityType": "OPTIONS Method Supported"
//        }
//      ],
//      "documents": [],
//      "vulnerabilityComments": [],
//      "dependency": null,
//      "app": {
//        "id": 1,
//        "name": "TF Demo App",
//        "url": "http://tftarget",
//        "applicationCriticality": {
//          "id": 2,
//          "name": "Medium"
//        }
//      },
//      "team": {
//        "id": 1,
//        "name": "Example Team"
//      },
//      "vulnId": "215",
//      "channelNames": [
//        "WebInspect"
//      ],
//      "parameter": null,
//      "path": "/"
//    },
//    {
//      "id": 237,
//      "defect": null,
//      "genericVulnerability": {
//        "id": 16,
//        "name": "Configuration",
//        "displayId": 16
//      },
//      "genericSeverity": {
//        "id": 5,
//        "name": "Info",
//        "intValue": 1
//      },
//      "calculatedFilePath": null,
//      "active": true,
//      "isFalsePositive": false,
//      "hidden": false,
//      "findings": [
//        {
//          "id": 317,
//          "longDescription": null,
//          "attackString": "",
//          "attackRequest": null,
//          "attackResponse": null,
//          "nativeId": "7f00f27977d40aca399a12363ab05dfe",
//          "displayId": null,
//          "surfaceLocation": {
//            "id": 317,
//            "parameter": null,
//            "path": "/"
//          },
//          "sourceFileLocation": null,
//          "dataFlowElements": [],
//          "calculatedUrlPath": "/",
//          "calculatedFilePath": "",
//          "dependency": null,
//          "severity": "0",
//          "vulnerabilityType": "X-Frame-Options header not set"
//        }
//      ],
//      "documents": [],
//      "vulnerabilityComments": [],
//      "dependency": null,
//      "app": {
//        "id": 1,
//        "name": "TF Demo App",
//        "url": "http://tftarget",
//        "applicationCriticality": {
//          "id": 2,
//          "name": "Medium"
//        }
//      },
//      "team": {
//        "id": 1,
//        "name": "Example Team"
//      },
//      "vulnId": "237",
//      "channelNames": [
//        "OWASP Zed Attack Proxy"
//      ],
//      "parameter": null,
//      "path": "/"
//    },
//    {
//      "id": 264,
//      "defect": null,
//      "genericVulnerability": {
//        "id": 16,
//        "name": "Configuration",
//        "displayId": 16
//      },
//      "genericSeverity": {
//        "id": 4,
//        "name": "Low",
//        "intValue": 2
//      },
//      "calculatedFilePath": null,
//      "active": true,
//      "isFalsePositive": false,
//      "hidden": false,
//      "findings": [
//        {
//          "id": 345,
//          "longDescription": null,
//          "attackString": "",
//          "attackRequest": null,
//          "attackResponse": null,
//          "nativeId": "2d0a7b83d71dc4b5fcbabd8d7b3845d8",
//          "displayId": null,
//          "surfaceLocation": {
//            "id": 345,
//            "parameter": null,
//            "path": "/"
//          },
//          "sourceFileLocation": null,
//          "dataFlowElements": [],
//          "calculatedUrlPath": "/",
//          "calculatedFilePath": "",
//          "dependency": null,
//          "severity": "1",
//          "vulnerabilityType": "X-Content-Type-Options header missing"
//        }
//      ],
//      "documents": [],
//      "vulnerabilityComments": [],
//      "dependency": null,
//      "app": {
//        "id": 1,
//        "name": "TF Demo App",
//        "url": "http://tftarget",
//        "applicationCriticality": {
//          "id": 2,
//          "name": "Medium"
//        }
//      },
//      "team": {
//        "id": 1,
//        "name": "Example Team"
//      },
//      "vulnId": "264",
//      "channelNames": [
//        "OWASP Zed Attack Proxy"
//      ],
//      "parameter": null,
//      "path": "/"
//    },
//    {
//      "id": 54700,
//      "defect": null,
//      "genericVulnerability": {
//        "id": 311,
//        "name": "Missing Encryption of Sensitive Data",
//        "displayId": 311
//      },
//      "genericSeverity": {
//        "id": 3,
//        "name": "Medium",
//        "intValue": 3
//      },
//      "calculatedFilePath": null,
//      "active": true,
//      "isFalsePositive": false,
//      "hidden": false,
//      "findings": [
//        {
//          "id": 54783,
//          "longDescription": null,
//          "attackString": null,
//          "attackRequest": null,
//          "attackResponse": null,
//          "nativeId": "6d2e6761d1d10ff740d1228b583e87b7",
//          "displayId": "47098787",
//          "surfaceLocation": {
//            "id": 54783,
//            "parameter": null,
//            "path": "/"
//          },
//          "sourceFileLocation": null,
//          "dataFlowElements": [],
//          "calculatedUrlPath": "/",
//          "calculatedFilePath": "",
//          "dependency": null,
//          "severity": "3",
//          "vulnerabilityType": "Insufficient Transport Layer Protection"
//        }
//      ],
//      "documents": [],
//      "vulnerabilityComments": [],
//      "dependency": null,
//      "app": {
//        "id": 2,
//        "name": "Pearson Imports",
//        "url": "http://test.actaspire.org/",
//        "applicationCriticality": {
//          "id": 2,
//          "name": "Medium"
//        }
//      },
//      "team": {
//        "id": 2,
//        "name": "Import Team"
//      },
//      "vulnId": "54700",
//      "channelNames": [
//        "WhiteHat Sentinel"
//      ],
//      "parameter": null,
//      "path": "/"
//    },
//    {
//      "id": 54704,
//      "defect": null,
//      "genericVulnerability": {
//        "id": 290,
//        "name": "Authentication Bypass by Spoofing",
//        "displayId": 290
//      },
//      "genericSeverity": {
//        "id": 3,
//        "name": "Medium",
//        "intValue": 3
//      },
//      "calculatedFilePath": null,
//      "active": true,
//      "isFalsePositive": false,
//      "hidden": false,
//      "findings": [
//        {
//          "id": 54787,
//          "longDescription": null,
//          "attackString": null,
//          "attackRequest": null,
//          "attackResponse": null,
//          "nativeId": "673f98a4334256a7f2cf0baf935c106d",
//          "displayId": "47098769",
//          "surfaceLocation": {
//            "id": 54787,
//            "parameter": null,
//            "path": "/"
//          },
//          "sourceFileLocation": null,
//          "dataFlowElements": [],
//          "calculatedUrlPath": "/",
//          "calculatedFilePath": "",
//          "dependency": null,
//          "severity": "3",
//          "vulnerabilityType": "Content Spoofing"
//        }
//      ],
//      "documents": [],
//      "vulnerabilityComments": [],
//      "dependency": null,
//      "app": {
//        "id": 2,
//        "name": "Pearson Imports",
//        "url": "http://test.actaspire.org/",
//        "applicationCriticality": {
//          "id": 2,
//          "name": "Medium"
//        }
//      },
//      "team": {
//        "id": 2,
//        "name": "Import Team"
//      },
//      "vulnId": "54704",
//      "channelNames": [
//        "WhiteHat Sentinel"
//      ],
//      "parameter": null,
//      "path": "/"
//    }
//  ]
//}
