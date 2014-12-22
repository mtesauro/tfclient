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

// Use to test the conversion of the upload response into a struct
// without having to upload repeatedly

const uploadResponse = `{"message":"","success":true,"responseCode":-1,"object":{"id":72,"importTime":1384804367000,"numberClosedVulnerabilities":0,"numberNewVulnerabilities":29,"numberOldVulnerabilities":0,"numberResurfacedVulnerabilities":0,"numberTotalVulnerabilities":29,"numberRepeatResults":0,"numberRepeatFindings":0,"numberInfoVulnerabilities":25,"numberLowVulnerabilities":0,"numberMediumVulnerabilities":0,"numberHighVulnerabilities":4,"numberCriticalVulnerabilities":0,"findings":[{"id":56336,"longDescription":null,"attackString":null,"attackRequest":"GET /demo/ HTTP/1.1Host: tftargetAccept: */*Accept-Language: enUser-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)Connection: close","attackResponse":"HTTP/1.1 200 OKDate: Mon, 18 Nov 2013 19:43:48 GMTServer: Apache/2.2.19 (Win32) PHP/5.3.6Last-Modified: Thu, 09 Jun 2011 14:24:57 GMTETag: \"2000000023431-384-4a54837b0b761\"Accept-Ranges: bytesContent-Length: 900Connection: closeContent-Type: text/html<!-- XSS TEST - STORED --><!-- The goal is to pull the payload from the database. After that we'll see. --><html>\t<head>\t\t<title>Threadfix Vulnerability Demos</title>\t</head>\t<body>\t<h2> Demo List </h2>\t<ol>\t\t<li><a href=\"XSS.php\">XSS</a><br/></li>\t\t<li><a href=\"SQLI.php\">SQL Injection</a><br/></li>\t\t<li><a href=\"PredictableResource.php\">Predictable Resource Location</a><br/></li>\t\t<li><a href=\"PathTraversal.php?action=PathTraversal.php\">Path Traversal</a></li>\t\t<li><a href=\"DirectoryIndexing/\">Directory Indexing</a></li>\t\t<li><a href=\"XPathInjection.php\">XPath Injection</a></li>\t\t<li><a href=\"LDAPInjection.php\">LDAP Injection</a></li>\t\t<li><a href=\"FormatString.php\">Format String Injection</a></li>\t\t<li><a href=\"OSCommandInjection.php\">OS Command Injection</a></li>\t\t<li><a href=\"EvalInjection.php\">Eval Injection</a></li>\t</ol>\t</body></html>","nativeId":"9002034926150259712","displayId":null,"surfaceLocation":{"id":56336,"parameter":null,"path":"/demo/"},"sourceFileLocation":null,"dataFlowElements":null,"calculatedUrlPath":"/demo/","calculatedFilePath":"","dependency":null,"severity":"Information","vulnerabilityType":"HTML does not specify charset"},{"id":56337,"longDescription":null,"attackString":"","attackRequest":"GET /demo/PredictableResource.php HTTP/1.1Host: tftargetAccept: */*Accept-Language: enUser-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)Connection: closeReferer: http://tftarget/demo/","attackResponse":"HTTP/1.1 200 OKDate: Mon, 18 Nov 2013 19:43:48 GMTServer: Apache/2.2.19 (Win32) PHP/5.3.6X-Powered-By: PHP/5.3.6Content-Length: 375Connection: closeContent-Type: text/html<!-- Predictable Resource     This file tells you where the (hopefully) poorly hidden files are. -->\t <html>\t<head>\t\t<title>Predictable Resource Location</title>\t</head>\t<body>\t<h2> Predictable Resource Location </h2>\t<ul>\t\t<li>There is a backup of this file at http://192.168.1.30:8080/demo/PredictableResource.php.bak</li>\t</ul>\t</body></html>","nativeId":"5377296584001723392","displayId":null,"surfaceLocation":{"id":56337,"parameter":null,"path":"/demo/PredictableResource.php"},"sourceFileLocation":null,"dataFlowElements":null,"calculatedUrlPath":"/demo/PredictableResource.php","calculatedFilePath":"","dependency":null,"severity":"Information","vulnerabilityType":"Private IP addresses disclosed"},{"id":56338,"longDescription":null,"attackString":"%26echo%20a1cf3d1ff8<wbr>804333%20b37eb3f2418e5a53<wbr>%26","attackRequest":"POST /demo/OSCommandInjection2.php HTTP/1.1Host: tftargetAccept: */*Accept-Language: enUser-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)Connection: closeReferer: http://tftarget/demo/OSCommandInjection.phpContent-Type: application/x-www-form-urlencodedContent-Length: 21fileName=Peter+Wiener%26echo%20a1cf3d1ff8804333%20b37eb3f2418e5a53%26","attackResponse":"HTTP/1.1 200 OKDate: Mon, 18 Nov 2013 19:44:04 GMTServer: Apache/2.2.19 (Win32) PHP/5.3.6X-Powered-By: PHP/5.3.6Content-Length: 256Connection: closeContent-Type: text/html<!-- OS Command Injection 2  --><!-- This page realizes an OS Command Injection vulnerability. --><html>\t<head>\t\t<title>OS Command Injection</title>\t</head>\t<body>\t\t<pre>\t\t\ta1cf3d1ff8804333 b37eb3f2418e5a530\t\t</pre>\t</body></html>","nativeId":"5616851221970018304","displayId":null,"surfaceLocation":{"id":56338,"parameter":"fileName","path":"/demo/OSCommandInjection2.php"},"sourceFileLocation":null,"dataFlowElements":null,"calculatedUrlPath":"/demo/OSCommandInjection2.php","calculatedFilePath":"","dependency":null,"severity":"High","vulnerabilityType":"OS command injection"},{"id":56339,"longDescription":null,"attackString":null,"attackRequest":"GET /demo/LDAPInjection.php HTTP/1.1Host: tftargetAccept: */*Accept-Language: enUser-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)Connection: closeReferer: http://tftarget/demo/","attackResponse":"HTTP/1.1 200 OKDate: Mon, 18 Nov 2013 19:43:52 GMTServer: Apache/2.2.19 (Win32) PHP/5.3.6X-Powered-By: PHP/5.3.6Content-Length: 546Connection: closeContent-Type: text/html<!-- LDAP Injection  --><!-- This page demonstrates an LDAP Injection vulnerability. --><html>\t<head>\t\t<title>LDAP Injection</title>\t</head>\t<body>\t<h2> LDAP Injection </h2>\tThis is a login created to be vulnerable to LDAP Injection.<br/>\tSubmitting * for the username will log you in as the first user.<br/>\t\t<form action=\"LDAPInjection2.php\" method=\"post\">\t\tName: <input type=\"text\" name=\"username\" /><br/>\t\tPassword: <input type=\"text\" name=\"password\" /><br/>\t\t<input type=\"submit\" />\t</form>\t</body></html>","nativeId":"2979686476518700032","displayId":null,"surfaceLocation":{"id":56339,"parameter":null,"path":"/demo/LDAPInjection.php"},"sourceFileLocation":null,"dataFlowElements":null,"calculatedUrlPath":"/demo/LDAPInjection.php","calculatedFilePath":"","dependency":null,"severity":"Information","vulnerabilityType":"HTML does not specify charset"},{"id":56340,"longDescription":null,"attackString":null,"attackRequest":"GET /demo/XSS-reflected2.php HTTP/1.1Host: tftargetAccept: */*Accept-Language: enUser-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)Connection: close","attackResponse":"HTTP/1.1 200 OKDate: Mon, 18 Nov 2013 19:44:01 GMTServer: Apache/2.2.19 (Win32) PHP/5.3.6X-Powered-By: PHP/5.3.6Content-Length: 369Connection: closeContent-Type: text/html<!-- XSS2.php - Reflected     This file accepts the payload from XSS.php. -->\t <html>\t<head>\t\t<title>XSS Test - Reflected</title>\t</head>\t<body>\t<h2> Reflected XSS </h2>\t\tWelcome Notice: Undefined index: username in C:\\Program Files (x86)\\Apache Software Foundation\\Apache2.2\\htdocs\\demo\\XSS-reflected2.php on line 12!<br />\t</body></html>","nativeId":"5622104472001593344","displayId":null,"surfaceLocation":{"id":56340,"parameter":null,"path":"/demo/XSS-reflected2.php"},"sourceFileLocation":null,"dataFlowElements":null,"calculatedUrlPath":"/demo/XSS-reflected2.php","calculatedFilePath":"","dependency":null,"severity":"Information","vulnerabilityType":"HTML does not specify charset"},{"id":56341,"longDescription":null,"attackString":null,"attackRequest":"GET /demo/XSS-stored.php HTTP/1.1Host: tftargetAccept: */*Accept-Language: enUser-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)Connection: closeReferer: http://tftarget/demo/XSS.php","attackResponse":"HTTP/1.1 200 OKDate: Mon, 18 Nov 2013 19:43:55 GMTServer: Apache/2.2.19 (Win32) PHP/5.3.6X-Powered-By: PHP/5.3.6Content-Length: 284Connection: closeContent-Type: text/html<!-- XSS TEST - STORED --><!-- The goal is to pull the payload from the database. After that we'll see. --><html>\t<head>\t\t<title>XSS Test</title>\t</head>\t<body>\t<h2> Users List </h2>\t\t1 Jimmy<br />2 <script>alert('XSS')</script><br />3 John<br /> \t</body></html>","nativeId":"7585287139193964544","displayId":null,"surfaceLocation":{"id":56341,"parameter":null,"path":"/demo/XSS-stored.php"},"sourceFileLocation":null,"dataFlowElements":null,"calculatedUrlPath":"/demo/XSS-stored.php","calculatedFilePath":"","dependency":null,"severity":"Information","vulnerabilityType":"HTML does not specify charset"},{"id":56342,"longDescription":null,"attackString":null,"attackRequest":"GET /demo/EvalInjection.php HTTP/1.1Host: tftargetAccept: */*Accept-Language: enUser-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)Connection: closeReferer: http://tftarget/demo/","attackResponse":"HTTP/1.1 200 OKDate: Mon, 18 Nov 2013 19:43:52 GMTServer: Apache/2.2.19 (Win32) PHP/5.3.6X-Powered-By: PHP/5.3.6Content-Length: 526Connection: closeContent-Type: text/html<!-- Eval Injection  --><!-- This page demonstrates an Eval Injection vulnerability. --><html>\t<head>\t\t<title>Eval Injection</title>\t</head>\t<body>\t<h2> Eval Injection </h2>\tThis is a submission page created to be vulnerable to Eval Injection.<br/>\t<pre>One example payload is \tthisbroke\";sleep(5);\"which executes the sleep command.</pre>\t\t<form action=\"EvalInjection2.php\" method=\"post\">\t\tCommand: <input type=\"text\" name=\"command\" /><br/>\t\t<input type=\"submit\" />\t</form>\t</body></html>","nativeId":"3498317858268278784","displayId":null,"surfaceLocation":{"id":56342,"parameter":null,"path":"/demo/EvalInjection.php"},"sourceFileLocation":null,"dataFlowElements":null,"calculatedUrlPath":"/demo/EvalInjection.php","calculatedFilePath":"","dependency":null,"severity":"Information","vulnerabilityType":"HTML does not specify charset"},{"id":56343,"longDescription":null,"attackString":null,"attackRequest":"GET /demo/FormatString2.php HTTP/1.1Host: tftargetAccept: */*Accept-Language: enUser-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)Connection: close","attackResponse":"HTTP/1.1 200 OKDate: Mon, 18 Nov 2013 19:43:54 GMTServer: Apache/2.2.19 (Win32) PHP/5.3.6X-Powered-By: PHP/5.3.6Content-Length: 342Connection: closeContent-Type: text/html<!-- String Format Injection 2  --><!-- This page realizes an String Format Injection vulnerability. -->Notice: Undefined index: name in C:\\Program Files (x86)\\Apache Software Foundation\\Apache2.2\\htdocs\\demo\\FormatString2.php on line 6<html><head><title>500 Internal Server Error</title></head><body><h1>Internal Server Error</h1>","nativeId":"3349744853421256704","displayId":null,"surfaceLocation":{"id":56343,"parameter":null,"path":"/demo/FormatString2.php"},"sourceFileLocation":null,"dataFlowElements":null,"calculatedUrlPath":"/demo/FormatString2.php","calculatedFilePath":"","dependency":null,"severity":"Information","vulnerabilityType":"HTML does not specify charset"},{"id":56344,"longDescription":null,"attackString":null,"attackRequest":"GET /demo/OSCommandInjection.php HTTP/1.1Host: tftargetAccept: */*Accept-Language: enUser-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)Connection: closeReferer: http://tftarget/demo/","attackResponse":"HTTP/1.1 200 OKDate: Mon, 18 Nov 2013 19:43:52 GMTServer: Apache/2.2.19 (Win32) PHP/5.3.6X-Powered-By: PHP/5.3.6Content-Length: 641Connection: closeContent-Type: text/html<!-- OS Command Injection  --><!-- This page demonstrates an OS Command Injection vulnerability. --><html>\t<head>\t\t<title>OS Command Injection</title>\t</head>\t<body>\t<h2> OS Command Injection </h2>\tThis is a submission page created to be vulnerable to OS Command Injection.<br/>\tThe input is prefaced by the Windows type command. You can view file contents.<br/>\tI edited w3af to find a real vulnerability instead of an informational finding here.<br/>\t\t<form action=\"OSCommandInjection2.php\" method=\"post\">\t\tFile: <input type=\"text\" name=\"fileName\" /><br/>\t\t<input type=\"submit\" />\t</form>\t</body></html>","nativeId":"6800421540366612480","displayId":null,"surfaceLocation":{"id":56344,"parameter":null,"path":"/demo/OSCommandInjection.php"},"sourceFileLocation":null,"dataFlowElements":null,"calculatedUrlPath":"/demo/OSCommandInjection.php","calculatedFilePath":"","dependency":null,"severity":"Information","vulnerabilityType":"HTML does not specify charset"},{"id":56345,"longDescription":null,"attackString":"","attackRequest":"GET /demo/PathTraversal.php HTTP/1.1Host: tftargetAccept: */*Accept-Language: enUser-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)Connection: close","attackResponse":"HTTP/1.1 200 OKDate: Mon, 18 Nov 2013 19:43:48 GMTServer: Apache/2.2.19 (Win32) PHP/5.3.6X-Powered-By: PHP/5.3.6Content-Length: 147Connection: closeContent-Type: text/htmlParse error: syntax error, unexpected ';' in C:\\Program Files (x86)\\Apache Software Foundation\\Apache2.2\\htdocs\\demo\\PathTraversal.php on line 10","nativeId":"4636012210865943552","displayId":null,"surfaceLocation":{"id":56345,"parameter":null,"path":"/demo/PathTraversal.php"},"sourceFileLocation":null,"dataFlowElements":null,"calculatedUrlPath":"/demo/PathTraversal.php","calculatedFilePath":"","dependency":null,"severity":"Information","vulnerabilityType":"Content type incorrectly stated"},{"id":56346,"longDescription":null,"attackString":null,"attackRequest":"GET /demo/PredictableResource.php HTTP/1.1Host: tftargetAccept: */*Accept-Language: enUser-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)Connection: closeReferer: http://tftarget/demo/","attackResponse":"HTTP/1.1 200 OKDate: Mon, 18 Nov 2013 19:43:48 GMTServer: Apache/2.2.19 (Win32) PHP/5.3.6X-Powered-By: PHP/5.3.6Content-Length: 375Connection: closeContent-Type: text/html<!-- Predictable Resource     This file tells you where the (hopefully) poorly hidden files are. -->\t <html>\t<head>\t\t<title>Predictable Resource Location</title>\t</head>\t<body>\t<h2> Predictable Resource Location </h2>\t<ul>\t\t<li>There is a backup of this file at http://192.168.1.30:8080/demo/PredictableResource.php.bak</li>\t</ul>\t</body></html>","nativeId":"885313499681931264","displayId":null,"surfaceLocation":{"id":56346,"parameter":null,"path":"/demo/PredictableResource.php"},"sourceFileLocation":null,"dataFlowElements":null,"calculatedUrlPath":"/demo/PredictableResource.php","calculatedFilePath":"","dependency":null,"severity":"Information","vulnerabilityType":"HTML does not specify charset"},{"id":56347,"longDescription":null,"attackString":null,"attackRequest":"GET /demo/XSS-cookie.php HTTP/1.1Host: tftargetAccept: */*Accept-Language: enUser-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)Connection: closeReferer: http://tftarget/demo/XSS.php","attackResponse":"HTTP/1.1 200 OKDate: Mon, 18 Nov 2013 19:43:57 GMTServer: Apache/2.2.19 (Win32) PHP/5.3.6X-Powered-By: PHP/5.3.6Content-Length: 923Connection: closeContent-Type: text/html<!--Response SplittingInjecting a newline into a cookie allows you to return any http response you want.This page exhibits this vulnerability.value2;%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20302%20Moved%20Temporarily%0d%0aContent-Type:%20text/html%0d%0aContent-Length%2026%0d%0a%0d%0a<html><h2>DONE</h2></html>302%20Moved%20Temporarily-->Notice: Undefined index: username in C:\\Program Files (x86)\\Apache Software Foundation\\Apache2.2\\htdocs\\demo\\XSS-cookie.php on line 11<html>\t<head>\t\t<title>Response Splitting</title>\t</head>\t<body>\t\t<h2> Response Splitting </h2>\t\tThe cookie's value is Notice: Undefined index: vuln in C:\\Program Files (x86)\\Apache Software Foundation\\Apache2.2\\htdocs\\demo\\XSS-cookie.php on line 26\t\t<form action=\"ResponseSplitting.php\" method=\"post\">\t\t\tName: <input type=\"text\" name=\"username\" />\t\t\t<input type=\"submit\" />\t\t</form>\t</body></html>","nativeId":"2132573365222095872","displayId":null,"surfaceLocation":{"id":56347,"parameter":null,"path":"/demo/XSS-cookie.php"},"sourceFileLocation":null,"dataFlowElements":null,"calculatedUrlPath":"/demo/XSS-cookie.php","calculatedFilePath":"","dependency":null,"severity":"Information","vulnerabilityType":"HTML does not specify charset"},{"id":56348,"longDescription":null,"attackString":null,"attackRequest":"GET /demo/DirectoryIndexing/ HTTP/1.1Host: tftargetAccept: */*Accept-Language: enUser-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)Connection: closeReferer: http://tftarget/demo/","attackResponse":"HTTP/1.1 200 OKDate: Mon, 18 Nov 2013 19:43:48 GMTServer: Apache/2.2.19 (Win32) PHP/5.3.6Content-Length: 297Connection: closeContent-Type: text/html;charset=UTF-8<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 3.2 Final//EN\"><html> <head>  <title>Index of /demo/DirectoryIndexing</title> </head> <body><h1>Index of /demo/DirectoryIndexing</h1><ul><li><a href=\"/demo/\"> Parent Directory</a></li><li><a href=\"admin.txt\"> admin.txt</a></li></ul></body></html>","nativeId":"1546251653222968320","displayId":null,"surfaceLocation":{"id":56348,"parameter":null,"path":"/demo/DirectoryIndexing/"},"sourceFileLocation":null,"dataFlowElements":null,"calculatedUrlPath":"/demo/DirectoryIndexing/","calculatedFilePath":"","dependency":null,"severity":"Information","vulnerabilityType":"Directory listing"},{"id":56349,"longDescription":null,"attackString":null,"attackRequest":"GET /demo/XSS.php HTTP/1.1Host: tftargetAccept: */*Accept-Language: enUser-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)Connection: closeReferer: http://tftarget/demo/","attackResponse":"HTTP/1.1 200 OKDate: Mon, 18 Nov 2013 19:43:48 GMTServer: Apache/2.2.19 (Win32) PHP/5.3.6X-Powered-By: PHP/5.3.6Content-Length: 322Connection: closeContent-Type: text/html<!-- XSS  --><!-- This page just links to the two XSS pages. --><html>\t<head>\t\t<title>XSS</title>\t</head>\t<body>\t<h2> XSS Demo List </h2>\t\t<a href=\"XSS-reflected.php\">Reflected XSS</a><br/>\t\t<a href=\"XSS-stored.php\">Stored XSS</a><br/>\t\t<a href=\"XSS-cookie.php\">Cookie XSS</a><br/>\t</body></html>","nativeId":"4718065776296858624","displayId":null,"surfaceLocation":{"id":56349,"parameter":null,"path":"/demo/XSS.php"},"sourceFileLocation":null,"dataFlowElements":null,"calculatedUrlPath":"/demo/XSS.php","calculatedFilePath":"","dependency":null,"severity":"Information","vulnerabilityType":"HTML does not specify charset"},{"id":56350,"longDescription":null,"attackString":"\"","attackRequest":"POST /demo/SQLI2.php HTTP/1.1Host: tftargetAccept: */*Accept-Language: enUser-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)Connection: closeReferer: http://tftarget/demo/SQLI.phpContent-Type: application/x-www-form-urlencodedContent-Length: 21username=Peter+Wiener\"","attackResponse":"HTTP/1.1 200 OKDate: Mon, 18 Nov 2013 19:43:55 GMTServer: Apache/2.2.19 (Win32) PHP/5.3.6X-Powered-By: PHP/5.3.6Content-Length: 527Connection: closeContent-Type: text/html<!--SQL Injection test pageThis page's intended use is to show unauthorized password retrieval using SQL Injection.This is the submission form.Jimmy\"; SELECT id, password as name FROM users where name = \"Jimmy--><html>\t<head>\t\t<title>SQL Injection Test</title>\t</head>\t<body>\t<h2> Search Result </h2>\t\tError Message: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '\"Peter Wiener\"\"' at line 1 \t</body></html>","nativeId":"3993330662501398528","displayId":null,"surfaceLocation":{"id":56350,"parameter":"username","path":"/demo/SQLI2.php"},"sourceFileLocation":null,"dataFlowElements":null,"calculatedUrlPath":"/demo/SQLI2.php","calculatedFilePath":"","dependency":null,"severity":"High","vulnerabilityType":"SQL injection"},{"id":56351,"longDescription":null,"attackString":null,"attackRequest":"POST /demo/XPathInjection2.php HTTP/1.1Accept: */*Referer: http://tftarget/demo/XPathInjection.phpAccept-Language: en-usContent-Type: application/x-www-form-urlencodedUA-CPU: x86Accept-Encoding: gzip, deflateUser-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)Proxy-Connection: Keep-AliveContent-Length: 48Host: tftargetPragma: no-cacheusername=%27+or+1%3D1+or+%27%27%3D%27+&password=","attackResponse":"HTTP/1.1 200 OKDate: Mon, 18 Nov 2013 19:43:06 GMTServer: Apache/2.2.19 (Win32) PHP/5.3.6X-Powered-By: PHP/5.3.6Content-Length: 227Content-Type: text/html<!-- XPath Injection 2  --><!-- This page realizes an XPath Injection vulnerability. --><html>\t<head>\t\t<title>XPath Injection</title>\t</head>\t<body>\t\tYou have logged in as Jimmy with id 1.\t</body></html>","nativeId":"1469436927779449856","displayId":null,"surfaceLocation":{"id":56351,"parameter":null,"path":"/demo/XPathInjection2.php"},"sourceFileLocation":null,"dataFlowElements":null,"calculatedUrlPath":"/demo/XPathInjection2.php","calculatedFilePath":"","dependency":null,"severity":"Information","vulnerabilityType":"HTML does not specify charset"},{"id":56352,"longDescription":null,"attackString":null,"attackRequest":"GET /demo/SQLI.php HTTP/1.1Host: tftargetAccept: */*Accept-Language: enUser-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)Connection: closeReferer: http://tftarget/demo/","attackResponse":"HTTP/1.1 200 OKDate: Mon, 18 Nov 2013 19:43:48 GMTServer: Apache/2.2.19 (Win32) PHP/5.3.6X-Powered-By: PHP/5.3.6Content-Length: 608Connection: closeContent-Type: text/html<!--SQL Injection test pageThis page's intended use is to show unauthorized password retrieval using SQL Injection.This is the submission form.--><html>\t<head>\t\t<title>SQL Injection Test</title>\t</head>\t<body>\t<h2> User Search </h2>\tPossible payloads (in progress) :\t<ul>\t\t<li>Jimmy\"; SELECT id, password as name FROM users where name = \"Jimmy</li>\t\t<li>John\"; SELECT id, password as name FROM users where name = \"John</li>\t</ul>\t<form action=\"SQLI2.php\" method=\"post\">\t\tName: <input type=\"text\" name=\"username\" />\t\t<input type=\"submit\" />\t</form>\t</body></html>","nativeId":"4583408969376884736","displayId":null,"surfaceLocation":{"id":56352,"parameter":null,"path":"/demo/SQLI.php"},"sourceFileLocation":null,"dataFlowElements":null,"calculatedUrlPath":"/demo/SQLI.php","calculatedFilePath":"","dependency":null,"severity":"Information","vulnerabilityType":"HTML does not specify charset"},{"id":56353,"longDescription":null,"attackString":null,"attackRequest":"GET /demo/XSS-reflected.php HTTP/1.1Host: tftargetAccept: */*Accept-Language: enUser-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)Connection: closeReferer: http://tftarget/demo/XSS.php","attackResponse":"HTTP/1.1 200 OKDate: Mon, 18 Nov 2013 19:43:55 GMTServer: Apache/2.2.19 (Win32) PHP/5.3.6X-Powered-By: PHP/5.3.6Content-Length: 489Connection: closeContent-Type: text/html<!-- XSS TEST --><!-- The goal is to be able to pop up an alert through script tags injected into the username field. --><html> <head>  <title>XSS Test - Reflected</title> </head> <body> <h2> Reflected XSS </h2> A simple &#60;script&#62;alert('XSS')&#60;/script&#62; will work, along with any other JavaScript. <form action=\"XSS-reflected2.php\" method=\"post\">  Name: <input type=\"text\" name=\"username\" />  <input type=\"submit\" /> </form>  </body></html>","nativeId":"8043348113233281024","displayId":null,"surfaceLocation":{"id":56353,"parameter":null,"path":"/demo/XSS-reflected.php"},"sourceFileLocation":null,"dataFlowElements":null,"calculatedUrlPath":"/demo/XSS-reflected.php","calculatedFilePath":"","dependency":null,"severity":"Information","vulnerabilityType":"HTML does not specify charset"},{"id":56354,"longDescription":null,"attackString":"","attackRequest":"GET /demo/DirectoryIndexing/admin.txt HTTP/1.1Host: tftargetAccept: */*Accept-Language: enUser-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)Connection: closeReferer: http://tftarget/demo/DirectoryIndexing/","attackResponse":"HTTP/1.1 200 OKDate: Mon, 18 Nov 2013 19:43:52 GMTServer: Apache/2.2.19 (Win32) PHP/5.3.6Last-Modified: Wed, 01 Jun 2011 19:59:54 GMTETag: \"1000000023445-e2-4a4abf6cf8280\"Accept-Ranges: bytesContent-Length: 226Connection: closeContent-Type: text/plainadmin.txtMySQL configusername: rootpassword: rootvar;%20%0D%0AContent-Length:%200%0D%0A%0D%0AHTTP/1.1%20200%20OK%0D%0AContent-Type:%20text/html%0D%0AContent-Length:%2031%0D%0A<html>Hacked%20by%20yehg.org</html>","nativeId":"6245572582880674816","displayId":null,"surfaceLocation":{"id":56354,"parameter":null,"path":"/demo/DirectoryIndexing/admin.txt"},"sourceFileLocation":null,"dataFlowElements":null,"calculatedUrlPath":"/demo/DirectoryIndexing/admin.txt","calculatedFilePath":"","dependency":null,"severity":"Information","vulnerabilityType":"Content type incorrectly stated"},{"id":56355,"longDescription":null,"attackString":"7b65f&lt;script&gt;alert(1)&lt;<wbr>/script&gt;bd443a2a95d","attackRequest":"POST /demo/EvalInjection2.php HTTP/1.1Host: tftargetAccept: */*Accept-Language: enUser-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)Connection: closeReferer: http://tftarget/demo/EvalInjection.phpContent-Type: application/x-www-form-urlencodedContent-Length: 32command=555-555-0199@example.com7b65f<script>alert(1)</script>bd443a2a95d","attackResponse":"HTTP/1.1 200 OKDate: Mon, 18 Nov 2013 19:44:02 GMTServer: Apache/2.2.19 (Win32) PHP/5.3.6X-Powered-By: PHP/5.3.6Content-Length: 260Connection: closeContent-Type: text/html<!-- Eval Injection 2  --><!-- This page realizes an Eval Injection vulnerability. --><html>\t<head>\t\t<title>Eval Injection</title>\t</head>\t<body>\t\t<pre>555-555-0199@example.com7b65f<script>alert(1)</script>bd443a2a95d</pre>\t</body></html>","nativeId":"3295474588815328256","displayId":null,"surfaceLocation":{"id":56355,"parameter":"command","path":"/demo/EvalInjection2.php"},"sourceFileLocation":null,"dataFlowElements":null,"calculatedUrlPath":"/demo/EvalInjection2.php","calculatedFilePath":"","dependency":null,"severity":"High","vulnerabilityType":"Cross-site scripting (reflected)"},{"id":56356,"longDescription":null,"attackString":null,"attackRequest":"GET /demo/LDAPInjection2.php HTTP/1.1Host: tftargetAccept: */*Accept-Language: enUser-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)Connection: close","attackResponse":"HTTP/1.1 200 OKDate: Mon, 18 Nov 2013 19:43:57 GMTServer: Apache/2.2.19 (Win32) PHP/5.3.6X-Powered-By: PHP/5.3.6Content-Length: 344Connection: closeContent-Type: text/html<!-- LDAP Injection 2  --><!-- This page realizes an LDAP Injection vulnerability. --><html>\t<head>\t\t<title>LDAP Injection2</title>\t</head>\t<body>\t\tNotice: Undefined index: username in C:\\Program Files (x86)\\Apache Software Foundation\\Apache2.2\\htdocs\\demo\\LDAPInjection2.php on line 25Login failed.<br>\t</body></html>","nativeId":"3314671521517694976","displayId":null,"surfaceLocation":{"id":56356,"parameter":null,"path":"/demo/LDAPInjection2.php"},"sourceFileLocation":null,"dataFlowElements":null,"calculatedUrlPath":"/demo/LDAPInjection2.php","calculatedFilePath":"","dependency":null,"severity":"Information","vulnerabilityType":"HTML does not specify charset"},{"id":56357,"longDescription":null,"attackString":null,"attackRequest":"GET /demo/FormatString.php HTTP/1.1Host: tftargetAccept: */*Accept-Language: enUser-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)Connection: closeReferer: http://tftarget/demo/","attackResponse":"HTTP/1.1 200 OKDate: Mon, 18 Nov 2013 19:43:52 GMTServer: Apache/2.2.19 (Win32) PHP/5.3.6X-Powered-By: PHP/5.3.6Content-Length: 528Connection: closeContent-Type: text/html<!-- Format String Injection  --><!-- This page demonstrates an Format String Injection vulnerability. --><html>\t<head>\t\t<title>Format String Injection</title>\t</head>\t<body>\t<h2> Format String Injection </h2>\tThis is a login created to be vulnerable to Format String Injection.<br/>\tIt throws an error when % characters are used. <br/>\t\t<form action=\"FormatString2.php\" method=\"post\">\t\tName: <input type=\"text\" name=\"name\" /><br/>\t\t<input type=\"submit\" value=\"Say Hi!\"/>\t</form>\t</body></html>","nativeId":"7525811108987363328","displayId":null,"surfaceLocation":{"id":56357,"parameter":null,"path":"/demo/FormatString.php"},"sourceFileLocation":null,"dataFlowElements":null,"calculatedUrlPath":"/demo/FormatString.php","calculatedFilePath":"","dependency":null,"severity":"Information","vulnerabilityType":"HTML does not specify charset"},{"id":56358,"longDescription":null,"attackString":null,"attackRequest":"GET /demo/EvalInjection2.php HTTP/1.1Host: tftargetAccept: */*Accept-Language: enUser-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)Connection: close","attackResponse":"HTTP/1.1 200 OKDate: Mon, 18 Nov 2013 19:43:57 GMTServer: Apache/2.2.19 (Win32) PHP/5.3.6X-Powered-By: PHP/5.3.6Content-Length: 473Connection: closeContent-Type: text/html<!-- Eval Injection 2  --><!-- This page realizes an Eval Injection vulnerability. --><html>\t<head>\t\t<title>Eval Injection</title>\t</head>\t<body>\t\t<pre>Notice: Undefined index: command in C:\\Program Files (x86)\\Apache Software Foundation\\Apache2.2\\htdocs\\demo\\EvalInjection2.php on line 10Notice: Undefined index: command in C:\\Program Files (x86)\\Apache Software Foundation\\Apache2.2\\htdocs\\demo\\EvalInjection2.php on line 14</pre>\t</body></html>","nativeId":"2436621143556105216","displayId":null,"surfaceLocation":{"id":56358,"parameter":null,"path":"/demo/EvalInjection2.php"},"sourceFileLocation":null,"dataFlowElements":null,"calculatedUrlPath":"/demo/EvalInjection2.php","calculatedFilePath":"","dependency":null,"severity":"Information","vulnerabilityType":"HTML does not specify charset"},{"id":56359,"longDescription":null,"attackString":null,"attackRequest":"GET /demo/XPathInjection.php HTTP/1.1Host: tftargetAccept: */*Accept-Language: enUser-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)Connection: closeReferer: http://tftarget/demo/","attackResponse":"HTTP/1.1 200 OKDate: Mon, 18 Nov 2013 19:43:52 GMTServer: Apache/2.2.19 (Win32) PHP/5.3.6X-Powered-By: PHP/5.3.6Content-Length: 588Connection: closeContent-Type: text/html<!-- XPath Injection  --><!-- This page demonstrates an XPath Injection vulnerability. --><html>\t<head>\t\t<title>XPath Injection</title>\t</head>\t<body>\t<h2> XPath Injection </h2>\tThis is a login created to be vulnerable to XPath Injection.<br/>\tThis payload in the user field enables you to login with no security credentials.<br/>\t' or 1=1 or ''='\t\t<form action=\"XPathInjection2.php\" method=\"post\">\t\tName: <input type=\"text\" name=\"username\" /><br/>\t\tPassword: <input type=\"text\" name=\"password\" /><br/>\t\t<input type=\"submit\" />\t</form>\t</body></html>","nativeId":"8932068351221153792","displayId":null,"surfaceLocation":{"id":56359,"parameter":null,"path":"/demo/XPathInjection.php"},"sourceFileLocation":null,"dataFlowElements":null,"calculatedUrlPath":"/demo/XPathInjection.php","calculatedFilePath":"","dependency":null,"severity":"Information","vulnerabilityType":"HTML does not specify charset"},{"id":56360,"longDescription":null,"attackString":null,"attackRequest":"GET /demo/PathTraversal.php HTTP/1.1Host: tftargetAccept: */*Accept-Language: enUser-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)Connection: close","attackResponse":"HTTP/1.1 200 OKDate: Mon, 18 Nov 2013 19:43:48 GMTServer: Apache/2.2.19 (Win32) PHP/5.3.6X-Powered-By: PHP/5.3.6Content-Length: 147Connection: closeContent-Type: text/htmlParse error: syntax error, unexpected ';' in C:\\Program Files (x86)\\Apache Software Foundation\\Apache2.2\\htdocs\\demo\\PathTraversal.php on line 10","nativeId":"3666771622552669184","displayId":null,"surfaceLocation":{"id":56360,"parameter":null,"path":"/demo/PathTraversal.php"},"sourceFileLocation":null,"dataFlowElements":null,"calculatedUrlPath":"/demo/PathTraversal.php","calculatedFilePath":"","dependency":null,"severity":"Information","vulnerabilityType":"HTML does not specify charset"},{"id":56361,"longDescription":null,"attackString":"1951f&lt;script&gt;alert(1)&lt;<wbr>/script&gt;578bb19c374","attackRequest":"POST /demo/XSS-reflected2.php HTTP/1.1Host: tftargetAccept: */*Accept-Language: enUser-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)Connection: closeReferer: http://tftarget/demo/XSS-reflected.phpContent-Type: application/x-www-form-urlencodedContent-Length: 21username=Peter+Wiener1951f<script>alert(1)</script>578bb19c374","attackResponse":"HTTP/1.1 200 OKDate: Mon, 18 Nov 2013 19:44:02 GMTServer: Apache/2.2.19 (Win32) PHP/5.3.6X-Powered-By: PHP/5.3.6Content-Length: 282Connection: closeContent-Type: text/html<!-- XSS2.php - Reflected     This file accepts the payload from XSS.php. -->\t <html>\t<head>\t\t<title>XSS Test - Reflected</title>\t</head>\t<body>\t<h2> Reflected XSS </h2>\t\tWelcome Peter Wiener1951f<script>alert(1)</script>578bb19c374!<br />\t</body></html>","nativeId":"3382053426657538048","displayId":null,"surfaceLocation":{"id":56361,"parameter":"username","path":"/demo/XSS-reflected2.php"},"sourceFileLocation":null,"dataFlowElements":null,"calculatedUrlPath":"/demo/XSS-reflected2.php","calculatedFilePath":"","dependency":null,"severity":"High","vulnerabilityType":"Cross-site scripting (reflected)"},{"id":56362,"longDescription":null,"attackString":null,"attackRequest":"GET /demo/OSCommandInjection2.php HTTP/1.1Host: tftargetAccept: */*Accept-Language: enUser-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)Connection: close","attackResponse":"HTTP/1.1 200 OKDate: Mon, 18 Nov 2013 19:44:01 GMTServer: Apache/2.2.19 (Win32) PHP/5.3.6X-Powered-By: PHP/5.3.6Content-Length: 366Connection: closeContent-Type: text/html<!-- OS Command Injection 2  --><!-- This page realizes an OS Command Injection vulnerability. --><html>\t<head>\t\t<title>OS Command Injection</title>\t</head>\t<body>\t\t<pre>\t\t\tNotice: Undefined index: fileName in C:\\Program Files (x86)\\Apache Software Foundation\\Apache2.2\\htdocs\\demo\\OSCommandInjection2.php on line 121\t\t</pre>\t</body></html>","nativeId":"5052297586238244864","displayId":null,"surfaceLocation":{"id":56362,"parameter":null,"path":"/demo/OSCommandInjection2.php"},"sourceFileLocation":null,"dataFlowElements":null,"calculatedUrlPath":"/demo/OSCommandInjection2.php","calculatedFilePath":"","dependency":null,"severity":"Information","vulnerabilityType":"HTML does not specify charset"},{"id":56363,"longDescription":null,"attackString":null,"attackRequest":"TRACE / HTTP/1.0Host: tftargetCookie: 274ef754a182e499","attackResponse":"HTTP/1.1 200 OKDate: Mon, 18 Nov 2013 19:43:06 GMTServer: Apache/2.2.19 (Win32) PHP/5.3.6Connection: closeContent-Type: message/httpTRACE / HTTP/1.0Host: tftargetCookie: 274ef754a182e499","nativeId":"4563171744274440192","displayId":null,"surfaceLocation":{"id":56363,"parameter":null,"path":"/"},"sourceFileLocation":null,"dataFlowElements":null,"calculatedUrlPath":"/","calculatedFilePath":"","dependency":null,"severity":"Information","vulnerabilityType":"TRACE method is enabled"},{"id":56364,"longDescription":null,"attackString":null,"attackRequest":"GET /demo/SQLI2.php HTTP/1.1Host: tftargetAccept: */*Accept-Language: enUser-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)Connection: close","attackResponse":"HTTP/1.1 200 OKDate: Mon, 18 Nov 2013 19:43:53 GMTServer: Apache/2.2.19 (Win32) PHP/5.3.6X-Powered-By: PHP/5.3.6Content-Length: 481Connection: closeContent-Type: text/html<!--SQL Injection test pageThis page's intended use is to show unauthorized password retrieval using SQL Injection.This is the submission form.Jimmy\"; SELECT id, password as name FROM users where name = \"Jimmy--><html>\t<head>\t\t<title>SQL Injection Test</title>\t</head>\t<body>\t<h2> Search Result </h2>\t\tNotice: Undefined index: username in C:\\Program Files (x86)\\Apache Software Foundation\\Apache2.2\\htdocs\\demo\\SQLI2.php on line 16 \t</body></html>","nativeId":"6606573814891010048","displayId":null,"surfaceLocation":{"id":56364,"parameter":null,"path":"/demo/SQLI2.php"},"sourceFileLocation":null,"dataFlowElements":null,"calculatedUrlPath":"/demo/SQLI2.php","calculatedFilePath":"","dependency":null,"severity":"Information","vulnerabilityType":"HTML does not specify charset"}],"scannerName":"Burp Suite"}}`

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
	//aBody := lookupAppId(tfClient, 3)
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
	//aBody, _ := scanUpload(tfClient, 6, "./examples/burp-demo-site.xml")
	//aBody = uploadResponse
	//fmt.Println(aBody)
	//var upld UpldResp
	//makeUploadStruct(&upld, aBody)
	//fmt.Printf("\n\n The path is %+v \n\n", upld.Upload[0].Findings[0].Loc.Path)
	//var app AppResp
	//makeAppStruct(&app, aBody)
	//waf := createWaf(tfClient, "example waf", "")
	// {"id":1,"name":"example waf","wafTypeName":"mod_security","applications":null}
	//waf := lookupWafId(tfClient, 1)
	//waf := lookupWafName(tfClient, "example waf")
	//waf := getWafs(tfClient)
	//fmt.Println(waf)
	// NEEDS MORE WORK
	vulns := vulnSearch(tfClient)
	fmt.Println(vulns)
	// json.MarshalIndent(team, "", " ")
	// fmt.Printf("JSON was\n\n%s", json.MarshalIndent(team, "", " "))

	fmt.Println("\n")

}

// Helper Functions

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

func createSearchStruct() Search {
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

	mp := MultiPara{
		map[string]string{"name": "teams%5B0%5D.id", "value": ""},                   // Teams
		map[string]string{"name": "applications%5B0%5D.id", "value": ""},            // Apps
		map[string]string{"name": "genericVulnerabilities%5B0%5D.id", "value": ""},  // Cwe
		map[string]string{"name": "channelTypes%5B0%5D.name", "value": ""},          // Scammer
		map[string]string{"name": "genericSeverities%5B0%5D.intValue", "value": ""}, // Severity
	}

	// Create the Search Struct
	s := Search{
		r,  // ReqPara
		sp, // SinglePara
		mp, // MultiPara
	}

	return s

}

// Search helper calls

func showInSearch(s *Search, show string) {
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

	// ToDo: Add a default case and return an error if show
	// doesn't match any of the cases

}

func numSearchResults(s *Search, n int) {
	// Set the Number of vulnerabilities to return
	s.SingleParas.NumVulns["value"] = strconv.Itoa(n)
}

func paramSearch(s *Search, p string) {
	// Set the parameter to search for
	s.SingleParas.Param["value"] = p
}

func pathSearch(s *Search, p string) {
	// Set the path to search for
	s.SingleParas.Path["value"] = p
}

func startSearch(s *Search, str string) {
	// Parse the string into a Go time struct
	// expecting date as mm/dd/yyyy
	t, _ := time.Parse("01/02/2006", str)
	// ToDo: catch this error and try other formats

	// Convert string to miliseconds since the Unix Epoch as expected by Java
	// and the ThreadFix API
	s.SingleParas.Start["value"] = strconv.FormatInt((t.UnixNano() / 1000000), 10)
}

func endSearch(s *Search, str string) {
	// Parse the string into a Go time struct
	// expecting date as mm/dd/yyyy
	t, _ := time.Parse("01/02/2006", str)
	// ToDo: catch this error and try other formats

	// Convert string to miliseconds since the Unix Epoch as expected by Java
	// and the ThreadFix API
	s.SingleParas.End["value"] = strconv.FormatInt((t.UnixNano() / 1000000), 10)
}

func numMergedSearch(s *Search, n int) {
	// Set the Number of vulnerabilities to return
	s.SingleParas.NumMerged["value"] = strconv.Itoa(n)
}

func teamIdSearch(s *Search, t ...int) {
	// Create a comma seperated list for the teams value
	var val string
	for i, _ := range t {
		val = val + "," + strconv.Itoa(t[i])
	}

	// Set Teams search by slicing off the initial comma
	s.MultiParas.Teams["value"] = val[1:]
}

func appIdSearch(s *Search, a ...int) {
	// Create a comman seperated list for the apps value
	var val string
	for i, _ := range a {
		val = val + "," + strconv.Itoa(a[i])
	}

	// Set Apps search by slicing off the initial comma
	s.MultiParas.Apps["value"] = val[1:]
}

func cweIdSearch(s *Search, c ...int) {
	// Create a comman seperated list for the cwe value
	var val string
	for i, _ := range c {
		val = val + "," + strconv.Itoa(c[i])
	}

	// Set CWE search by slicing off the initial comma
	s.MultiParas.Cwe["value"] = val[1:]
}

func scannerSearch(s *Search, sc ...string) {
	// Create a comman seperated list of scanners
	var val string
	for i, _ := range sc {
		val = val + "," + sc[i]
	}

	// Set CWE search by slicing off the initial comma
	s.MultiParas.Scanner["value"] = val[1:]
}

func severitySearch(s *Search, sev ...int) {
	// Create a comman seperated list for the cwe value
	var val string
	for i, _ := range sev {
		val = val + "," + strconv.Itoa(sev[i])
	}

	// Set CWE search by slicing off the initial comma
	s.MultiParas.Severity["value"] = val[1:]
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
	var postStr = []byte("showOpen=false&showClosed=false&showFalsePositive=false" +
		"&showHidden=false&numberVulnerabilities=3")
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
			// Note: There is likely differenced based on timezone of the
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
}

func makeUploadStruct(u *UpldResp, b string) {
	// Parse the sent JSON body from the API
	var raw map[string]interface{}
	if err := json.Unmarshal([]byte(b), &raw); err != nil {
		// Add some proper error handling here - maybe return an error
		panic(err)
	}

	// Setup the values in the initial struct
	u.Success = raw["success"].(bool)
	u.RespCode = int(raw["responseCode"].(float64))
	u.Msg = raw["message"].(string)

	// Setup a struct for Upld based on the type
	// resulting from unmarshall'ing the JSON
	tType := reflect.TypeOf(raw["object"])
	var obj []interface{}
	if strings.Contains(tType.String(), "map") {
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
			dF := make(map[int]string)
			if reflect.TypeOf(f["dataFlowElements"]) != nil {
				// dataFlowElements was actually set - not seen an example of this
				dF[1] = f["dataFlowElements"].(string)
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
				dF,
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
}
