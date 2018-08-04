from burp import IBurpExtender
from burp import IHttpListener
from burp import IScanIssue
from burp import IScannerInsertionPoint
from burp import IScannerCheck
from burp import IScannerListener
from burp import IResponseInfo
from burp import IParameter
from burp import IExtensionHelpers
global newMsg

body = ''

print "[+] Simplify has been loaded" 

class BurpExtender(IBurpExtender, IScannerCheck): #IHttpListener,

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.callbacks.setExtensionName("Simplify_v0.1")
        self.helpers = callbacks.getHelpers()
        self.callbacks.registerScannerCheck(self)


    def doPassiveScan(self, baseRequestResponse):
	fullShortHeader = ''
        reqInfo = self.helpers.analyzeRequest(baseRequestResponse)
        host = reqInfo.getUrl().getHost()

        headers = reqInfo.getHeaders()
        newHeaders = list(headers)
	request = self.helpers.bytesToString(baseRequestResponse.getRequest())
	response = baseRequestResponse.getResponse()

	body = self.helpers.bytesToString(request[reqInfo.getBodyOffset():])

	# Response stability check 
	baseReqLen = self.helpers.buildHttpMessage(newHeaders, request[reqInfo.getBodyOffset():])
	baseReqLen = self.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(),baseReqLen)
	baseReqLen = baseReqLen.getResponse()
	unstableReq = 0
	for i in range(3):
	    print "[+] Stability check :",i
	    baseReqLen2 = self.helpers.buildHttpMessage(newHeaders, request[reqInfo.getBodyOffset():])
	    baseReqLen2 = self.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(),baseReqLen2)
	    baseReqLen2 = baseReqLen2.getResponse()
	    if len(baseReqLen) != len(baseReqLen2):
		unstableReq += 1
		print "[-] Sorry the response is not stable"
		print "original response length: ",len(baseReqLen)
		print "next check response length: ",len(baseReqLen2)
                return [CustomScanIssue(
                    baseRequestResponse.getHttpService(),
                    self.helpers.analyzeRequest(baseRequestResponse).getUrl(),
                    [],
                    "Unstable response",
                    "Identical request get a response that varies in length. This can cause false positives in attacks such as SQL Injection.",
                    "Information")]


	if unstableReq > 0:
	    print "[-] Sorry the response is not stable"
	else:
	    print "[+] The response is stable, the testing will continue"
            print "[+] Simplified request: "
	    print "#"*100
            for header in newHeaders:
                if header.startswith('GET /') or header.startswith('POST /'):
                    idx = newHeaders.index(header)
		    fullShortHeader+= header+"\n"
                elif header.startswith('Host') or header.startswith('host') or header.startswith('HOST'):
                    idx = newHeaders.index(header)                           
                    fullShortHeader+= header+"\n"                            
                elif header.startswith('Cookie') or header.startswith('COOKIE') or header.startswith('cookie'):
		    idx = newHeaders.index(header)
                    newHeaders.remove(header)
                    newMsg = self.helpers.buildHttpMessage(newHeaders, request[reqInfo.getBodyOffset():])
                    sendSploit = self.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(),newMsg)
                    modresp = sendSploit.getResponse() 
                    if len(modresp) != len(response): 
			print "[+] Find session cookie"
                        # fullShortHeader+= header+"\n"         

		        cookieParts = header.split(": ")
		        cookieCap = cookieParts[0]
		        xCookies = header.strip(cookieCap+":")
		        xCookie = xCookies.split(";")
		        print "[+] START COOKIE TEST"
			neededcookies=""
		        for c in xCookie:
			    c = c.strip()
		            reducexCookies = xCookies.strip(c)
		            reducexCookies = reducexCookies.replace(";;",";")
			    cookieHeader = "Cookies: " + reducexCookies
			    newHeaders.insert(idx, cookieHeader)
			    newMsg = self.helpers.buildHttpMessage(newHeaders, request[reqInfo.getBodyOffset():])
			    sendSploit = self.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(),newMsg)
			    modresp = sendSploit.getResponse()
			    if len(modresp) != len(response):
				print "[+] Cookie is needed: ",c
				neededcookies += c+"; "
			    newHeaders.remove(cookieHeader)
			    print newHeaders

			if neededcookies != "":	
			    fullShortHeader+= "Cookie: "+neededcookies
			     
		    # print "\n\n"
                    # idx = newHeaders.index(header)                           
                    # fullShortHeader+= header+"\n"                            
	        else: 
	            newHeaders.remove(header)
                    newMsg = self.helpers.buildHttpMessage(newHeaders, request[reqInfo.getBodyOffset():])
                    sendSploit = self.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(),newMsg)
                    modresp = sendSploit.getResponse()
                    if len(modresp) != len(response): 
		        fullShortHeader+= header+"\n"

	    print fullShortHeader
	    print str(body)
	    print "#"*100
	    print "Length of orginal request: ",len(request)
	    print "Length of shortened request: ",len(fullShortHeader)


            if int(len(response)) > int(len(fullShortHeader)):
                fullShortHeader = fullShortHeader.replace("\n","<br/>")
                return [CustomScanIssue(
     	            baseRequestResponse.getHttpService(),
	            self.helpers.analyzeRequest(baseRequestResponse).getUrl(),
	            [],
	            "Simplify request",
	            "You can simplify the request to: <br/><br/>" + fullShortHeader + "<br/>" + str(body),
	            "Information")]

    def consolidateDuplicateIssues(existingIssue,newIssue):
        if existingIssue.getIssueName() == newIssue.getIssueName():
            return -1
        else:
            return 0

class CustomScanIssue (IScanIssue):                                             
    def __init__(self, httpService, url, httpMessages, name, detail, severity): 
        self._httpService = httpService                                         
        self._url = url                                                         
        self._httpMessages = httpMessages                                       
        self._name = name                                                       
        self._detail = detail                                                   
        self._severity = severity                                               
                                                                                
    def getUrl(self):                                                           
        return self._url                                                        
                                                                                
    def getIssueName(self):                                                     
        return self._name                                                       
                                                                                
    def getIssueType(self):                                                     
        return 0                                                                
                                                                                
    def getSeverity(self):                                                      
        return self._severity                                                   
                                                                                
    def getConfidence(self):                                                    
        return "Certain"                                                        
                                                                                
    def getIssueBackground(self):                                               
        pass                                                                    
                                                                                
    def getRemediationBackground(self):                                         
        pass                                                                    
                                                                                
    def getIssueDetail(self):                                                   
        return self._detail                                                     
                                                                                
    def getRemediationDetail(self):                                             
        pass                                                                    
                                                                                
    def getHttpMessages(self):                                                  
        return self._httpMessages                                               
                                                                                
    def getHttpService(self):                                                   
        return self._httpService                                                

