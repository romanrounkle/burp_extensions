from burp import IBurpExtender
from burp import IHttpListener
from burp import IHttpRequestResponse
from burp import IBurpExtenderCallbacks
from burp import IRequestInfo
from burp import IParameter
import urllib
import re


class BurpExtender(IBurpExtender, IHttpListener, IHttpRequestResponse, IBurpExtenderCallbacks, IRequestInfo, IParameter):

    #
    # implement IBurpExtender
    #
    
    def	registerExtenderCallbacks(self, callbacks):
        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()


        # set our extension name
        callbacks.setExtensionName("Param test v0.5")
        
        # register ourselves as an HTTP listener
        callbacks.registerHttpListener(self)

    
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):


        requestInfo = self._helpers.analyzeRequest(messageInfo.getRequest())


	toolNum = IBurpExtenderCallbacks.TOOL_PROXY        
	if toolNum == 4:
            parameters = requestInfo.getParameters()
            headers = requestInfo.getHeaders()

            for header in headers:
                if header.startswith("GET") or header.startswith("POST") or header.startswith("HEAD") or header.startswith("PUT") or header.startswith("DELETE"):
                    headerPartsUrl = header.split(" ")
                    path = headerPartsUrl[1]
                    pathParts = path.split("?")
                    pathSan = pathParts[0]
                    pathSanParts = pathSan.split("/")
                    for f in pathSanParts:
                        if bool(re.match("^[a-zA-Z0-9\_\-\.\~]{1,40}$",f)):
                            with open("/Users/Bob/HACKING_WORDLISTS/files-custom.txt","r+") as file:
                                for line in file:
                                        if f in line:
                                            break
                                else:
                                    file.write(f+"\n")
                            file.close()


                elif ":" in header:
                    headerParts = header.split(":")
                    header = headerParts[0]
                    if "/" not in header: 
                        with open("/Users/Bob/HACKING_WORDLISTS/headers-custom.txt","r+") as file:
                            for line in file:
                                if header in line:
                                   break
                            else:
                                file.write(header+"\n")
                        file.close()


            for parameter in parameters:
                with open("/Users/Bob/HACKING_WORDLISTS/parameter-names-custom.txt","r+") as file:
                    if re.match("^[a-zA-Z0-9\_\-\.]{1,40}$",parameter.getName()):
                        for line in file:
                            if parameter.getName() in line:
                                break
                        else:
                            file.write(parameter.getName()+"\n")
                file.close()
