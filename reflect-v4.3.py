from burp import IBurpExtender
from burp import IScannerCheck
from burp import IScanIssue
from array import array
# Added for this project
from burp import IHttpListener
from burp import IHttpRequestResponse
from burp import IBurpExtenderCallbacks
from burp import IRequestInfo
from burp import IResponseInfo
from burp import IParameter
from burp import IInterceptedProxyMessage
import urllib

INJ_TEST = bytearray("test1234")
INJ_ERROR = "test1234"
INJ_ERROR_BYTES = bytearray(INJ_ERROR)

print("reflection vuln extension loaded")

class BurpExtender(IBurpExtender, IScannerCheck,  IHttpListener, IHttpRequestResponse, IBurpExtenderCallbacks, IRequestInfo, IResponseInfo, IParameter, IInterceptedProxyMessage):

    #
    # implement IBurpExtender
    #

    def registerExtenderCallbacks(self, callbacks):
        # keep a reference to our callbacks object
        self._callbacks = callbacks

        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()


        # set our extension name
        callbacks.setExtensionName("Refleter 4.3 - Passive Vuln scan")

        # register ourselves as a custom scanner check
        callbacks.registerScannerCheck(self)

    # helper method to search a response for occurrences of a literal match string
    # and return a list of start/end offsets

    def _get_matches(self, response, match):
        matches = []
        start = 0
        reslen = len(response)
        matchlen = len(match)
        while start < reslen:
            start = self._helpers.indexOf(response, match, True, start, reslen)
            if start == -1:
                break
            matches.append(array('i', [start, start + matchlen]))
            start += matchlen

        return matches

    #
    # implement IScannerCheck
    #

    def doPassiveScan(self, baseRequestResponse):
        print("reached passive scan")
        requestInfo = self._helpers.analyzeRequest(baseRequestResponse.getRequest())
        parameters = requestInfo.getParameters()



        for parameter in parameters:
            print("Inside the loop")
            value = parameter.getValue()
            name = parameter.getName()
            print(name)
            # look for matches of our passive check grep string
            matches = self._get_matches(baseRequestResponse.getResponse(), value)
            matchesCanary = self._get_matches(baseRequestResponse.getResponse(), bytearray("test1234"))

            if (len(matches) != 0) and (len(value) > 2):
                return [CustomScanIssue(
                    baseRequestResponse.getHttpService(),
                    self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                    [self._callbacks.applyMarkers(baseRequestResponse, None, matches)],
                    "Possible Reflection: "+name,
                    "The response contains the string: " + value + " that might come from the variable " + name,
                    "Information")]

            elif bytearray("https") in value or bytearray("http") in value:
                return [CustomScanIssue(
                    baseRequestResponse.getHttpService(),
                    self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                    [self._callbacks.applyMarkers(baseRequestResponse, None, matches)],
                    "URL in parameter "+name,
                    "The parameter " + name + " contains the value " + value + ",it seems to be a URL. This could be leveraged for a insecure redirect, RFI or SSRF attack.",
                    "Information")]

            elif bytearray("/") in value or bytearray("%2F") in value or bytearray("%2f") in value:
                return [CustomScanIssue(
                    baseRequestResponse.getHttpService(),
                    self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                    [self._callbacks.applyMarkers(baseRequestResponse, None, matches)],
                    "PATH in parameter "+name, 
                    "The parameter " + name + " contains the value " + value + ",it seems to be a PATH. This could be leveraged for a LFI or path traversal attack.",
                    "Information")]

            elif bytearray("<") in value or bytearray("%3c") in value: 
                return [CustomScanIssue(
                    baseRequestResponse.getHttpService(),
                    self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                    [self._callbacks.applyMarkers(baseRequestResponse, None, matches)],
                    "HTML in parameter "+name,
                    "The parameter " + name + " contains the value " + value + ",it seems to contain HTML. This could be leveraged for XSS, XXE or HTML injection attack.",
                    "Information")]

            elif (len(matchesCanary) != 0):
                return [CustomScanIssue(
                    baseRequestResponse.getHttpService(),
                    self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                    [self._callbacks.applyMarkers(baseRequestResponse, None, matchesCanary)],
                    "Canary found: test1234",
                    "The string test1234 is found in the response and is used as a Canary. It could lead to a stored XSS vulnerability.",
                    "Information")]

            else: 
                return None

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        # make a request containing our injection test in the insertion point
        checkRequest = insertionPoint.buildRequest(INJ_TEST)
        checkRequestResponse = self._callbacks.makeHttpRequest(
                baseRequestResponse.getHttpService(), checkRequest)

        # look for matches of our active check grep string
        matches = self._get_matches(checkRequestResponse.getResponse(), INJ_ERROR_BYTES)
        if len(matches) == 0:
            return None

        # get the offsets of the payload within the request, for in-UI highlighting
        requestHighlights = [insertionPoint.getPayloadOffsets(INJ_TEST)]

        # report the issue
        return [CustomScanIssue(
            baseRequestResponse.getHttpService(),
            self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
            [self._callbacks.applyMarkers(checkRequestResponse, requestHighlights, matches)],
            "Canary reflected",
            "The string test1234 was injected and reflected.",
            "Information")]

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        # This method is called when multiple issues are reported for the same URL 
        # path by the same extension-provided check. The value we return from this 
        # method determines how/whether Burp consolidates the multiple issues
        # to prevent duplication
        #
        # Since the issue name is sufficient to identify our issues as different,
        # if both issues have the same name, only report the existing issue
        # otherwise report both issues
        if existingIssue.getIssueName() == newIssue.getIssueName():
            return -1

        return 0

#
# class implementing IScanIssue to hold our custom scan issue details
#
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
