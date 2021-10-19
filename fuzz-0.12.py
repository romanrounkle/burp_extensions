from burp import IBurpExtender
from burp import IIntruderPayloadGeneratorFactory
from burp import IIntruderPayloadProcessor
from burp import IIntruderPayloadGenerator
import base64
from binascii import hexlify
import random
import re
import gzip
import StringIO
import zlib
import hashlib
from burp import IHttpRequestResponse
from burp import IHttpListener
from burp import IBurpExtenderCallbacks


############# Diff calc ##############
from difflib import SequenceMatcher
originalRes = ""

def similar(a, b):
    return SequenceMatcher(None, a, b).ratio()
######################################


############# OPTIONS ################
# fuzzing payloads
stuff = ["A","a","1","<",">","~","`","!","@","#","$","%","^","&","*","(",")","-","_","+","=","{","}","[","]","|","\\","\"","\'",";",":","'",".","?","/","test1234","bla<xss>bla"]

# Add all URL encoded ASCII chars. Remove prepended # to enable. 
#for n in range(256):
    #stuff.append("%{:02x}".format(n)) # URL encoded 
    #stuff.append("&#x{:02x};".format(n)) # HTML encoded 
    #stuff.append("%u00{:02x}".format(n)) # HTML encoded 

# Add buffer overflow payloads
for n2 in range(1,11):
    stuff.append("A"*500*n2)
######################################


####### GET MOST DIFFERENT ###########

mostDiff = [0,"Request","Response"]

######################################

# ignore this array
PAYLOADS = [bytearray("a")]



class BurpExtender(IBurpExtender, IIntruderPayloadGeneratorFactory, IIntruderPayloadProcessor, IHttpRequestResponse, IHttpListener, IBurpExtenderCallbacks):

    #
    # implement IBurpExtender
    #
    
    def registerExtenderCallbacks(self, callbacks):
        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()
        
        # set our extension name
        callbacks.setExtensionName("Cat On Keyboard 0.12")
        
        # register ourselves as an Intruder payload generator
        callbacks.registerIntruderPayloadGeneratorFactory(self)
        
        # register ourselves as an Intruder payload processor
        callbacks.registerIntruderPayloadProcessor(self)

        # register ourselves as an HTTP listener
        callbacks.registerHttpListener(self)

        # count the number of requests
        self._reqnum = 0
        self._originalRes = ""

    #
    # implement IIntruderPayloadGeneratorFactory
    #
    
    def getGeneratorName(self):
        return "Cat On Keyboard 0.12"

    def createNewInstance(self, attack):
        # return a new IIntruderPayloadGenerator to generate payloads for this attack
        return IntruderPayloadGenerator()

    #
    # implement IIntruderPayloadProcessor
    #
    
    def getProcessorName(self):
        return "Serialized input wrapper"

    def processPayload(self, currentPayload, originalPayload, baseValue):
        # decode the base value
        dataParameter = self._helpers.bytesToString(
                self._helpers.base64Decode(self._helpers.urlDecode(baseValue)))
        
        # parse the location of the input string in the decoded data
        start = dataParameter.index("input=") + 6
        if start == -1:
            return currentPayload

        prefix = dataParameter[0:start]
        end = dataParameter.index("&", start)
        if end == -1:
            end = len(dataParameter)

        suffix = dataParameter[end:len(dataParameter)]
        
        # rebuild the serialized data with the new payload
        dataParameter = prefix + self._helpers.bytesToString(currentPayload) + suffix
        return self._helpers.stringToBytes(
                self._helpers.urlEncode(self._helpers.base64Encode(dataParameter)))



    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):


        myResponse = messageInfo.getResponse()
        try:
            myResponse = "".join(map(chr, myResponse))
        except:
            pass
        # print myResponse

        # get the HTTP service for the request
        httpService = messageInfo.getHttpService()
        myRequest = messageInfo.getRequest()
        myRequest = "".join(map(chr, myRequest))
        myComment = ""

        if self._reqnum == 0:
            print("The original response" + "\n\n")
            print(myResponse + "\n\n")
            messageInfo.setHighlight("blue")
            myComment = "Original response"
            self._originalRes = myResponse

        else:
            bofCleanRes = myResponse
            bofCleanRes = re.sub(r'(A[A]*A)','', bofCleanRes)
            bofCleanRes = re.sub(r'([Dd]{1}ate:.*?\n)','', bofCleanRes)
            self._originalRes = re.sub(r'([Dd]{1}ate:.*?\n)','', self._originalRes)
            
            similarityNum = SequenceMatcher(None, self._originalRes, bofCleanRes).ratio() * 100
            diffNum = "{:05.2f}".format(100 - similarityNum)
            myComment = str(diffNum) + "% different"

            # Find most different
            if diffNum > mostDiff[0]:
                mostDiff[0] = diffNum
                mostDiff[1] = myRequest
                mostDiff[2] = myResponse
                

        if "test1234" in myResponse and "test1234" in myRequest:
            messageInfo.setHighlight("orange")
            myComment = myComment + ", Reflection: test1234"


        elif "bla<xss>bla" in myResponse and "bla<xss>bla" in myRequest:
            messageInfo.setHighlight("red")
            myComment = myComment + ", XSS reflection: bla<xss>bla"


        messageInfo.setComment(myComment)
        

        self._reqnum += 1
        # print(str(self._reqnum))
    
#
# class to generate payloads from a simple list
#

class IntruderPayloadGenerator(IIntruderPayloadGenerator):
    def __init__(self):
        self._payloadIndex = 0
        self._n = int(0)

    def hasMorePayloads(self):
        return self._payloadIndex < len(PAYLOADS)

    def getNextPayload(self, baseValue):
        payload = PAYLOADS[self._payloadIndex]
        self._payloadIndex = self._payloadIndex + 1
        byte_data = baseValue
        s = "".join(map(chr, byte_data)) 
        total_req = len(s) * len(stuff)
        # print ("total req: "+str(total_req))
        if self._n <= total_req:
            for thing in stuff:
                for c in s:
                    self._n = int(self._n + 1) 
                    # print("self._n: "+str(self._n))
                    PAYLOADS.append(bytearray(c))
                    # return s[:(self._n / len(stuff)) - 1]+stuff[self._n % len(stuff)]+s[(self._n / len(stuff)):]
                    return s[:(self._n / len(stuff))]+stuff[self._n % len(stuff)]+s[(self._n / len(stuff)):]
        else:
            print("Most different got updated\nDifference percent" + str(mostDiff[0]) + "Request\n\n" + str(mostDiff[1]) + "Response\n\n" + str(mostDiff[2]))


    def reset(self):
        self._payloadIndex = 0


