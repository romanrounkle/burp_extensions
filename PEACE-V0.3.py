from burp import IBurpExtender
from burp import IIntruderPayloadGeneratorFactory
from burp import IIntruderPayloadProcessor
from burp import IIntruderPayloadGenerator
from burp import IExtensionHelpers
import base64
from binascii import hexlify
import random
import re
import gzip
import StringIO
import zlib
import hashlib
from burp import IHttpRequestResponse

# hard-coded payloads
# [in reality, you would use an extension for something cleverer than this]

PAYLOADS = [
    bytearray("URL encoded"),
    bytearray("Double URL encoded"),
    bytearray("Triple URL encoded"),
    bytearray("HTML encode"),
    bytearray("HTML encode + 1 zero"),
    bytearray("HTML encode + 2 zero"),
    bytearray("HTML encode + 3 zero"),
    bytearray("HTML encode + 4 zero"),
    bytearray("HTML encode + 5 zero"),
    bytearray("HTML encode with semicolon"),
    bytearray("HTML encode with semicolon + 1 zero"),
    bytearray("HTML encode with semicolon + 2 zero"),
    bytearray("HTML encode with semicolon + 3 zero"),
    bytearray("HTML encode with semicolon + 4 zero"),
    bytearray("HTML encode with semicolon + 5 zero"),
    bytearray("HTML encode capital X + 0 zero"),
    bytearray("HTML encode capital X + 1 zero"),
    bytearray("HTML encode capital X + 2 zero"),
    bytearray("HTML encode capital X + 3 zero"),
    bytearray("HTML encode capital X + 4 zero"),
    bytearray("HTML encode capital X + 5 zero"),
    bytearray("HTML encode capital X and semicolon + 0 zero"),
    bytearray("HTML encode capital X and semicolon + 1 zero"),
    bytearray("HTML encode capital X and semicolon + 2 zero"),
    bytearray("HTML encode capital X and semicolon + 3 zero"),
    bytearray("HTML encode capital X and semicolon + 4 zero"),
    bytearray("HTML encode capital X and semicolon + 5 zero"),
    bytearray("HTML encode capital hex + 0 zero"),
    bytearray("HTML encode capital hex + 1 zero"),
    bytearray("HTML encode capital hex + 2 zero"),
    bytearray("HTML encode capital hex + 3 zero"),
    bytearray("HTML encode capital hex + 4 zero"),
    bytearray("HTML encode capital hex + 5 zero"),
    bytearray("HTML encode capital hex and semicolon + 0 zero"),
    bytearray("HTML encode capital hex and semicolon + 1 zero"),
    bytearray("HTML encode capital hex and semicolon + 2 zero"),
    bytearray("HTML encode capital hex and semicolon + 3 zero"),
    bytearray("HTML encode capital hex and semicolon + 4 zero"),
    bytearray("HTML encode capital hex and semicolon + 5 zero"),
    bytearray("HTML encode capital hex, X + 0 zero"),
    bytearray("HTML encode capital hex, X + 1 zero"),
    bytearray("HTML encode capital hex, X + 2 zero"),
    bytearray("HTML encode capital hex, X + 3 zero"),
    bytearray("HTML encode capital hex, X + 4 zero"),
    bytearray("HTML encode capital hex, X + 5 zero"),
    bytearray("HTML encode capital hex, X and semicolon+ 0 zero"),
    bytearray("HTML encode capital hex, X and semicolon+ 1 zero"),
    bytearray("HTML encode capital hex, X and semicolon+ 2 zero"),
    bytearray("HTML encode capital hex, X and semicolon+ 3 zero"),
    bytearray("HTML encode capital hex, X and semicolon+ 4 zero"),
    bytearray("HTML encode capital hex, X and semicolon+ 5 zero"),
    bytearray("Unicode lowercase"),
    bytearray("Unicode uppercase hex"),
    bytearray("Unicode lowercase with 00"),
    bytearray("Unicode uppercase hex with 00"),
    bytearray("Base64 encoding"),
    bytearray("Null Byte"),
    bytearray("Carrige return string"),
    bytearray("Carrige return url encoded"),
    bytearray("HTML entities encoding"),
    bytearray("HTML entities encoding with semicolon"),
    bytearray("HTML entities encoding upper case"),
    bytearray("HTML entities encoding upper case with semicolon"),
    bytearray("Lowercase"),
    bytearray("Uppercase"),
    bytearray("Alternate case"),
    bytearray("reuniting payload"),
    bytearray("Embedded tab"),
    bytearray("Embedded New line"),
    bytearray("Embedded Carrige return"),
    bytearray("Buffer Overflow 1000"),
    bytearray("Buffer Overflow 2500"),
    bytearray("Buffer Overflow 5000"),
    bytearray("Buffer Overflow 10000"),
    bytearray("Carrige return inverted - AP"),
    bytearray("Alternative Double URL encoding - AP"),
    bytearray("ASCII Hex"),
    bytearray("Double ASCII Hex"),
    bytearray("Embedded payload"),
    bytearray("Comment out 1"),
    bytearray("Comment out 2"),
    bytearray("Comment out 3"),
    bytearray("Comment out 4"),
    bytearray("Comment out 5"),
    bytearray("Comment out 6"),
    bytearray("Comment out 7"),
    bytearray("Comment out 8"),
    bytearray("Comment out 9"),
    bytearray("Comment out 10"),
    bytearray("Comment out 11"),
    bytearray("Comment out 12"),
    bytearray("Comment out 13"),
    bytearray("Comment out 14"),
    bytearray("Comment out 15"),
    bytearray("Comment out 16"),
    bytearray("Encode to binary"),
    bytearray("Compression GZIP"),
    bytearray("Compression ZIP"),
    bytearray("CHOP PAYLOAD")
]



class BurpExtender(IBurpExtender, IIntruderPayloadGeneratorFactory, IIntruderPayloadProcessor,IExtensionHelpers):

    #
    # implement IBurpExtender
    #
    
    def registerExtenderCallbacks(self, callbacks):
        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()
        
        # set our extension name
        callbacks.setExtensionName("Custom intruder payloads")
        
        # register ourselves as an Intruder payload generator
        callbacks.registerIntruderPayloadGeneratorFactory(self)
        
        # register ourselves as an Intruder payload processor
        callbacks.registerIntruderPayloadProcessor(self)

    #
    # implement IIntruderPayloadGeneratorFactory
    #
    
    def getGeneratorName(self):
        return "My custom payloads"

    def createNewInstance(self, attack):
        # return a new IIntruderPayloadGenerator to generate payloads for this attack
        return IntruderPayloadGenerator()

    #
    # implement IIntruderPayloadProcessor
    #
    
    def getProcessorName(self):
        return "Serialized input wrapper"
      

    def processPayload(baseValue):       
        # rebuild the serialized data with the new payload
        dataParameter = baseValue
        return base64.b64encode(dataParameter)

    
#
# class to generate payloads from a simple list
#

class IntruderPayloadGenerator(IIntruderPayloadGenerator):
    def __init__(self):
        self._payloadIndex = 0
        self._chopCount = 0

    def hasMorePayloads(self):
        numPayload = len(PAYLOADS)
        # numPayload = numPayload + 10
        return self._payloadIndex < numPayload 

    def getNextPayload(self, baseValue):
        payload = PAYLOADS[self._payloadIndex]
        self._payloadIndex = self._payloadIndex + 1


        # URL encode payload
        if self._payloadIndex == 1:
            s = hexlify(baseValue)           
            s = '%'.join(s[i:i+2] for i in range(0, len(s), 2))
            s = '%' + s
            return s

        # Double URL encode payload
        elif self._payloadIndex == 2:
            s = hexlify(baseValue)           
            s = '%25'.join(s[i:i+2] for i in range(0, len(s), 2))
            s = '%25' + s
            return s

        # Trible URL encode payload
        elif self._payloadIndex == 3:
            s = hexlify(baseValue)           
            s = '%%2525'.join(s[i:i+2] for i in range(0, len(s), 2))
            s = '%%2525' + s
            return s



        # HTML encode 0 zero
        elif self._payloadIndex == 4:
            s = hexlify(baseValue)           
            s = '&#x'.join(s[i:i+2] for i in range(0, len(s), 2))
            s = '&#x' + s
            return s


        # HTML encode 1 zero
        elif self._payloadIndex == 5:
            s = hexlify(baseValue)           
            s = '&#x0'.join(s[i:i+2] for i in range(0, len(s), 2))
            s = '&#x0' + s
            return s


        # HTML encode 2 zero
        elif self._payloadIndex == 6:
            s = hexlify(baseValue)           
            s = '&#x00'.join(s[i:i+2] for i in range(0, len(s), 2))
            s = '&#x00' + s
            return s


        # HTML encode 3 zero
        elif self._payloadIndex == 7:
            s = hexlify(baseValue)           
            s = '&#x000'.join(s[i:i+2] for i in range(0, len(s), 2))
            s = '&#x000' + s
            return s


        # HTML encode 4 zero
        elif self._payloadIndex == 8:
            s = hexlify(baseValue)           
            s = '&#x0000'.join(s[i:i+2] for i in range(0, len(s), 2))
            s = '&#x0000' + s
            return s


        # HTML encode 5 zero
        elif self._payloadIndex == 9:
            s = hexlify(baseValue)           
            s = '&#x00000'.join(s[i:i+2] for i in range(0, len(s), 2))
            s = '&#x00000' + s
            return s


        # HTML encode with semicolon 0 zero
        elif self._payloadIndex == 10:
            s = hexlify(baseValue)
            s = ';'.join(s[i:i+2] for i in range(0, len(s), 2))  
            s = s + ';'         
            s = '&#x'.join(s[i:i+3] for i in range(0, len(s), 3))
            s = '&#x' + s
            return s

        # HTML encode with semicolon 1 zero
        elif self._payloadIndex == 11:
            s = hexlify(baseValue)
            s = ';'.join(s[i:i+2] for i in range(0, len(s), 2))  
            s = s + ';'         
            s = '&#x0'.join(s[i:i+3] for i in range(0, len(s), 3))
            s = '&#x0' + s
            return s

        # HTML encode with semicolon 2 zero
        elif self._payloadIndex == 12:
            s = hexlify(baseValue)
            s = ';'.join(s[i:i+2] for i in range(0, len(s), 2))  
            s = s + ';'         
            s = '&#x00'.join(s[i:i+3] for i in range(0, len(s), 3))
            s = '&#x00' + s
            return s

        # HTML encode with semicolon 3 zero
        elif self._payloadIndex == 13:
            s = hexlify(baseValue)
            s = ';'.join(s[i:i+2] for i in range(0, len(s), 2))  
            s = s + ';'         
            s = '&#x000'.join(s[i:i+3] for i in range(0, len(s), 3))
            s = '&#x000' + s
            return s

        # HTML encode with semicolon 4 zero
        elif self._payloadIndex == 14:
            s = hexlify(baseValue)
            s = ';'.join(s[i:i+2] for i in range(0, len(s), 2))  
            s = s + ';'         
            s = '&#x0000'.join(s[i:i+3] for i in range(0, len(s), 3))
            s = '&#x0000' + s
            return s

        # HTML encode with semicolon 5 zero
        elif self._payloadIndex == 15:
            s = hexlify(baseValue)
            s = ';'.join(s[i:i+2] for i in range(0, len(s), 2))  
            s = s + ';'         
            s = '&#x00000'.join(s[i:i+3] for i in range(0, len(s), 3))
            s = '&#x00000' + s
            return s

        # HTML encode with capital X  0 zero
        elif self._payloadIndex == 16:
            s = hexlify(baseValue)           
            s = '&#X'.join(s[i:i+2] for i in range(0, len(s), 2))
            s = '&#X' + s
            return s

        # HTML encode with capital X  1 zero
        elif self._payloadIndex == 17:
            s = hexlify(baseValue)           
            s = '&#X0'.join(s[i:i+2] for i in range(0, len(s), 2))
            s = '&#X0' + s
            return s

        # HTML encode with capital X  2 zero
        elif self._payloadIndex == 18:
            s = hexlify(baseValue)           
            s = '&#X00'.join(s[i:i+2] for i in range(0, len(s), 2))
            s = '&#X00' + s
            return s


        # HTML encode with capital X  3 zero
        elif self._payloadIndex == 19:
            s = hexlify(baseValue)           
            s = '&#X000'.join(s[i:i+2] for i in range(0, len(s), 2))
            s = '&#X000' + s
            return s

        # HTML encode with capital X  4 zero
        elif self._payloadIndex == 20:
            s = hexlify(baseValue)           
            s = '&#X0000'.join(s[i:i+2] for i in range(0, len(s), 2))
            s = '&#X0000' + s
            return s


        # HTML encode with capital X  5 zero
        elif self._payloadIndex == 21:
            s = hexlify(baseValue)           
            s = '&#X00000'.join(s[i:i+2] for i in range(0, len(s), 2))
            s = '&#X00000' + s
            return s

        # HTML encode with semicolon and capital X  0 zero
        elif self._payloadIndex == 22:
            s = hexlify(baseValue)
            s = ';'.join(s[i:i+2] for i in range(0, len(s), 2))  
            s = s + ';'         
            s = '&#X'.join(s[i:i+3] for i in range(0, len(s), 3))
            s = '&#X' + s
            return s

        # HTML encode with semicolon and capital X  1 zero
        elif self._payloadIndex == 23:
            s = hexlify(baseValue)
            s = ';'.join(s[i:i+2] for i in range(0, len(s), 2))  
            s = s + ';'         
            s = '&#X0'.join(s[i:i+3] for i in range(0, len(s), 3))
            s = '&#X0' + s
            return s

        # HTML encode with semicolon and capital X  2 zero
        elif self._payloadIndex == 24:
            s = hexlify(baseValue)
            s = ';'.join(s[i:i+2] for i in range(0, len(s), 2))  
            s = s + ';'         
            s = '&#X00'.join(s[i:i+3] for i in range(0, len(s), 3))
            s = '&#X00' + s
            return s

        # HTML encode with semicolon and capital X  3 zero
        elif self._payloadIndex == 25:
            s = hexlify(baseValue)
            s = ';'.join(s[i:i+2] for i in range(0, len(s), 2))  
            s = s + ';'         
            s = '&#X000'.join(s[i:i+3] for i in range(0, len(s), 3))
            s = '&#X000' + s
            return s


        # HTML encode with semicolon and capital X  4 zero
        elif self._payloadIndex == 26:
            s = hexlify(baseValue)
            s = ';'.join(s[i:i+2] for i in range(0, len(s), 2))  
            s = s + ';'         
            s = '&#X0000'.join(s[i:i+3] for i in range(0, len(s), 3))
            s = '&#X0000' + s
            return s

        # HTML encode with semicolon and capital X  5 zero
        elif self._payloadIndex == 27:
            s = hexlify(baseValue)
            s = ';'.join(s[i:i+2] for i in range(0, len(s), 2))  
            s = s + ';'         
            s = '&#X00000'.join(s[i:i+3] for i in range(0, len(s), 3))
            s = '&#X00000' + s
            return s

        # HTML encode with capital hex  0 zero
        elif self._payloadIndex == 28:
            s = hexlify(baseValue).upper()           
            s = '&#x'.join(s[i:i+2] for i in range(0, len(s), 2))
            s = '&#x' + s
            return s

        # HTML encode with capital hex  1 zero
        elif self._payloadIndex == 29:
            s = hexlify(baseValue).upper()           
            s = '&#x0'.join(s[i:i+2] for i in range(0, len(s), 2))
            s = '&#x0' + s
            return s

        # HTML encode with capital hex  2 zero
        elif self._payloadIndex == 30:
            s = hexlify(baseValue).upper()           
            s = '&#x00'.join(s[i:i+2] for i in range(0, len(s), 2))
            s = '&#x00' + s
            return s


        # HTML encode with capital hex  3 zero
        elif self._payloadIndex == 31:
            s = hexlify(baseValue).upper()           
            s = '&#x000'.join(s[i:i+2] for i in range(0, len(s), 2))
            s = '&#x000' + s
            return s

        # HTML encode with capital hex  4 zero
        elif self._payloadIndex == 32:
            s = hexlify(baseValue).upper()           
            s = '&#x0000'.join(s[i:i+2] for i in range(0, len(s), 2))
            s = '&#x0000' + s
            return s

        # HTML encode with capital hex  5 zero
        elif self._payloadIndex == 33:
            s = hexlify(baseValue).upper()           
            s = '&#x00000'.join(s[i:i+2] for i in range(0, len(s), 2))
            s = '&#x00000' + s
            return s

        # HTML encode with semicolon and capital  hex 0 zero
        elif self._payloadIndex == 34:
            s = hexlify(baseValue).upper()
            s = ';'.join(s[i:i+2] for i in range(0, len(s), 2))  
            s = s + ';'         
            s = '&#x'.join(s[i:i+3] for i in range(0, len(s), 3))
            s = '&#x' + s
            return s

        # HTML encode with semicolon and capital  hex 1 zero
        elif self._payloadIndex == 35:
            s = hexlify(baseValue).upper()
            s = ';'.join(s[i:i+2] for i in range(0, len(s), 2))  
            s = s + ';'         
            s = '&#x0'.join(s[i:i+3] for i in range(0, len(s), 3))
            s = '&#x0' + s
            return s

        # HTML encode with semicolon and capital  hex 2 zero
        elif self._payloadIndex == 36:
            s = hexlify(baseValue).upper()
            s = ';'.join(s[i:i+2] for i in range(0, len(s), 2))  
            s = s + ';'         
            s = '&#x00'.join(s[i:i+3] for i in range(0, len(s), 3))
            s = '&#x00' + s
            return s

        # HTML encode with semicolon and capital  hex  3 zero
        elif self._payloadIndex == 37:
            s = hexlify(baseValue).upper()
            s = ';'.join(s[i:i+2] for i in range(0, len(s), 2))  
            s = s + ';'         
            s = '&#x000'.join(s[i:i+3] for i in range(0, len(s), 3))
            s = '&#x000' + s
            return s

        # HTML encode with semicolon and capital  hex 4 zero
        elif self._payloadIndex == 38:
            s = hexlify(baseValue).upper()
            s = ';'.join(s[i:i+2] for i in range(0, len(s), 2))  
            s = s + ';'         
            s = '&#x0000'.join(s[i:i+3] for i in range(0, len(s), 3))
            s = '&#x0000' + s
            return s

        # HTML encode with semicolon and capital  hex 5 zero
        elif self._payloadIndex == 39:
            s = hexlify(baseValue).upper()
            s = ';'.join(s[i:i+2] for i in range(0, len(s), 2))  
            s = s + ';'         
            s = '&#x00000'.join(s[i:i+3] for i in range(0, len(s), 3))
            s = '&#x00000' + s
            return s

        # HTML encode with capital hex, X  0 zero
        elif self._payloadIndex == 40:
            s = hexlify(baseValue).upper()           
            s = '&#X'.join(s[i:i+2] for i in range(0, len(s), 2))
            s = '&#X' + s
            return s

        # HTML encode with capital hex, X  1 zero
        elif self._payloadIndex == 41:
            s = hexlify(baseValue).upper()           
            s = '&#X0'.join(s[i:i+2] for i in range(0, len(s), 2))
            s = '&#X0' + s
            return s

        # HTML encode with capital hex, X  2 zero
        elif self._payloadIndex == 42:
            s = hexlify(baseValue).upper()           
            s = '&#X00'.join(s[i:i+2] for i in range(0, len(s), 2))
            s = '&#X00' + s
            return s


        # HTML encode with capital  hex, X 3 zero
        elif self._payloadIndex == 43:
            s = hexlify(baseValue).upper()           
            s = '&#X000'.join(s[i:i+2] for i in range(0, len(s), 2))
            s = '&#X000' + s
            return s

        # HTML encode with capital hex, X  4 zero
        elif self._payloadIndex == 44:
            s = hexlify(baseValue).upper()           
            s = '&#X0000'.join(s[i:i+2] for i in range(0, len(s), 2))
            s = '&#X0000' + s
            return s

        # HTML encode with capital hex,X 5 zero
        elif self._payloadIndex == 45:
            s = hexlify(baseValue).upper()           
            s = '&#X00000'.join(s[i:i+2] for i in range(0, len(s), 2))
            s = '&#X00000' + s
            return s

        # HTML encode with semicolon and capital  hex,X 0 zero
        elif self._payloadIndex == 46:
            s = hexlify(baseValue).upper()
            s = ';'.join(s[i:i+2] for i in range(0, len(s), 2))  
            s = s + ';'         
            s = '&#X'.join(s[i:i+3] for i in range(0, len(s), 3))
            s = '&#X' + s
            return s

        # HTML encode with semicolon and capital  hex,X 1 zero
        elif self._payloadIndex == 47:
            s = hexlify(baseValue).upper()
            s = ';'.join(s[i:i+2] for i in range(0, len(s), 2))  
            s = s + ';'         
            s = '&#X0'.join(s[i:i+3] for i in range(0, len(s), 3))
            s = '&#X0' + s
            return s

        # HTML encode with semicolon and capital  hex, X 2 zero
        elif self._payloadIndex == 48:
            s = hexlify(baseValue).upper()
            s = ';'.join(s[i:i+2] for i in range(0, len(s), 2))  
            s = s + ';'         
            s = '&#X00'.join(s[i:i+3] for i in range(0, len(s), 3))
            s = '&#X00' + s
            return s

        # HTML encode with semicolon and capital  hex,X  3 zero
        elif self._payloadIndex == 49:
            s = hexlify(baseValue).upper()
            s = ';'.join(s[i:i+2] for i in range(0, len(s), 2))  
            s = s + ';'         
            s = '&#X000'.join(s[i:i+3] for i in range(0, len(s), 3))
            s = '&#X000' + s
            return s

        # HTML encode with semicolon and capital  hex, X 4 zero
        elif self._payloadIndex == 50:
            s = hexlify(baseValue).upper()
            s = ';'.join(s[i:i+2] for i in range(0, len(s), 2))  
            s = s + ';'         
            s = '&#X0000'.join(s[i:i+3] for i in range(0, len(s), 3))
            s = '&#X0000' + s
            return s

        # HTML encode with semicolon and capital  hex, X 5 zero
        elif self._payloadIndex == 51:
            s = hexlify(baseValue).upper()
            s = ';'.join(s[i:i+2] for i in range(0, len(s), 2))  
            s = s + ';'         
            s = '&#X00000'.join(s[i:i+3] for i in range(0, len(s), 3))
            s = '&#X00000' + s
            return s

        # Unicode lowercase
        elif self._payloadIndex == 52:
            s = hexlify(baseValue)          
            s = '\\x'.join(s[i:i+2] for i in range(0, len(s), 2))
            s = '\\x' + s
            return s


        # Unicode uppercase hex
        elif self._payloadIndex == 53:
            s = hexlify(baseValue).upper()          
            s = '\\x'.join(s[i:i+2] for i in range(0, len(s), 2))
            s = '\\x' + s
            return s

        # Unicode lowercase with 00
        elif self._payloadIndex == 54:
            s = hexlify(baseValue)          
            s = '\\u00'.join(s[i:i+2] for i in range(0, len(s), 2))
            s = '\\u00' + s
            return s

        # Unicode uppercase with 00
        elif self._payloadIndex == 55:
            s = hexlify(baseValue).upper()          
            s = '\\u00'.join(s[i:i+2] for i in range(0, len(s), 2))
            s = '\\u00' + s
            return s

        # Base64 encoding
        elif self._payloadIndex == 56:
            return base64.b64encode(baseValue)

        # Null byte
        elif self._payloadIndex == 57:
            s = '%00'+baseValue
            return s

        # Carrige return string
        elif self._payloadIndex == 58:
            s = '\\r\\n'+baseValue
            return s

        # Carrige return url encoded
        elif self._payloadIndex == 59:
            s = '%0A%0D'+baseValue
            return s

        # HTML entities encoding
        elif self._payloadIndex == 60:
            byte_data = baseValue
            s = "".join(map(chr, byte_data))
	    # list the changes you want
            s = s.replace("&","&amp")
            s = s.replace("<","&lt")
            s = s.replace(">","&gt")            
            s = s.replace("\"","&quot")
            s = s.replace("'","&apos")            
            return s

        # HTML entities encoding with semicolon
        elif self._payloadIndex == 61:
            byte_data = baseValue
            s = "".join(map(chr, byte_data))
	    # list the changes you want
            s = s.replace("&","&amp;")
            s = s.replace("<","&lt;")
            s = s.replace(">","&gt;")            
            s = s.replace("\"","&quot;")
            s = s.replace("'","&apos;")            
            return s

        # HTML entities encoding uppercase 
        elif self._payloadIndex == 62:
            byte_data = baseValue
            s = "".join(map(chr, byte_data))
	    # list the changes you want
            s = s.replace("&","&AMP")
            s = s.replace("<","&LT")
            s = s.replace(">","&GT")            
            s = s.replace("\"","&QUOT")
            s = s.replace("'","&APOS")            
            return s

        # HTML entities encoding uppercase with semicolon
        elif self._payloadIndex == 63:
            byte_data = baseValue
            s = "".join(map(chr, byte_data))
	    # list the changes you want
            s = s.replace("&","&AMP;")
            s = s.replace("<","&LT;")
            s = s.replace(">","&GT;")            
            s = s.replace("\"","&QUOT;")
            s = s.replace("'","&APOS;")            
            return s

        # Lowercase
        elif self._payloadIndex == 64:
            byte_data = baseValue
            s = "".join(map(chr, byte_data))
            s = s.lower()
            return s

        # Uppercase
        elif self._payloadIndex == 65:
            byte_data = baseValue
            s = "".join(map(chr, byte_data))
            s = s.upper()
            return s

        # Alternate cases
        elif self._payloadIndex == 66:
            byte_data = baseValue   
            s = "".join(map(chr, byte_data))
            temp = ""
            for i in s:
                randomNum = random.randint(0,1)
                if randomNum == 0:
                    temp += i.upper()
                else:
                    temp += i.lower()
            return temp


        # Reuniting payload
        elif self._payloadIndex == 67:
            byte_data = baseValue
            s = "".join(map(chr, byte_data))
            regex = r'\b\w+\b'
            list1 = re.findall(regex,s)
            # make list unique
            list1 = list(set(list1))
            for i in list1:
                if len(i) > 1:
                    temp = i[:1] + i + i[1:]
                    s = s.replace(i,temp)
            return s


        # Embedded tab
        elif self._payloadIndex == 68:
            byte_data = baseValue
            s = "".join(map(chr, byte_data))
            regex = r'\b\w+\b'
            list1 = re.findall(regex,s)
            # make list unique
            list1 = list(set(list1))
            for i in list1:
                if len(i) > 1:
                    temp = i[:1] + "%09" + i[1:]
                    s = s.replace(i,temp)
            return s

        # Embedded new line
        elif self._payloadIndex == 69:
            byte_data = baseValue
            s = "".join(map(chr, byte_data))
            regex = r'\b\w+\b'
            list1 = re.findall(regex,s)
            # make list unique
            list1 = list(set(list1))
            for i in list1:
                if len(i) > 1:
                    temp = i[:1] + "%0a" + i[1:]
                    s = s.replace(i,temp)
            return s

        # Embedded new line
        elif self._payloadIndex == 70:
            byte_data = baseValue
            s = "".join(map(chr, byte_data))
            regex = r'\b\w+\b'
            list1 = re.findall(regex,s)
            # make list unique
            list1 = list(set(list1))
            for i in list1:
                if len(i) > 1:
                    temp = i[:1] + "%0a%0d" + i[1:]
                    s = s.replace(i,temp)
            return s


        # bufferoverflow 1000
        elif self._payloadIndex == 71:
            byte_data = baseValue
            s = "".join(map(chr, byte_data))
            o = "A" * 1000
            s = o + s
            return s



        # bufferoverflow 2500
        elif self._payloadIndex == 72:
            byte_data = baseValue
            s = "".join(map(chr, byte_data))
            o = "A" * 2500
            s = o + s
            return s

        # bufferoverflow 5000
        elif self._payloadIndex == 73:
            byte_data = baseValue
            s = "".join(map(chr, byte_data))
            o = "A" * 5000
            s = o + s
            return s

        # bufferoverflow 10000
        elif self._payloadIndex == 74:
            byte_data = baseValue
            s = "".join(map(chr, byte_data))
            o = "A" * 10000
            s = o + s
            return s


        # Carrige return url encoded - AP
        elif self._payloadIndex == 75:
            s = '%0d%0a'+baseValue
            return s

        # Alternative URL encode payload - AP
        if self._payloadIndex == 76:
            s = hexlify(baseValue)
            s = hexlify(s)           
            s = '%'.join(s[i:i+2] for i in range(0, len(s), 2))
            s = '%' + s
            s = '%25'.join(s[i:i+6] for i in range(0, len(s), 6))
            s = '%25' + s
            return s


        # ASCII hex
        if self._payloadIndex == 77:
            s = hexlify(baseValue)
            return s

        # Double ASCII hex
        if self._payloadIndex == 78:
            s = hexlify(baseValue)
            s = hexlify(s)           
            return s

        # Embedded payload
        elif self._payloadIndex == 79:
            s = "blabla"+baseValue+"blabla"
            return s

        # Comment out 1
        elif self._payloadIndex == 80:
            s = "<!--"+baseValue
            return s

        # Comment out 2
        elif self._payloadIndex == 81:
            s = "//"+baseValue
            return s

        # Comment out 3
        elif self._payloadIndex == 82:
            s = "/*"+baseValue
            return s

        # Comment out 4
        elif self._payloadIndex == 83:
            s = "\\"+baseValue
            return s

        # Comment out 5
        elif self._payloadIndex == 84:
            s = "\\\\"+baseValue
            return s

        # Comment out 6 
        elif self._payloadIndex == 85:
            s = "--"+baseValue
            return s

        # Comment out 7
        elif self._payloadIndex == 86:
            s = "#"+baseValue
            return s

        # Comment out 8
        elif self._payloadIndex == 87:
            s = '"""'+baseValue
            return s

        # Comment out 9
        elif self._payloadIndex == 88:
            s = "(*"+baseValue
            return s


        # Comment out 10
        elif self._payloadIndex == 89:
            s = "'"+baseValue
            return s


        # Comment out 11
        elif self._payloadIndex == 90:
            s = "C "+baseValue
            return s


        # Comment out 12
        elif self._payloadIndex == 91:
            s = "!*"+baseValue
            return s


        # Comment out 13
        elif self._payloadIndex == 92:
            s = "--[["+baseValue
            return s


        # Comment out 14
        elif self._payloadIndex == 93:
            s = "%{"+baseValue
            return s


        # Comment out 15
        elif self._payloadIndex == 94:
            s = "<#"+baseValue
            return s


        # Comment out 16
        elif self._payloadIndex == 95:
            s = "=begin "+baseValue
            return s


        # Binary encoding
        elif self._payloadIndex == 96:
            s = "".join(map(chr, baseValue))
            s = ''.join('{0:08b}'.format(ord(x), 'b') for x in s)
            return s

        # Compression GZIP
        elif self._payloadIndex == 97:
            s = baseValue
            out = StringIO.StringIO()
            with gzip.GzipFile(fileobj=out, mode="w") as f:
                f.write(s)
            s = out.getvalue()
            return s


        # Compression ZIP
        elif self._payloadIndex == 98:
            s = "".join(map(chr, baseValue))
            s = zlib.compress(s)

            # add fields
            AddedPayloads = 0
            for i in range(len(baseValue)):
                PAYLOADS.append(bytearray(baseValue[i]))
                # PAYLOADS.append(bytearray(baseValue[i]))
                AddedPayloads = AddedPayloads + 1
            return s




 



        # CHOP PAYLOAD
        
        else:
            # add word fields
            byte_data = baseValue
            sp = "".join(map(chr, byte_data))
            regex = r'\b\w+\b'
            list2 = re.findall(regex,sp)
            # make list unique
            list2 = list(set(list2))
            for w in list2:
                if len(w) > 1:
                    PAYLOADS.append(bytearray(w))

            s = "".join(map(chr, baseValue))
            if self._payloadIndex >= 99 and self._payloadIndex < (len(s) + 99): 
                PAYLOADS.append(bytearray("Add cumulative chop"))
                return str(s[self._payloadIndex - 99])
            elif self._payloadIndex >= (len(s) + 99) and self._payloadIndex <= (len(s) + len(s) + 100):
                # elif self._payloadIndex  > (len(s) + 99):
                return str(s[:self._payloadIndex - (99 + len(s))])
            elif self._payloadIndex > (len(s) + len(s) + 100) and self._payloadIndex <= (len(list2) + len(s) + len(s) + 100):          
	        return str(list2[self._payloadIndex - (101 + len(s) + len(s))])

                   
        

    def reset(self):
        self._payloadIndex = 0
