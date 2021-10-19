from burp import IBurpExtender
from burp import IMessageEditorTab
from burp import IMessageEditorTabFactory
from burp import IParameter
import base64
import sys
import urllib
import string


class BurpExtender(IBurpExtender, IMessageEditorTabFactory):
    def registerExtenderCallbacks(self, callbacks):

        sys.stdout = callbacks.getStdout()

        self._callbacks = callbacks

        self._helpers = callbacks.getHelpers()

        callbacks.setExtensionName("Base64 Decode")

        callbacks.registerMessageEditorTabFactory(self)

        return
        
    def createNewInstance(self, controller, editable):
        return DisplayValues(self, controller, editable)



class DisplayValues(IMessageEditorTab):
    def __init__(self, extender, controller, editable):
        self._txtInput = extender._callbacks.createTextEditor()
        self._extender = extender

    def getUiComponent(self):
        return self._txtInput.getComponent()
    
    def getTabCaption(self):
        return "B64"
        
    def isEnabled(self, content, isRequest):
        if isRequest == True:
            requestInfo = self._extender._helpers.analyzeRequest(content)
            fullRequest = ""
            
            # body
            allparam = ""
            param = requestInfo.getParameters()
            param = list(param)
            for p in param:
                myvalue = p.getValue()
                myvalueu = urllib.unquote(myvalue).decode('utf8')
                try:
                    myvalueb = str(base64.b64decode(myvalueu))
                    myvalue = filter(lambda x: x in string.printable, myvalueb)
                except:
                    myvalue = ""
                if myvalue != "":
                    allparam += str(p.getName()) + "=" + str(myvalue) + "\n\n"
            fullRequest += allparam
            self._fullRequesturl = fullRequest

        return isRequest and self._fullRequesturl
        
    def setMessage(self, content, isRequest):
        if (content is None):
            self._txtInput.setText(None)
            self._txtInput.setEditable(False)
        else:
            self._txtInput.setText(self._fullRequesturl)
        return
