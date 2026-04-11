ScriptName HTTPUtils Hidden

;----------------------------------------------------------------------------------------------------------
; Request
;----------------------------------------------------------------------------------------------------------

; load asUrl, returns the request's ID that is used by other functions
; optional URL parameters can be sent via asParamKeys and asParamValues, the two arrays must be equal in length
Int Function Request_GET(Form akForm, String asUrl, Int aiTimeout = 5000, String[] asParamKeys = None, String[] asParamValues = None, String[] asHeaderKeys = None, String[] asHeaderValues = None) Global Native

Int Function Request_POST(Form akForm, String asUrl, Int aiTimeout = 5000, String asBody = "", String[] asHeaderKeys = None, String[] asHeaderValues = None) Global Native

Int Function RequestJSON_GET(Form akForm, String asUrl, Int aiTimeout = 5000, String[] asParamKeys = None, String[] asParamValues = None, String[] asHeaderKeys = None, String[] asHeaderValues = None) Global Native

Int Function RequestJSON_POST(Form akForm, String asUrl, Int aiTimeout = 5000, String asBody = "", String[] asHeaderKeys = None, String[] asHeaderValues = None) Global Native

; destroys an ongoing request, or clears the cache of a previously made request
Function Destroy(Int aiHandle) Global Native


;----------------------------------------------------------------------------------------------------------
; Handling JSON response
;----------------------------------------------------------------------------------------------------------

; returns true if LoadJSON had successfully parsed the JSON response from server
Bool Function ValidateJSON(Int aiHandle) Global Native

; retreive values from a LoadJSON request
; asPath uses RFC 6901 pointer format: use "/" to separate objects and arrays
; example: "/rootObject/subObject/0/arrayItem"
String Function GetJSONString(Int aiHandle, String asPath, String asDefault = "") Global Native
Int Function GetJSONInt(Int aiHandle, String asPath, Int asDefault = 0) Global Native
Float Function GetJSONFloat(Int aiHandle, String asPath, Float asDefault = 0.0) Global Native
Bool Function GetJSONBool(Int aiHandle, String asPath, Bool asDefault = False) Global Native

; returns the number of array items located at asPath
Int Function GetJSONArrayLength(Int aiHandle, String asPath) Global Native


;----------------------------------------------------------------------------------------------------------
; Utilities
;----------------------------------------------------------------------------------------------------------

; take two arrays of key & value pairs, returns the result formatted as JSON object
; @param aiLowercaseKeys Weather to convert the asKeys array to lowercase, to overcome Papyrus' case insensitivity
String Function FormatJSON(String[] asKeys, String[] asValues, Bool aiLowercaseKeys = False) Global Native

; take two arrays of key & value pairs and updates URL parameters in the asURL
String Function EncodeURL(String asURL, String[] asKeys, String[] asValues, Bool aiLowercaseKeys = False) Global Native


;----------------------------------------------------------------------------------------------------------
; AI
;----------------------------------------------------------------------------------------------------------

; shortcut for Request_POST that sets request parameters based on PapyrusHTTP.ini file,
; this is so we have a central ini file for setting the parameters required for AI prompt requests
; OnRequestSuccess() function receives the raw response text
Int Function AIPrompt(Form akForm, String asprompt, Int aiTimeout = 20000) Global Native


;----------------------------------------------------------------------------------------------------------
; Event
;----------------------------------------------------------------------------------------------------------

Event OnRequestSuccess(Int aiHandle, String asResponse)
    "Doing it wrong: copy this method to your Quest script, do not call directly!"
EndEvent

Event OnRequestFail(Int aiHandle, Int aiStatusCode)
    "Doing it wrong: copy this method to your Quest script, do not call directly!"
EndEvent


;----------------------------------------------------------------------------------------------------------
; Deprecated
;----------------------------------------------------------------------------------------------------------
Int Function LoadURL(Form akForm, String asUrl, Int aiTimeout = 5000, String[] asParamKeys = None, String[] asParamValues = None) Global Native
Int Function LoadJSON(Form akForm, String asUrl, Int aiTimeout = 5000, String[] asParamKeys = None, String[] asParamValues = None) Global Native