ScriptName HTTPUtils Hidden

Int[] Function GetVersion() Global Native

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

; check if a previsouly created handle is valid or not
Bool Function ValidateHandle(Int aiHandle) Global Native


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
; retreive a value and interpret it as a FormID, then returns the Form
; FormID must be in one of the following format:
;   - Editor ID (e.g., "BearPelt")
;   - Plugin~FormID (e.g., "0x12345~Skyrim.esm")
;   - Hex FormID (e.g., "0x00012345")
Form Function GetJSONForm(Int aiHandle, String asPath) Global Native

; returns the number of array items located at asPath
Int Function GetJSONArrayLength(Int aiHandle, String asPath) Global Native

; Returns values directly from a JSON array of values
String[] Function GetJSONStringA(Int aiHandle, String asPath, Int aiStartIndex = 0, Int aiEndIndex = 0) Global Native
Int[] Function GetJSONIntA(Int aiHandle, String asPath, Int aiStartIndex = 0, Int aiEndIndex = 0) Global Native
Float[] Function GetJSONFloatA(Int aiHandle, String asPath, Int aiStartIndex = 0, Int aiEndIndex = 0) Global Native
Bool[] Function GetJSONBoolA(Int aiHandle, String asPath, Int aiStartIndex = 0, Int aiEndIndex = 0) Global Native
; retreives the array at asPath, then interpret each value as a FormID.
; FormIDs must be in one of the following format:
;   - Editor ID (e.g., "BearPelt")
;   - Plugin~FormID (e.g., "0x12345~Skyrim.esm")
;   - Hex FormID (e.g., "0x00012345")
Form[] Function GetJSONFormA(Int aiHandle, String asPath, Int aiStartIndex = 0, Int aiEndIndex = 0) Global Native

; Returns a property value from each object in a JSON array of objects
; @param abPreserveIndexes Weather to skip invalid items in the array (default behavior), or use the default value so keep indexes consistent
String[] Function PluckJSONStringA(Int aiHandle, String asPathToArray, String asObjectKey, Int aiStartIndex = 0, Int aiEndIndex = 0, Bool abPreserveIndexes = False, String asDefault = "") Global Native
Int[] Function PluckJSONIntA(Int aiHandle, String asPathToArray, String asObjectKey, Int aiStartIndex = 0, Int aiEndIndex = 0, Bool abPreserveIndexes = False, Int asDefault = 0) Global Native
Float[] Function PluckJSONFloatA(Int aiHandle, String asPathToArray, String asObjectKey, Int aiStartIndex = 0, Int aiEndIndex = 0, Bool abPreserveIndexes = False, Float asDefault = 0.0) Global Native
Bool[] Function PluckJSONBoolA(Int aiHandle, String asPathToArray, String asObjectKey, Int aiStartIndex = 0, Int aiEndIndex = 0, Bool abPreserveIndexes = False, Bool asDefault = False) Global Native
; Looks for an array of objects at asPathToArray, interprets each property key (asObjectKey) as a FormID.
; FormIDs must be in one of the following format:
;   - Editor ID (e.g., "BearPelt")
;   - Plugin~FormID (e.g., "0x12345~Skyrim.esm")
;   - Hex FormID (e.g., "0x00012345")
Form[] Function PluckJSONFormA(Int aiHandle, String asPathToArray, String asObjectKey, Int aiStartIndex = 0, Int aiEndIndex = 0, Bool abPreserveIndexes = False) Global Native


;----------------------------------------------------------------------------------------------------------
; File
;----------------------------------------------------------------------------------------------------------

; I like the JSON api, why not allow reading data from files as well? :D
; this function is not async and you can immediately use the GetJSON* functions ^
; returns -1 if the file was missing or JSON data was invalid.
; path starts from /data directory.
Int Function LoadJSONFile(String asFilePath) Global Native


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