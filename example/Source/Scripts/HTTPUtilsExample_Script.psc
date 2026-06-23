Scriptname HTTPUtilsExample_Script extends Quest

Import HTTPUtils

Int handle1
Int handle2
Int handle3

Function Run()
    ; load sample webpage from httpbingo.com
    handle1 = Request_GET(Self, "https://httpbingo.org/html")
EndFunction

; aiHandle is the Int returned by Request* functions,
; useful when you have multiple requests ongoing.
Event OnRequestSuccess(int aiHandle, String asResult)
    If aiHandle == handle1
            Debug.MessageBox("Webpage loaded result: " + asResult)
            Utility.Wait(0.5) ; this is added just so MessageBox behaves properly
            Debug.MessageBox("Now let's try loading JSON!")
            handle2 = RequestJSON_GET(Self, "https://httpbingo.org/json")
    ElseIf aiHandle == handle2
        If ! ValidateJSON(handle2)
            Debug.MessageBox("There was an error in parsing JSON data. We're out of here!")
        Else
            ; looping over JSON array
            Int len = GetJSONArrayLength(handle2, "/slideshow/slides")
            Int i
            String result
            While i < len
                result += i + ": " + GetJSONString(handle2, "/slideshow/slides/" + i + "/title") + "\n"
                i += 1
            EndWhile
            Debug.MessageBox("Now let's loop over a data from JSON! \n\n" + result)
            Utility.Wait(0.5)

            ; you can also get the array:
            String[] items = GetJSONStringA(handle2, "/slideshow/slides/1/items")
            Debug.MessageBox("Items array in second slide: " + items)

            ; free up memory, good practice, but the plugin will
            ; cleanup everything upon loading a save file anyway.
            Destroy(handle2)
        EndIf

        ; request failure example
        Debug.MessageBox("Next request will inveitably fail, since there's a 10 seconds delay but the timeout is set to 1 second only.")
        handle3 = Request_GET(Self, "https://httpbingo.org/delay/10", 1000)
    EndIf
EndEvent

Event OnRequestFail(int aiHandle, Int aiStatusCode)
    Debug.MessageBox("Request with handle " + aiHandle + " failed, status code: " + aiStatusCode)
EndEvent