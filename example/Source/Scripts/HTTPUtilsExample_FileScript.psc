Scriptname HTTPUtilsExample_FileScript extends activemagiceffect

Import HTTPUtils

Event OnEffectStart(Actor akTarget, Actor akCaster)
    ; JSON file is from https://microsoftedge.github.io/Demos/json-dummy-data/
    Int handle = LoadJSONFile("64KB.json")
    If handle == -1
        Debug.MessageBox("Error reading the file.")
        Return
    EndIf

    ; the "name" and "version" keys are wrapped with "###" to avoid
    ; Papyrus string cache, the "###" is removed by HTTPUtils
    ;
    ; also using aiStartIndex & aiEndIndex to limit scope of where we get the data
    String[] names = PluckJSONStringA(handle, "", "###name###", aiStartIndex = 0, aiEndIndex = 10)
    Debug.MessageBox("Length: " + names.Length)
    Utility.Wait(0.2)
    Debug.MessageBox("Names (String): " + names)
    Utility.Wait(0.2)
    Float[] versions = PluckJSONFloatA(handle, "", "###version###", aiStartIndex = 0, aiEndIndex = 10)
    Debug.MessageBox("Version (Float): " + versions)

    ; courteous thing to destroy the handle when we don't need it anymore
    Destroy(handle)
EndEvent
