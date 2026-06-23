Scriptname HTTPUtilsExample_UtilsEffectScript extends activemagiceffect
{Example script on how to use utility functions in Papyrus HTTP Utils}

Import HTTPUtils

Event OnEffectStart(Actor akTarget, Actor akCaster)
    ; both FormatJSON() and EncodeURL() require a key/value array pair
    ; length of both arrays must be the same.

    String[] keys = new String[3]
    keys[0] = "param1"
    keys[1] = "param2"
    keys[2] = "param3"

    String[] values = new String[3]
    values[0] = "some string"
    values[1] = 2.9
    values[2] = ""

    Debug.MessageBox("Data formatted as JSON: " + FormatJSON(keys, values))

    Debug.MessageBox("Encoded URL: " + EncodeURL("https://mywebsite.com", keys, values))
EndEvent