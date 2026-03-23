#include "logger.h"
#include <thread>
#include <cpr/cpr.h>
#include "nlohmann/json.hpp"
#include "../external/simpleini/SimpleIni.h"

using JSON = nlohmann::json;

std::string aiEndpoint = "";
std::string aiModel = "";
std::string aiApikey = "";

void to_lowercase(std::string& s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
}

struct Request {
    std::string scriptName{};
    VMHandle vmhandle;
    std::shared_ptr<std::atomic_bool> canceled = std::make_shared<std::atomic_bool>(false);
    JSON json;
    bool jsonValidated = false;
};

std::map<int, Request> requests;
int lastHandle = 0;
std::mutex requestMutex;

template <class... Args>
void CallPapyrus(VMHandle a_handle, std::string scriptName, std::string methodName,
                 Args... args)
{
    static auto* vm = BSScript::Internal::VirtualMachine::GetSingleton();
    static auto* policy = vm->GetObjectHandlePolicy();

    BSTSmartPointer<BSScript::Object> papyrusObject;
    BSTSmartPointer<BSScript::IStackCallbackFunctor> callback;

    if (!vm->FindBoundObject(a_handle, scriptName.data(), papyrusObject)) {
        return;
    }

    auto packed = MakeFunctionArguments(std::decay_t<Args>(args)...);

    vm->DispatchMethodCall1(papyrusObject, methodName, packed, callback);
}

int CreateHandle(BSScript::Internal::VirtualMachine* vm, const RE::VMStackID stackID, TESForm* a_form) {
    std::lock_guard<std::mutex> lock{requestMutex};
    auto* frame = vm->allRunningStacks.find(stackID)->second->top->previousFrame;
    auto scriptName = frame->owningObjectType->GetName();
    auto* policy = vm->GetObjectHandlePolicy();
    VMHandle vmhandle = policy->GetHandleForObject(a_form->GetFormType(), a_form);
    requests.emplace(++lastHandle, Request{std::string(scriptName), vmhandle});
    return lastHandle;
}

int CreateRequest(BSScript::Internal::VirtualMachine* vm, const RE::VMStackID stackID,
                    TESForm* a_form, std::string a_url, int a_timeout = 5000,
                    std::vector<std::string> a_paramKeys = std::vector<std::string>(),
                    std::vector<std::string> a_paramValues = std::vector<std::string>(),
                    std::string postBody = "", bool isJSON = false, bool isGET = true,
                    std::vector<std::string> a_HeaderKeys = std::vector<std::string>(),
                    std::vector<std::string> a_HeaderValues = std::vector<std::string>(),
                    std::function<void(cpr::Response& response)> a_callback = nullptr) {
    int handle = CreateHandle(vm, stackID, a_form);
    std::shared_ptr<std::atomic_bool> canceledFlag;
    {
        std::lock_guard<std::mutex> lock(requestMutex);
        canceledFlag = requests[handle].canceled;
    }

    std::jthread([a_url, a_timeout, handle, canceledFlag, a_paramKeys, a_paramValues, postBody, isJSON, isGET,
                  a_HeaderKeys, a_HeaderValues, a_callback]() {
        cpr::Header header;
        if (isJSON) header["Content-Type"] = "application/json";
        if (!a_HeaderKeys.empty() && a_HeaderKeys.size() == a_HeaderValues.size()) {
            for (int i = 0; i < a_HeaderKeys.size(); i++) {
                header[a_HeaderKeys[i]] = a_HeaderValues[i];
            }
        }

        cpr::Response response;
        if (isGET) {
            cpr::Parameters params;
            if (!a_paramKeys.empty() && a_paramKeys.size() == a_paramValues.size()) {
                for (int i = 0; i < a_paramKeys.size(); i++) {
                    params.Add({a_paramKeys[i], a_paramValues[i]});
                }
            }
            response = cpr::Get(cpr::Url{a_url}, cpr::Timeout{a_timeout}, params, header);
        } else {
            response = cpr::Post(cpr::Url{a_url}, cpr::Timeout{a_timeout}, cpr::Body{postBody}, header);
        }
        if (canceledFlag->load()) return; // game was reloaded maybe?

        if (a_callback) {
            a_callback(response);
        }

        SKSE::GetTaskInterface()->AddTask([response = std::move(response), handle, canceledFlag, isJSON, a_callback]() {
            if (canceledFlag->load()) return;  // another safety check

            std::lock_guard<std::mutex> lock(requestMutex);
            auto it = requests.find(handle);
            if (it != requests.end()) {
                auto& req = it->second;
                if (response.status_code == 200) {
                    if (isJSON) {
                        try {
                            req.json = JSON::parse(response.text);
                            if (!req.json.is_discarded()) {
                                req.jsonValidated = true;
                            }
                        } catch (...) {
                        }
                    }
                    CallPapyrus(req.vmhandle, req.scriptName, "OnRequestSuccess", handle, response.text);
                } else {
                    CallPapyrus(req.vmhandle, req.scriptName, "OnRequestFail", handle, (int)response.status_code);
                }
            }
        });
    }).detach();

    return handle;
}

// send GET request
int Request_GET(BSScript::Internal::VirtualMachine* vm, const RE::VMStackID stackID, StaticFunctionTag*, TESForm* a_form,
            std::string a_url, int a_timeout = 5000,
            std::vector<std::string> a_paramKeys = std::vector<std::string>(),
            std::vector<std::string> a_paramValues = std::vector<std::string>(),
            std::vector<std::string> a_headerKeys = std::vector<std::string>(),
            std::vector<std::string> a_headerValues = std::vector<std::string>()) {
    return CreateRequest(vm, stackID, a_form, a_url, a_timeout, a_paramKeys, a_paramValues, "", false, true,
                         a_headerKeys, a_headerValues);
}

// send POST request
int Request_POST(BSScript::Internal::VirtualMachine* vm, const RE::VMStackID stackID, StaticFunctionTag*,
                 TESForm* a_form, std::string a_url, int a_timeout = 5000, std::string a_postBody = "",
                 std::vector<std::string> a_headerKeys = std::vector<std::string>(),
                 std::vector<std::string> a_headerValues = std::vector<std::string>()) {
    return CreateRequest(vm, stackID, a_form, a_url, a_timeout, std::vector<std::string>(), std::vector<std::string>(),
                         a_postBody, false, false, a_headerKeys, a_headerValues);
}

// send GET request and expect & parse JSON response
int RequestJSON_GET(BSScript::Internal::VirtualMachine* vm, const RE::VMStackID stackID, StaticFunctionTag*, TESForm* a_form,
            std::string a_url, int a_timeout = 5000,
            std::vector<std::string> a_paramKeys = std::vector<std::string>(),
            std::vector<std::string> a_paramValues = std::vector<std::string>(),
            std::vector<std::string> a_headerKeys = std::vector<std::string>(),
            std::vector<std::string> a_headerValues = std::vector<std::string>()) {
    return CreateRequest(vm, stackID, a_form, a_url, a_timeout, a_paramKeys, a_paramValues, "", true, true,
                         a_headerKeys, a_headerValues);
}

// send POST request and expect & parse JSON response
int RequestJSON_POST(BSScript::Internal::VirtualMachine* vm, const RE::VMStackID stackID, StaticFunctionTag*,
                 TESForm* a_form, std::string a_url, int a_timeout = 5000, std::string a_postBody = "",
                 std::vector<std::string> a_headerKeys = std::vector<std::string>(),
                 std::vector<std::string> a_headerValues = std::vector<std::string>()) {
    return CreateRequest(vm, stackID, a_form, a_url, a_timeout, std::vector<std::string>(), std::vector<std::string>(),
                         a_postBody, true, false, a_headerKeys, a_headerValues);
}

// @deprecated
int LoadURL(BSScript::Internal::VirtualMachine* vm, const RE::VMStackID stackID, StaticFunctionTag*, TESForm* a_form,
            std::string a_url, int a_timeout = 5000,
            std::vector<std::string> a_paramKeys = std::vector<std::string>(),
            std::vector<std::string> a_paramValues = std::vector<std::string>()) {
    return CreateRequest(vm, stackID, a_form, a_url, a_timeout, a_paramKeys, a_paramValues, "", false);
}

// @deprecated
int LoadJSON(BSScript::Internal::VirtualMachine* vm, const RE::VMStackID stackID, StaticFunctionTag*, TESForm* a_form,
            std::string a_url, int a_timeout = 5000,
            std::vector<std::string> a_paramKeys = std::vector<std::string>(),
            std::vector<std::string> a_paramValues = std::vector<std::string>()) {
    return CreateRequest(vm, stackID, a_form, a_url, a_timeout, a_paramKeys, a_paramValues, "", true);
}

void Destroy(BSScript::Internal::VirtualMachine* vm, const RE::VMStackID stackID, StaticFunctionTag*, int a_handle) {
    std::lock_guard<std::mutex> lock(requestMutex);

    auto it = requests.find(a_handle);
    if (it == requests.end()) return;

    auto* stack = vm->allRunningStacks.find(stackID)->second.get();
    auto* frame = stack->top->previousFrame;
    if (frame->owningObjectType->GetName() == it->second.scriptName) {
        it->second.canceled->store(true);  // Tell the thread to ignore results
        requests.erase(it);
    }
}

bool ValidateJSON(StaticFunctionTag*, int a_handle) {
    std::lock_guard<std::mutex> lock(requestMutex);
    auto it = requests.find(a_handle);
    if (it == requests.end()) return false;
    return it->second.jsonValidated;
}

template <typename T>
T GetJSONValue(int a_handle, const std::string a_path, T a_default) {
    std::lock_guard<std::mutex> lock(requestMutex);
    auto it = requests.find(a_handle);
    if (it == requests.end()) return a_default;

    try {
        nlohmann::json::json_pointer ptr(a_path);

        if (it->second.json.contains(ptr)) {
            return it->second.json[ptr].get<T>();
        }
    } catch (...) {
    }

    return a_default;
}

std::string GetJSONString(StaticFunctionTag*, int a_handle, const std::string a_path, std::string a_default = "") {
    return GetJSONValue<std::string>(a_handle, a_path, a_default);
}

int GetJSONInt(StaticFunctionTag*, int a_handle, const std::string a_path, int a_default = 0) {
    return GetJSONValue<int>(a_handle, a_path, a_default);
}

float GetJSONFloat(StaticFunctionTag*, int a_handle, const std::string a_path, float a_default = 0.0f) {
    return GetJSONValue<float>(a_handle, a_path, a_default);
}

bool GetJSONBool(StaticFunctionTag*, int a_handle, const std::string a_path, bool a_default = false) {
    return GetJSONValue<bool>(a_handle, a_path, a_default);
}

int GetJSONArrayLength(StaticFunctionTag*, int a_handle, const std::string a_path) {
    std::lock_guard<std::mutex> lock(requestMutex);
    auto it = requests.find(a_handle);
    if (it == requests.end()) return 0;

    try {
        nlohmann::json::json_pointer ptr(a_path);
        const auto& node = it->second.json.at(ptr);

        if (node.is_array()) return static_cast<int>(node.size());
    } catch (...) {
    }

    return 0;
}

std::string FormatJSON(StaticFunctionTag*, std::vector<std::string> a_Keys, std::vector<std::string> a_Values,
    bool a_lowercaseKeys = false) {
    std::string output = "";
    if (!a_Keys.empty() && a_Keys.size() == a_Values.size()) {
        JSON payload;
        for (int i = 0; i < a_Keys.size(); i++) {
            if (a_lowercaseKeys) to_lowercase(a_Keys[i]);
            payload[a_Keys[i]] = a_Values[i];
        }
        output = payload.dump();
    }

    return output;
}

void OnMessage(SKSE::MessagingInterface::Message* message) {
    if (message->type == SKSE::MessagingInterface::kDataLoaded) {
        CSimpleIniA ini;
        if (ini.LoadFile("Data/SKSE/Plugins/PapyrusHTTP.ini") == SI_OK) {
            aiApikey = ini.GetValue("AI", "API_Key");
            aiEndpoint = ini.GetValue("AI", "URL");
            aiModel = ini.GetValue("AI", "Model");
        }
    } else if (message->type == SKSE::MessagingInterface::kPostLoadGame) {
        std::lock_guard<std::mutex> lock(requestMutex);
        for (auto& [handle, req] : requests) {
            req.canceled->store(true);  // Invalidate all ongoing threads
        }
        requests.clear();
    }
}

void ParseOpenAIResponse(cpr::Response& response) {
    if (response.status_code != 200) return;

    std::string result;

    try {
        JSON json = JSON::parse(response.text);
        if (json.is_discarded()) return;

        if (json.contains("output")) {  // Responses API
            // response from the AI may include the "reasoning" text as well, we want "message" instead
            for (const auto& item : json["output"]) {
                if (!item.contains("type") || item["type"] != "message") continue;
                if (!item.contains("content")) continue;
                for (const auto& block : item["content"]) {
                    if (block.contains("text")) {
                        result += block["text"].get<std::string>();
                    }
                }
                if (!result.empty()) break;
            }
        } else if (json.contains("choices")) {  // Chat completions API
            const auto& choices = json["choices"];

            if (choices.is_array() && !choices.empty()) {
                const auto& choice = choices[0];
                if (choice.contains("message") && choice["message"].contains("content")) {
                    result = choice["message"]["content"].get<std::string>();
                }
            }
        }
    } catch (const std::exception&) {
    }

    response.text = std::move(result);
}

// a shortcut for Request_POST that sets request parameters based on PapyrusHTTP.ini file.
// I hate that this is here. It's only to have a central place for setting the AI config.
int AIPrompt(BSScript::Internal::VirtualMachine* vm, const RE::VMStackID stackID, StaticFunctionTag*,
             TESForm* a_form, std::string a_prompt, int a_timeout = 20000) {
    if (aiEndpoint.empty()) return 0;
        std::vector<std::string> headerKeys{"Content-Type"};
    std::vector<std::string> headerValues{"application/json"};
    if (!aiApikey.empty()) {
        headerKeys.push_back("Authorization");
        headerValues.push_back("Bearer " + aiApikey);
    }
    bool newAPI = true;
    // old OpenAI API format
    if (aiEndpoint.ends_with("/completions"sv)) {
        newAPI = false;
    }

    JSON body;
    if (newAPI) {
        body["model"] = aiModel;
        body["input"] = a_prompt;
    } else {
        body["model"] = aiModel;
        body["messages"] = JSON::array({{{"role", "user"}, {"content", a_prompt}}});
    }
    return CreateRequest(vm, stackID, a_form, aiEndpoint, a_timeout, {}, {}, body.dump(), false, false, headerKeys,
                         headerValues, ParseOpenAIResponse);
}

bool PapyrusBinder(RE::BSScript::IVirtualMachine* vm) {
    std::string_view scriptName = "HTTPUtils";

    vm->RegisterFunction("Request_GET", scriptName, Request_GET);
    vm->RegisterFunction("RequestJSON_GET", scriptName, RequestJSON_GET);
    vm->RegisterFunction("Request_POST", scriptName, Request_POST);
    vm->RegisterFunction("RequestJSON_POST", scriptName, RequestJSON_POST);
    vm->RegisterFunction("Destroy", scriptName, Destroy);

    // JSON response
    vm->RegisterFunction("ValidateJSON", scriptName, ValidateJSON);
    vm->RegisterFunction("GetJSONString", scriptName, GetJSONString);
    vm->RegisterFunction("GetJSONFloat", scriptName, GetJSONFloat);
    vm->RegisterFunction("GetJSONInt", scriptName, GetJSONInt);
    vm->RegisterFunction("GetJSONBool", scriptName, GetJSONBool);
    vm->RegisterFunction("GetJSONArrayLength", scriptName, GetJSONArrayLength);

    // utilities
    vm->RegisterFunction("FormatJSON", scriptName, FormatJSON);

    // AI
    vm->RegisterFunction("AIPrompt", scriptName, AIPrompt);

    // @deprecated
    vm->RegisterFunction("LoadURL", scriptName, LoadURL);
    vm->RegisterFunction("LoadJSON", scriptName, LoadJSON);

    return false;
}

SKSEPluginLoad(const SKSE::LoadInterface* skse) {
    SetupLog();
    SKSE::Init(skse);
    SKSE::GetMessagingInterface()->RegisterListener(OnMessage);
    SKSE::GetPapyrusInterface()->Register(PapyrusBinder);
    return true;
}