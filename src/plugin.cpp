#include "logger.h"
#include <thread>
#include <cpr/cpr.h>
#include "nlohmann/json.hpp"

using JSON = nlohmann::json;

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
    std::vector<std::string> a_paramValues = std::vector<std::string>(), bool isJSON = false) {
    int handle = CreateHandle(vm, stackID, a_form);
    std::shared_ptr<std::atomic_bool> canceledFlag;
    {
        std::lock_guard<std::mutex> lock(requestMutex);
        canceledFlag = requests[handle].canceled;
    }

    std::jthread([a_url, a_timeout, handle, canceledFlag, a_paramKeys, a_paramValues, isJSON]() {
        cpr::Parameters params;
        if (!a_paramKeys.empty() && a_paramKeys.size() == a_paramValues.size()) {
            for (int i = 0; i < a_paramKeys.size(); i++) {
                params.Add({a_paramKeys[i], a_paramValues[i]});
            }
        }
        auto response = cpr::Get(cpr::Url{a_url}, cpr::Timeout{a_timeout}, params);
        if (canceledFlag->load()) return; // game was reloaded maybe?

        SKSE::GetTaskInterface()->AddTask([response = std::move(response), handle, canceledFlag, isJSON]() {
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

int LoadURL(BSScript::Internal::VirtualMachine* vm, const RE::VMStackID stackID, StaticFunctionTag*, TESForm* a_form,
            std::string a_url, int a_timeout = 5000,
            std::vector<std::string> a_paramKeys = std::vector<std::string>(),
            std::vector<std::string> a_paramValues = std::vector<std::string>()) {
    return CreateRequest(vm, stackID, a_form, a_url, a_timeout, a_paramKeys, a_paramValues, false);
}

int LoadJSON(BSScript::Internal::VirtualMachine* vm, const RE::VMStackID stackID, StaticFunctionTag*, TESForm* a_form,
            std::string a_url, int a_timeout = 5000,
            std::vector<std::string> a_paramKeys = std::vector<std::string>(),
            std::vector<std::string> a_paramValues = std::vector<std::string>()) {
    return CreateRequest(vm, stackID, a_form, a_url, a_timeout, a_paramKeys, a_paramValues, true);
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

void OnMessage(SKSE::MessagingInterface::Message* message) {
    if (message->type == SKSE::MessagingInterface::kPostLoadGame) {
        std::lock_guard<std::mutex> lock(requestMutex);
        for (auto& [handle, req] : requests) {
            req.canceled->store(true);  // Invalidate all ongoing threads
        }
        requests.clear();
    }
}

bool PapyrusBinder(RE::BSScript::IVirtualMachine* vm) {
    vm->RegisterFunction("LoadURL", "HTTPUtils", LoadURL);
    vm->RegisterFunction("Destroy", "HTTPUtils", Destroy);
    vm->RegisterFunction("LoadJSON", "HTTPUtils", LoadJSON);
    vm->RegisterFunction("ValidateJSON", "HTTPUtils", ValidateJSON);
    vm->RegisterFunction("GetJSONString", "HTTPUtils", GetJSONString);
    vm->RegisterFunction("GetJSONFloat", "HTTPUtils", GetJSONFloat);
    vm->RegisterFunction("GetJSONInt", "HTTPUtils", GetJSONInt);
    vm->RegisterFunction("GetJSONBool", "HTTPUtils", GetJSONBool);

    return false;
}

SKSEPluginLoad(const SKSE::LoadInterface* skse) {
    SetupLog();
    SKSE::Init(skse);
    SKSE::GetMessagingInterface()->RegisterListener(OnMessage);
    SKSE::GetPapyrusInterface()->Register(PapyrusBinder);
    return true;
}
