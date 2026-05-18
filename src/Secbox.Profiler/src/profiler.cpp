// ICorProfilerCallback implementation. Phase-2 observer-only — no IL
// rewriting; the curated tripwire IL rewrite (Phase 4) bolts on by adding
// JITCompilationStarted handling and the ICorProfilerInfo::SetILFunctionBody
// path.
//
// We implement up to ICorProfilerCallback11 for forward compatibility with
// recent CoreCLR; older interface methods are stubs that delegate to base.
// Callbacks are written carefully:
//   - All exceptions caught and swallowed (a thrown exception out of an
//     ICorProfilerCallback method tears down the host).
//   - No blocking I/O — emit() pushes to the ring or directly invokes the
//     managed callback. Both are non-blocking.
//   - No allocation of unbounded size on hot paths.

#include "profiler.h"
#include "event_ring.h"

// corprof.h declares each IID as EXTERN_C const IID with the actual storage
// living in a separate MIDL-generated corprof_i.cpp we don't bundle. Rather
// than fetch that file, we use the MSVC __uuidof() compile-time intrinsic in
// QueryInterface — every interface in corprof.h is decorated with
// MIDL_INTERFACE("guid") which expands to __declspec(uuid(...)), and
// __uuidof reads that attribute without needing any IID storage at link time.

#include <cor.h>
#include <corhdr.h>
#include <corprof.h>

#include <atomic>
#include <sstream>
#include <string>
#include <cstring>

namespace secbox {

extern void Emit(int32_t kind, std::wstring payload);
extern void SetInitialized(bool v);

namespace {
    // Helpers for JSON-ish payload construction. The managed side parses
    // these as JSON; keep keys camelCase to match EnvelopeJson conventions.
    std::wstring Quote(const std::wstring& s) {
        std::wstring out;
        out.reserve(s.size() + 2);
        out += L'"';
        for (auto c : s) {
            switch (c) {
                case L'"':  out += L"\\\""; break;
                case L'\\': out += L"\\\\"; break;
                case L'\n': out += L"\\n";  break;
                case L'\r': out += L"\\r";  break;
                case L'\t': out += L"\\t";  break;
                default:    out += c;       break;
            }
        }
        out += L'"';
        return out;
    }

    std::wstring K(const wchar_t* key) { return std::wstring(L"\"") + key + L"\":"; }
}

class SecboxProfiler : public ICorProfilerCallback11 {
public:
    SecboxProfiler() : ref_(1), info_(nullptr) {}
    virtual ~SecboxProfiler() = default;

    // === IUnknown ===
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv) override {
        if (ppv == nullptr) return E_POINTER;
        if (riid == __uuidof(IUnknown) ||
            riid == __uuidof(ICorProfilerCallback) ||
            riid == __uuidof(ICorProfilerCallback2) ||
            riid == __uuidof(ICorProfilerCallback3) ||
            riid == __uuidof(ICorProfilerCallback4) ||
            riid == __uuidof(ICorProfilerCallback5) ||
            riid == __uuidof(ICorProfilerCallback6) ||
            riid == __uuidof(ICorProfilerCallback7) ||
            riid == __uuidof(ICorProfilerCallback8) ||
            riid == __uuidof(ICorProfilerCallback9) ||
            riid == __uuidof(ICorProfilerCallback10) ||
            riid == __uuidof(ICorProfilerCallback11)) {
            *ppv = static_cast<ICorProfilerCallback11*>(this);
            AddRef();
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return ++ref_; }
    ULONG STDMETHODCALLTYPE Release() override {
        auto r = --ref_;
        if (r == 0) delete this;
        return r;
    }

    // === Initialize / Shutdown ===
    HRESULT STDMETHODCALLTYPE Initialize(IUnknown* unk) override {
        if (unk == nullptr) return E_INVALIDARG;
        HRESULT hr = unk->QueryInterface(__uuidof(ICorProfilerInfo11), reinterpret_cast<void**>(&info_));
        if (FAILED(hr)) {
            // Older runtime — best-effort fall through is fine for observer-
            // only mode. Future IL-rewrite phase requires Info10+.
            hr = unk->QueryInterface(__uuidof(ICorProfilerInfo3), reinterpret_cast<void**>(&info_));
            if (FAILED(hr)) return hr;
        }

        DWORD mask = COR_PRF_MONITOR_MODULE_LOADS
                   | COR_PRF_MONITOR_ASSEMBLY_LOADS
                   | COR_PRF_MONITOR_JIT_COMPILATION
                   | COR_PRF_MONITOR_EXCEPTIONS
                   | COR_PRF_ENABLE_REJIT;       // future IL rewrite
        DWORD maskHi = 0;
        // ICorProfilerInfo methods return HRESULT — they don't throw managed
        // exceptions. SetEventMask2 failure isn't fatal for observer-only mode.
        (void)info_->SetEventMask2(mask, maskHi);

        SetInitialized(true);
        Emit(EK_ProfilerAttached, L"{}");
        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE Shutdown() override {
        Emit(EK_ProfilerDetaching, L"{}");
        SetInitialized(false);
        if (info_) { info_->Release(); info_ = nullptr; }
        return S_OK;
    }

    // === Assembly / Module loads ===
    HRESULT STDMETHODCALLTYPE AssemblyLoadFinished(AssemblyID asmId, HRESULT) override {
        try { Emit(EK_AssemblyLoad, BuildAssemblyPayload(asmId)); }
        catch (...) { /* swallow */ }
        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE ModuleLoadFinished(ModuleID modId, HRESULT) override {
        try { Emit(EK_ModuleLoad, BuildModulePayload(modId)); }
        catch (...) { /* swallow */ }
        return S_OK;
    }

    // === JIT ===
    HRESULT STDMETHODCALLTYPE JITCompilationStarted(FunctionID funcId, BOOL /*safe*/) override {
        try { Emit(EK_JitCompilationStarted, BuildFunctionPayload(funcId, false)); }
        catch (...) { /* swallow */ }
        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE DynamicMethodJITCompilationStarted(
        FunctionID funcId, BOOL /*safe*/, LPCBYTE /*pIL*/, ULONG /*cIL*/) override {
        try { Emit(EK_DynamicMethodJit, BuildFunctionPayload(funcId, true)); }
        catch (...) { /* swallow */ }
        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE ExceptionThrown(ObjectID /*objectId*/) override {
        try { Emit(EK_ExceptionThrown, L"{}"); }
        catch (...) { /* swallow */ }
        return S_OK;
    }

    // === All other inherited methods default to S_OK ===
    // (CoreCLR will not invoke them unless we set their event masks.)
    HRESULT STDMETHODCALLTYPE AppDomainCreationStarted(AppDomainID) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE AppDomainCreationFinished(AppDomainID, HRESULT) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE AppDomainShutdownStarted(AppDomainID) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE AppDomainShutdownFinished(AppDomainID, HRESULT) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE AssemblyLoadStarted(AssemblyID) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE AssemblyUnloadStarted(AssemblyID) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE AssemblyUnloadFinished(AssemblyID, HRESULT) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE ModuleLoadStarted(ModuleID) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE ModuleUnloadStarted(ModuleID) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE ModuleUnloadFinished(ModuleID, HRESULT) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE ModuleAttachedToAssembly(ModuleID, AssemblyID) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE ClassLoadStarted(ClassID) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE ClassLoadFinished(ClassID, HRESULT) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE ClassUnloadStarted(ClassID) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE ClassUnloadFinished(ClassID, HRESULT) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE FunctionUnloadStarted(FunctionID) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE JITCompilationFinished(FunctionID, HRESULT, BOOL) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE JITCachedFunctionSearchStarted(FunctionID, BOOL*) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE JITCachedFunctionSearchFinished(FunctionID, COR_PRF_JIT_CACHE) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE JITFunctionPitched(FunctionID) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE JITInlining(FunctionID, FunctionID, BOOL*) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE ThreadCreated(ThreadID) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE ThreadDestroyed(ThreadID) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE ThreadAssignedToOSThread(ThreadID, DWORD) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE RemotingClientInvocationStarted() override { return S_OK; }
    HRESULT STDMETHODCALLTYPE RemotingClientSendingMessage(GUID*, BOOL) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE RemotingClientReceivingReply(GUID*, BOOL) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE RemotingClientInvocationFinished() override { return S_OK; }
    HRESULT STDMETHODCALLTYPE RemotingServerReceivingMessage(GUID*, BOOL) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE RemotingServerInvocationStarted() override { return S_OK; }
    HRESULT STDMETHODCALLTYPE RemotingServerInvocationReturned() override { return S_OK; }
    HRESULT STDMETHODCALLTYPE RemotingServerSendingReply(GUID*, BOOL) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE UnmanagedToManagedTransition(FunctionID, COR_PRF_TRANSITION_REASON) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE ManagedToUnmanagedTransition(FunctionID, COR_PRF_TRANSITION_REASON) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE RuntimeSuspendStarted(COR_PRF_SUSPEND_REASON) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE RuntimeSuspendFinished() override { return S_OK; }
    HRESULT STDMETHODCALLTYPE RuntimeSuspendAborted() override { return S_OK; }
    HRESULT STDMETHODCALLTYPE RuntimeResumeStarted() override { return S_OK; }
    HRESULT STDMETHODCALLTYPE RuntimeResumeFinished() override { return S_OK; }
    HRESULT STDMETHODCALLTYPE RuntimeThreadSuspended(ThreadID) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE RuntimeThreadResumed(ThreadID) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE MovedReferences(ULONG, ObjectID*, ObjectID*, ULONG*) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE ObjectAllocated(ObjectID, ClassID) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE ObjectsAllocatedByClass(ULONG, ClassID*, ULONG*) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE ObjectReferences(ObjectID, ClassID, ULONG, ObjectID*) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE RootReferences(ULONG, ObjectID*) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE ExceptionSearchFunctionEnter(FunctionID) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE ExceptionSearchFunctionLeave() override { return S_OK; }
    HRESULT STDMETHODCALLTYPE ExceptionSearchFilterEnter(FunctionID) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE ExceptionSearchFilterLeave() override { return S_OK; }
    HRESULT STDMETHODCALLTYPE ExceptionSearchCatcherFound(FunctionID) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE ExceptionOSHandlerEnter(UINT_PTR) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE ExceptionOSHandlerLeave(UINT_PTR) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE ExceptionUnwindFunctionEnter(FunctionID) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE ExceptionUnwindFunctionLeave() override { return S_OK; }
    HRESULT STDMETHODCALLTYPE ExceptionUnwindFinallyEnter(FunctionID) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE ExceptionUnwindFinallyLeave() override { return S_OK; }
    HRESULT STDMETHODCALLTYPE ExceptionCatcherEnter(FunctionID, ObjectID) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE ExceptionCatcherLeave() override { return S_OK; }
    HRESULT STDMETHODCALLTYPE COMClassicVTableCreated(ClassID, REFGUID, void*, ULONG) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE COMClassicVTableDestroyed(ClassID, REFGUID, void*) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE ExceptionCLRCatcherFound() override { return S_OK; }
    HRESULT STDMETHODCALLTYPE ExceptionCLRCatcherExecute() override { return S_OK; }
    // ICorProfilerCallback2+
    HRESULT STDMETHODCALLTYPE ThreadNameChanged(ThreadID, ULONG, WCHAR*) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE GarbageCollectionStarted(int, BOOL*, COR_PRF_GC_REASON) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE SurvivingReferences(ULONG, ObjectID*, ULONG*) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE GarbageCollectionFinished() override { return S_OK; }
    HRESULT STDMETHODCALLTYPE FinalizeableObjectQueued(DWORD, ObjectID) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE RootReferences2(ULONG, ObjectID*, COR_PRF_GC_ROOT_KIND*, COR_PRF_GC_ROOT_FLAGS*, UINT_PTR*) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE HandleCreated(GCHandleID, ObjectID) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE HandleDestroyed(GCHandleID) override { return S_OK; }
    // ICorProfilerCallback3+
    HRESULT STDMETHODCALLTYPE InitializeForAttach(IUnknown* unk, void*, UINT) override {
        return Initialize(unk);
    }
    HRESULT STDMETHODCALLTYPE ProfilerAttachComplete() override { return S_OK; }
    HRESULT STDMETHODCALLTYPE ProfilerDetachSucceeded() override { return S_OK; }
    // ICorProfilerCallback4+
    HRESULT STDMETHODCALLTYPE ReJITCompilationStarted(FunctionID, ReJITID, BOOL) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE GetReJITParameters(ModuleID, mdMethodDef, ICorProfilerFunctionControl*) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE ReJITCompilationFinished(FunctionID, ReJITID, HRESULT, BOOL) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE ReJITError(ModuleID, mdMethodDef, FunctionID, HRESULT) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE MovedReferences2(ULONG, ObjectID*, ObjectID*, SIZE_T*) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE SurvivingReferences2(ULONG, ObjectID*, SIZE_T*) override { return S_OK; }
    // ICorProfilerCallback5+
    HRESULT STDMETHODCALLTYPE ConditionalWeakTableElementReferences(ULONG, ObjectID*, ObjectID*, GCHandleID*) override { return S_OK; }
    // ICorProfilerCallback6+
    HRESULT STDMETHODCALLTYPE GetAssemblyReferences(const WCHAR*, ICorProfilerAssemblyReferenceProvider*) override { return S_OK; }
    // ICorProfilerCallback7+
    HRESULT STDMETHODCALLTYPE ModuleInMemorySymbolsUpdated(ModuleID) override { return S_OK; }
    // ICorProfilerCallback8+
    HRESULT STDMETHODCALLTYPE DynamicMethodUnloaded(FunctionID) override { return S_OK; }
    // ICorProfilerCallback9+
    HRESULT STDMETHODCALLTYPE DynamicMethodJITCompilationFinished(FunctionID, HRESULT, BOOL) override { return S_OK; }
    // ICorProfilerCallback10+
    // Signature mirrors corprof.h: metadata + event payloads as raw byte
    // blobs, stack frames as a UINT_PTR[].
    HRESULT STDMETHODCALLTYPE EventPipeEventDelivered(
        EVENTPIPE_PROVIDER, DWORD, DWORD,
        ULONG, LPCBYTE,
        ULONG, LPCBYTE,
        LPCGUID, LPCGUID,
        ThreadID, ULONG, UINT_PTR[]) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE EventPipeProviderCreated(EVENTPIPE_PROVIDER) override { return S_OK; }
    // ICorProfilerCallback11+
    HRESULT STDMETHODCALLTYPE LoadAsNotificationOnly(BOOL*) override { return S_OK; }

private:
    std::wstring BuildAssemblyPayload(AssemblyID asmId) {
        WCHAR name[512]{}; ULONG nameLen = 0;
        AppDomainID appDomainId = 0; ModuleID moduleId = 0;
        if (info_) info_->GetAssemblyInfo(asmId, _countof(name), &nameLen, name, &appDomainId, &moduleId);
        std::wstringstream ss;
        ss << L"{" << K(L"assemblyId") << static_cast<uint64_t>(asmId)
           << L"," << K(L"name") << Quote(std::wstring(name, nameLen ? nameLen - 1 : 0))
           << L"}";
        return ss.str();
    }

    std::wstring BuildModulePayload(ModuleID modId) {
        WCHAR name[1024]{}; ULONG nameLen = 0;
        AssemblyID asmId = 0; LPCBYTE baseAddr = nullptr;
        if (info_) info_->GetModuleInfo(modId, &baseAddr, _countof(name), &nameLen, name, &asmId);
        std::wstringstream ss;
        ss << L"{" << K(L"moduleId") << static_cast<uint64_t>(modId)
           << L"," << K(L"path") << Quote(std::wstring(name, nameLen ? nameLen - 1 : 0))
           << L"," << K(L"assemblyId") << static_cast<uint64_t>(asmId)
           << L"}";
        return ss.str();
    }

    std::wstring BuildFunctionPayload(FunctionID funcId, bool dynamic) {
        ClassID classId = 0; ModuleID moduleId = 0; mdToken token = 0;
        if (info_) info_->GetFunctionInfo(funcId, &classId, &moduleId, &token);
        std::wstringstream ss;
        ss << L"{" << K(L"functionId") << static_cast<uint64_t>(funcId)
           << L"," << K(L"moduleId") << static_cast<uint64_t>(moduleId)
           << L"," << K(L"token") << static_cast<uint32_t>(token)
           << L"," << K(L"dynamic") << (dynamic ? L"true" : L"false")
           << L"}";
        return ss.str();
    }

    std::atomic<ULONG> ref_;
    ICorProfilerInfo11* info_;
};

} // namespace secbox

// === Exported COM entry points for CoreCLR's profiler loader ===
//
// combaseapi.h already declares DllGetClassObject / DllCanUnloadNow with
// their canonical linkage — we only DEFINE them below; redeclaring with our
// own attributes collides on MSVC (C2375). The .def file (or DllExport
// pragma) handles the export.

#if defined(_WIN32)
#include <objbase.h>
#pragma comment(linker, "/EXPORT:DllGetClassObject,PRIVATE")
#pragma comment(linker, "/EXPORT:DllCanUnloadNow,PRIVATE")
#endif

namespace {
    // Our CLSID — must match SECBOX_PROFILER_CLSID_STR in profiler.h.
    // {53C5B321-7B0E-4F8B-A3D9-5EC5B0A3F101}
    const GUID SecboxProfilerCLSID = { 0x53C5B321, 0x7B0E, 0x4F8B,
        { 0xA3, 0xD9, 0x5E, 0xC5, 0xB0, 0xA3, 0xF1, 0x01 } };

    class ClassFactory : public IClassFactory {
    public:
        HRESULT STDMETHODCALLTYPE CreateInstance(IUnknown* outer, REFIID riid, void** ppv) override {
            if (outer != nullptr) return CLASS_E_NOAGGREGATION;
            auto* p = new secbox::SecboxProfiler();
            HRESULT hr = p->QueryInterface(riid, ppv);
            p->Release();
            return hr;
        }
        HRESULT STDMETHODCALLTYPE LockServer(BOOL) override { return S_OK; }
        HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv) override {
            if (riid == IID_IUnknown || riid == IID_IClassFactory) {
                *ppv = static_cast<IClassFactory*>(this); AddRef(); return S_OK;
            }
            *ppv = nullptr; return E_NOINTERFACE;
        }
        ULONG STDMETHODCALLTYPE AddRef() override { return ++ref_; }
        ULONG STDMETHODCALLTYPE Release() override {
            auto r = --ref_; if (r == 0) delete this; return r;
        }
    private:
        std::atomic<ULONG> ref_{1};
    };
}

STDAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, LPVOID* ppv) {
    if (ppv == nullptr) return E_POINTER;
    if (rclsid != SecboxProfilerCLSID) return CLASS_E_CLASSNOTAVAILABLE;
    auto* f = new ClassFactory();
    HRESULT hr = f->QueryInterface(riid, ppv);
    f->Release();
    return hr;
}

STDAPI DllCanUnloadNow() {
    return S_FALSE; // pinned for process lifetime; matches every other profiler
}
