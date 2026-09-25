/* Minimal PKCS#11 2.40 provider stub for the win32 CI leg.
 *
 * Purpose: prove the PE32 loader path end to end — `LoadLibrary` of a real
 * 32-bit DLL, `C_GetFunctionList` resolution, and a cross-boundary call with
 * u32 `CK_ULONG` and pack(1) structs — without a full 32-bit provider build
 * (SoftHSM2-win is 64-bit and cannot load into a 32-bit daemon).
 *
 * The stub exports exactly one entry point, `C_GetFunctionList` (undecorated
 * via the sibling .def file), returning a static 2.40 function list whose
 * only live entries are `C_Initialize` (returns CKR_OK) and `C_GetInfo`
 * (fills a marker CK_INFO). Every other entry is NULL. There is no
 * `C_GetInterface` export, so the daemon takes its 2.40 legacy path.
 *
 * Calling convention is default C (__cdecl on x86) throughout, matching
 * cryptoki-sys 0.5.0, which declares every cryptoki entry `extern "C"`.
 * Structs are pack(1), matching the bindings' `repr(packed)` on Windows.
 * Field order mirrors cryptoki-sys 0.5.0 `generic.rs` exactly; the static
 * asserts below pin the packed offsets the daemon reads.
 *
 * Build (x86 MSVC, see the `win32` job in cross-platform.yml):
 *   cl /nologo /MT /LD p11win32stub.c /link /DEF:p11win32stub.def
 */

#include <windows.h>

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#pragma pack(push, 1)

/* --- Minimal cryptoki subset (win32: CK_ULONG is 32-bit) --- */
typedef uint32_t CK_ULONG;
typedef uint32_t CK_FLAGS;
typedef uint32_t CK_RV;
typedef unsigned char CK_UTF8CHAR;

typedef struct CK_VERSION {
    unsigned char major;
    unsigned char minor;
} CK_VERSION;

typedef struct CK_INFO {
    CK_VERSION cryptokiVersion;
    CK_UTF8CHAR manufacturerID[32];
    CK_FLAGS flags;
    CK_UTF8CHAR libraryDescription[32];
    CK_VERSION libraryVersion;
} CK_INFO;

#define CKR_OK 0
#define CKR_ARGUMENTS_BAD 7

typedef CK_RV (*CK_C_Initialize_fn)(void *pInitArgs);
typedef CK_RV (*CK_C_GetInfo_fn)(CK_INFO *pInfo);

/* Full v2.40 list in canonical order: the two live entries are typed, the
 * rest are untyped NULL slots (layout-identical at 4 bytes each on x86). */
typedef struct CK_FUNCTION_LIST {
    CK_VERSION version;
    CK_C_Initialize_fn C_Initialize;
    void *C_Finalize;
    CK_C_GetInfo_fn C_GetInfo;
    void *C_GetFunctionList;
    void *C_GetSlotList;
    void *C_GetSlotInfo;
    void *C_GetTokenInfo;
    void *C_GetMechanismList;
    void *C_GetMechanismInfo;
    void *C_InitToken;
    void *C_InitPIN;
    void *C_SetPIN;
    void *C_OpenSession;
    void *C_CloseSession;
    void *C_CloseAllSessions;
    void *C_GetSessionInfo;
    void *C_GetOperationState;
    void *C_SetOperationState;
    void *C_Login;
    void *C_Logout;
    void *C_CreateObject;
    void *C_CopyObject;
    void *C_DestroyObject;
    void *C_GetObjectSize;
    void *C_GetAttributeValue;
    void *C_SetAttributeValue;
    void *C_FindObjectsInit;
    void *C_FindObjects;
    void *C_FindObjectsFinal;
    void *C_EncryptInit;
    void *C_Encrypt;
    void *C_EncryptUpdate;
    void *C_EncryptFinal;
    void *C_DecryptInit;
    void *C_Decrypt;
    void *C_DecryptUpdate;
    void *C_DecryptFinal;
    void *C_DigestInit;
    void *C_Digest;
    void *C_DigestUpdate;
    void *C_DigestKey;
    void *C_DigestFinal;
    void *C_SignInit;
    void *C_Sign;
    void *C_SignUpdate;
    void *C_SignFinal;
    void *C_SignRecoverInit;
    void *C_SignRecover;
    void *C_VerifyInit;
    void *C_Verify;
    void *C_VerifyUpdate;
    void *C_VerifyFinal;
    void *C_VerifyRecoverInit;
    void *C_VerifyRecover;
    void *C_DigestEncryptUpdate;
    void *C_DecryptDigestUpdate;
    void *C_SignEncryptUpdate;
    void *C_DecryptVerifyUpdate;
    void *C_GenerateKey;
    void *C_GenerateKeyPair;
    void *C_WrapKey;
    void *C_UnwrapKey;
    void *C_DeriveKey;
    void *C_SeedRandom;
    void *C_GenerateRandom;
    void *C_GetFunctionStatus;
    void *C_CancelFunction;
    void *C_WaitForSlotEvent;
} CK_FUNCTION_LIST;

#pragma pack(pop)

_Static_assert(sizeof(CK_ULONG) == 4, "win32 CK_ULONG is u32");
_Static_assert(sizeof(CK_INFO) == 72, "pack(1) CK_INFO size");
_Static_assert(sizeof(CK_FUNCTION_LIST) == 274, "version + 68 x u32, packed");
_Static_assert(offsetof(CK_FUNCTION_LIST, C_Initialize) == 2,
               "packed: no padding after version");
_Static_assert(offsetof(CK_FUNCTION_LIST, C_GetInfo) == 10,
               "packed C_GetInfo offset");

static CK_RV stub_initialize(void *pInitArgs) {
    (void)pInitArgs;
    return CKR_OK;
}

/* PKCS#11 fixed-width strings are blank-padded, not NUL-terminated. */
static void fill_field(CK_UTF8CHAR *dst, const char *src) {
    size_t n = strlen(src);
    if (n > 32) {
        n = 32;
    }
    memset(dst, ' ', 32);
    memcpy(dst, src, n);
}

static CK_RV stub_get_info(CK_INFO *pInfo) {
    if (pInfo == NULL) {
        return CKR_ARGUMENTS_BAD;
    }
    pInfo->cryptokiVersion.major = 2;
    pInfo->cryptokiVersion.minor = 40;
    fill_field(pInfo->manufacturerID, "T2RUN WIN32 STUB");
    pInfo->flags = 0;
    fill_field(pInfo->libraryDescription, "PE32 stub provider");
    pInfo->libraryVersion.major = 2;
    pInfo->libraryVersion.minor = 40;
    return CKR_OK;
}

/* Positional init for the live prefix; the remaining slots implicitly NULL. */
static CK_FUNCTION_LIST g_list = {
    {2, 40},
    stub_initialize,
    NULL, /* C_Finalize */
    stub_get_info, /* C_GetInfo */
};

__declspec(dllexport) CK_RV C_GetFunctionList(CK_FUNCTION_LIST **ppFunctionList) {
    if (ppFunctionList == NULL) {
        return CKR_ARGUMENTS_BAD;
    }
    *ppFunctionList = &g_list;
    return CKR_OK;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    (void)hinstDLL;
    (void)fdwReason;
    (void)lpvReserved;
    return TRUE;
}
