# ADR-0004: Backend Integration Model

## Status
Proposed

## Context

The proxy daemon must load and communicate with PKCS#11 modules on the server
side. These modules may include HSM vendor libraries (e.g., Thales, Entrust),
software tokens (e.g., SoftHSM2), or module aggregators (e.g., p11-kit).

The current PRD still describes p11-kit as a primary backend integration layer,
but the design target is broader: the daemon must support arbitrary PKCS#11
modules, with vendor HSM libraries as the primary operational targets and
p11-kit only as one example of a module path. The daemon should not couple its
internals to p11-kit's API, configuration format, or subprocess model. The
architectural question is therefore:

- what is the daemon's internal backend abstraction boundary, and
- how does the daemon stay generic across vendor modules without privileging any
  one module family in the architecture?

The core question is: how does the daemon talk to a PKCS#11 backend module, and what abstraction boundary separates the daemon's logic from any specific module?

Related decisions:

- The daemon owns backend module lifecycle globally. `C_Initialize` is called once at startup (or on first client connect), and `C_Finalize` is called only on daemon shutdown or when the last logical client disconnects. Per-client lifecycle coordination is defined in ADR-0002.
- The PKCS#11 coverage policy (ADR-0001) requires the daemon to intersect the backend's reported mechanism list with its own allow-list before exposing capabilities to remote clients. The backend trait must surface mechanism discovery so the coverage filter can operate on it.

## Decision

### 1. Abstract Backend Trait

Define a Rust trait that represents "a PKCS#11 backend." This trait is the daemon's internal interface to any backend module. Its surface maps to the PKCS#11 function list: each PKCS#11 function that the daemon supports has a corresponding method on the trait.

```rust
/// A PKCS#11 backend that the daemon can dispatch operations to.
///
/// Each method corresponds to a supported PKCS#11 function.
/// Unsupported functions are not included in the trait surface;
/// the daemon rejects them before reaching the backend.
pub trait Pkcs11Backend: Send + Sync {
    fn initialize(&self) -> Result<(), Pkcs11Error>;
    fn finalize(&self) -> Result<(), Pkcs11Error>;
    fn get_info(&self) -> Result<Info, Pkcs11Error>;
    fn get_slot_list(&self, token_present: bool) -> Result<Vec<SlotId>, Pkcs11Error>;
    fn get_mechanism_list(&self, slot_id: SlotId) -> Result<Vec<MechanismType>, Pkcs11Error>;
    fn get_mechanism_info(
        &self,
        slot_id: SlotId,
        mechanism_type: MechanismType,
    ) -> Result<MechanismInfo, Pkcs11Error>;
    fn open_session(
        &self,
        slot_id: SlotId,
        flags: SessionFlags,
    ) -> Result<SessionHandle, Pkcs11Error>;
    fn close_session(&self, session: SessionHandle) -> Result<(), Pkcs11Error>;
    // ... remaining supported functions follow the same pattern
}
```

The trait boundary provides three benefits:

- **Testability.** Unit tests can supply a mock or stub backend that returns controlled responses, without loading any shared library.
- **Separation of concerns.** The daemon's session management, coverage filtering, handle virtualization, and protocol logic are independent of how the backend is loaded.
- **Extensibility.** Future backends (cloud KMS adapters, remote-to-remote chaining, test harnesses) can implement the trait without modifying the daemon core.

### 2. Primary Implementation: Direct FFI via dlopen

The primary trait implementation loads a PKCS#11 shared library through the
platform's dynamic linker and calls into it via FFI.

**Loading sequence:**

1. Open the shared library using the platform dynamic-loading API:
   - Linux: `dlopen` (via `libloading` crate)
   - macOS: `dlopen` (same API, `.dylib` extension)
   - Windows (future): `LoadLibrary` (`.dll` extension)

2. Resolve the entry-point symbol:
   - If `C_GetInterface` is present, request the highest standard `"PKCS 11"`
     interface version that the daemon supports, preferring 3.2, then 3.0.
   - If `C_GetInterface` is not present or does not return a usable standard
     interface, fall back to `C_GetFunctionList` and treat the module as v2.x
     only.
   - `C_GetInterfaceList` may be used to inspect the interface set during
     startup diagnostics, but is not required for steady-state dispatch.

3. Store the resolved function pointers in the FFI backend struct. Each trait method dispatches to the corresponding function pointer.

4. Call `C_Initialize` with a `CK_C_INITIALIZE_ARGS` structure that sets
   `flags = CKF_OS_LOCKING_OK` to indicate the daemon's threading model is
   compatible with OS-level locking. The `pReserved` field is `NULL`.

**Safety boundaries:**

- All FFI calls are `unsafe` in Rust. The `unsafe` boundary is confined to the FFI backend implementation. No `unsafe` code leaks into the daemon core, session manager, or protocol layer.
- The `libloading` crate is used for portable dynamic loading rather than raw `libc::dlopen`.
- Function pointer nullness is checked at load time. If a required function pointer is null, the backend reports an error during initialization rather than panicking at call time.

### 3. Example backend module paths

With the direct FFI approach, all backends are consumed as standard PKCS#11
modules rather than through backend-specific management APIs.

- To bypass p11-kit, configure the daemon to load a vendor module directly
  (e.g., `/opt/vendor/lib/pkcs11/libvendor.so`). This is the normal path when
  the deployment targets a specific HSM library.
- To use p11-kit, configure the daemon to load `p11-kit-proxy.so`.
- To use SoftHSM2 for development and testing, load `libsofthsm2.so` directly
  or behind p11-kit, depending on the test case.

This keeps the daemon free of:

- dependency on p11-kit's RPC protocol
- subprocess management for `p11-kit server`
- build-time linkage to p11-kit headers

This keeps all of those module paths on the same footing.

### 4. Configuration

The backend module path is specified in the daemon configuration file. Phase 1
supports a single active backend path at a time.

```toml
[backend]
# Path to the PKCS#11 shared library to load.
# Examples:
#   Direct vendor module: "/opt/vendor/lib/pkcs11/libvendor.so"
#   p11-kit proxy module: "/usr/lib/x86_64-linux-gnu/pkcs11/p11-kit-proxy.so"
#   SoftHSM2 for testing: "/usr/lib/softhsm/libsofthsm2.so"
module = "/opt/vendor/lib/pkcs11/libvendor.so"
```

Future phases may support multiple modules (each with its own slot namespace),
but that is explicitly out of scope for Phase 1. The configuration format is
chosen to be forward-compatible: adding a `[[backend.modules]]` array later
does not break the single-module `backend.module` key.

### 5. Module Lifecycle

The backend module is loaded once and kept resident for the lifetime of the daemon process.

- **Startup:** The daemon loads the shared library, resolves function pointers,
  and calls `C_Initialize`.
- **Unexpected already-initialized case:** On first load in a dedicated daemon
  process, `CKR_CRYPTOKI_ALREADY_INITIALIZED` is treated as unexpected and
  should fail startup unless the daemon is explicitly reusing a previously owned
  managed module instance during an intentional reload path.
- **Steady state:** All client operations dispatch through the stored function pointers. The module remains loaded in memory. There is no per-request or per-session load/unload.
- **Shutdown:** The daemon calls `C_Finalize` and then drops the library handle. This happens on clean daemon shutdown or when the last logical client disconnects (if configured for on-demand lifecycle).
- **Error recovery:** If the module returns `CKR_DEVICE_REMOVED` or `CKR_TOKEN_NOT_PRESENT` for an operation, the daemon propagates the error to the affected client(s). The daemon does not automatically reinitialize the module; operator intervention (restart or reload signal) is required. This avoids hidden state resets that could invalidate other clients' sessions.

### 6. Testing Strategy

The trait boundary supports a layered testing approach:

- **Unit tests (mock backend):** Implement the `Pkcs11Backend` trait with a struct that returns predetermined responses. This tests the daemon's session management, handle virtualization, coverage filtering, and protocol logic in isolation.
- **Integration tests (SoftHSM2):** Use the FFI backend pointed at `libsofthsm2.so` with a temporary token directory. SoftHSM2 is the standard integration test backend because it is freely available, supports a wide mechanism set, and runs without hardware.
- **System tests (p11-kit + SoftHSM2):** Load `p11-kit-proxy.so` configured to aggregate SoftHSM2, validating the aggregation path.
- **Vendor tests:** Load vendor modules in environments with real HSM access. These are not part of CI but are part of the validation matrix.

### 7. Isolation and compatibility rules

- Vendor modules are first-class backends, but only modules that pass the
  validation matrix under the isolation tier selected in ADR-0002 may remain on
  the shared-process path.
- If a direct module cannot safely satisfy `CKF_OS_LOCKING_OK` or leaks state
  across logical clients, the daemon must move that backend to a stronger
  isolation tier instead of pretending the shared-process mode is safe.

## Consequences

**What becomes easier:**

- Supporting any PKCS#11 module without code changes to the daemon. Operators
  choose the backend at deployment time through configuration.
- Testing the daemon in isolation. Mock backends make unit tests fast and deterministic.
- Keeping backend choice open instead of embedding assumptions about any one
  module family.
- Adding new backend types in the future. The trait boundary is the only
  integration point.

**What becomes harder:**

- Multi-module aggregation in Phase 1. The daemon can only load one module path
  at a time. Operators who need multiple modules in Phase 1 must use an
  external aggregator or run multiple daemon instances.
- Slot ID stability. The daemon inherits whatever slot topology the loaded
  module exposes unless it virtualizes slot IDs above that layer.

**What becomes riskier:**

- Module compatibility. Direct FFI means the daemon must handle quirks and
  non-conformances in individual modules. The daemon should log the module's
  `CK_INFO` (library description and version) at startup to aid debugging.
- Thread safety. The daemon calls `C_Initialize` with `CKF_OS_LOCKING_OK`,
  which requires the module to be thread-safe with OS-provided locking. Modules
  that do not honor this flag may exhibit undefined behavior under concurrent
  access and must not remain on the shared-process default path.

**Rejected alternatives:**

- **(B) Shell out to `p11-kit server` as a subprocess.** This would add an extra IPC hop (daemon to p11-kit server via Unix socket using p11-kit's RPC protocol, then p11-kit server to the module via FFI), require subprocess lifecycle management, and create a hard runtime dependency on p11-kit being installed and correctly configured. The performance and complexity costs are not justified when direct FFI to the same `p11-kit-proxy.so` module achieves the same aggregation result with a single FFI hop.
- **Direct integration with p11-kit's internal RPC protocol.** This would couple the daemon to an undocumented, unstable wire format and would provide no benefit over loading `p11-kit-proxy.so` as a standard PKCS#11 module.
