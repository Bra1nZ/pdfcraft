//! Digital IDs from PKCS #11 tokens and software modules: a certificate with a private key
//! that never leaves the device, only signs on request. This is the common language of the
//! smart cards and cryptographic modules used on Linux (Rutoken, JaCarta, NSS's software
//! token, …), coordinated system-wide by p11-kit.
//!
//! The module hand-rolls the PKCS #11 v2.40 C API it needs (the same way `der`, `cms` and
//! `pkcs12` hand-roll their formats): `dlopen` the module, `C_GetFunctionList`, then
//! enumerate slots → certificates → the private key matching each certificate by its PKCS #11
//! `CKA_ID`. Signing goes through [`crate::keys::ExternalKey`], like the macOS Keychain and
//! the Windows store: PdfCraft never sees the key material, it only asks the device to sign.
//! A token that requires authentication is given its PIN through [`find_with_pin`]; sessions
//! the environment has already authenticated sign without one.
//!
//! RSA (PKCS #1 v1.5) and ECDSA keys sign. GOST keys (Rutoken ECP and friends) enumerate
//! but are left out of the list for now: the signature formats above only carry RSA/ECDSA
//! algorithm identifiers, and GOST signing arrives with the GOST integration.

// The workspace forbids unsafe code; this module is the one documented exception on this
// branch: every `unsafe` line below is a call into, or the plumbing for, the PKCS #11 C
// API of a hardware token, none of it memory management of our own. The upstream branch
// replaces this module with the safe `cryptoki` wrapper and restores the forbid.
// The workspace forbids unsafe code; this module is the one documented exception on this
// branch: every `unsafe` line below is a call into, or the plumbing for, the PKCS #11 C
// API of a hardware token, none of it memory management of our own. The upstream branch
// replaces this module with the safe `cryptoki` wrapper and restores the forbid.
#![allow(unsafe_code)]
use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::sync::{Arc, Mutex, OnceLock};

use crate::keys::{DigestAlg, ExternalKey, PrivateKey, PublicKey};
use crate::{Certificate, DigitalId, SignError};

// --- the slice of the PKCS #11 v2.40 C API PdfCraft uses, with the field order the
// standard fixes for `CK_FUNCTION_LIST` (a truncated struct is fine: the tail is never
// dereferenced). `CK_ULONG` is 64 bits on the 64-bit Unix platforms PdfCraft runs on. ---

type CkRv = u64;
type CkSlotId = u64;
type CkSessionHandle = u64;
type CkObjectHandle = u64;
type CkUlong = u64;

const CKR_OK: CkRv = 0;
const CKR_CRYPTOKI_ALREADY_INITIALIZED: CkRv = 0x191;
const CKR_USER_NOT_LOGGED_IN: CkRv = 0x101;
const CKR_ATTRIBUTE_SENSITIVE: CkRv = 0x11;
const CKR_ATTRIBUTE_TYPE_INVALID: CkRv = 0x12;
const CKR_BUFFER_TOO_SMALL: CkRv = 0x130;

const CKO_CERTIFICATE: CkUlong = 0x1;
const CKO_PRIVATE_KEY: CkUlong = 0x3;
const CKC_X_509: CkUlong = 0x0;
const CKK_RSA: CkUlong = 0x0;
const CKK_EC: CkUlong = 0x3;

const CKA_CLASS: CkUlong = 0x0000_0000;
const CKA_VALUE: CkUlong = 0x0000_0011;
const CKA_KEY_TYPE: CkUlong = 0x0000_0100;
const CKA_ID: CkUlong = 0x0000_0102;
const CKA_CERTIFICATE_TYPE: CkUlong = 0x0000_0080;

const CKM_RSA_PKCS: CkUlong = 0x1;
const CKM_ECDSA: CkUlong = 0x1041;
const CKU_USER: CkUlong = 1;
const CKF_TOKEN_PRESENT: u8 = 1;
const CKF_SERIAL_SESSION: CkUlong = 0x4;
const CKF_RW_SESSION: CkUlong = 0x2;
const CKF_LOGIN_REQUIRED: CkUlong = 0x4;

#[repr(C)]
#[derive(Clone, Copy)]
struct CkVersion {
    major: u8,
    minor: u8,
}

#[repr(C)]
struct CkTokenInfo {
    label: [u8; 32],
    _manufacturer: [u8; 32],
    _model: [u8; 16],
    _serial: [u8; 16],
    flags: CkUlong,
    // The module writes the full `CK_TOKEN_INFO`; the fields below must exist so the
    // write stays inside the struct, even though their values are never read.
    _max_session_count: CkUlong,
    _session_count: CkUlong,
    _max_rw_session_count: CkUlong,
    _rw_session_count: CkUlong,
    _max_pin_len: CkUlong,
    _min_pin_len: CkUlong,
    _total_public_memory: CkUlong,
    _free_public_memory: CkUlong,
    _total_private_memory: CkUlong,
    _free_private_memory: CkUlong,
    _hardware_version: CkVersion,
    _firmware_version: CkVersion,
    _utc_time: [u8; 16],
}

/// One attribute of a search template or a value query. The buffers a template's pointers
/// refer to live in the caller's scope, next to the template.
#[repr(C)]
struct CkAttribute {
    attr_type: CkUlong,
    p_value: *mut c_void,
    value_len: CkUlong,
}

#[repr(C)]
struct CkMechanism {
    mechanism: CkUlong,
    p_parameter: *mut c_void,
    parameter_len: CkUlong,
}

type CkInitializeFn = unsafe extern "C" fn(*mut c_void) -> CkRv;
type CkGetSlotListFn = unsafe extern "C" fn(u8, *mut CkSlotId, *mut CkUlong) -> CkRv;
type CkGetTokenInfoFn = unsafe extern "C" fn(CkSlotId, *mut CkTokenInfo) -> CkRv;
type CkOpenSessionFn = unsafe extern "C" fn(CkSlotId, CkUlong, *mut c_void, *const c_void, *mut CkSessionHandle) -> CkRv;
type CkLoginFn = unsafe extern "C" fn(CkSessionHandle, CkUlong, *const u8, CkUlong) -> CkRv;
type CkFindObjectsInitFn = unsafe extern "C" fn(CkSessionHandle, *mut CkAttribute, CkUlong) -> CkRv;
type CkFindObjectsFn = unsafe extern "C" fn(CkSessionHandle, *mut CkObjectHandle, CkUlong, *mut CkUlong) -> CkRv;
type CkFindObjectsFinalFn = unsafe extern "C" fn(CkSessionHandle) -> CkRv;
type CkGetAttributeValueFn = unsafe extern "C" fn(CkSessionHandle, CkObjectHandle, *mut CkAttribute, CkUlong) -> CkRv;
type CkSignInitFn = unsafe extern "C" fn(CkSessionHandle, *mut CkMechanism, CkObjectHandle) -> CkRv;
type CkSignFn = unsafe extern "C" fn(CkSessionHandle, *const u8, CkUlong, *mut u8, *mut CkUlong) -> CkRv;

/// The function pointers PdfCraft calls, in the order `CK_FUNCTION_LIST` fixes (truncated
/// after `C_Sign`: nothing further down is reached).
#[repr(C)]
struct FunctionList {
    version: CkVersion,
    c_initialize: CkInitializeFn,
    _c_finalize: *mut c_void,
    _c_get_info: *mut c_void,
    _c_get_function_list: *mut c_void,
    c_get_slot_list: CkGetSlotListFn,
    _c_get_slot_info: *mut c_void,
    c_get_token_info: CkGetTokenInfoFn,
    _c_get_mechanism_list: *mut c_void,
    _c_get_mechanism_info: *mut c_void,
    _c_init_token: *mut c_void,
    _c_init_pin: *mut c_void,
    _c_set_pin: *mut c_void,
    c_open_session: CkOpenSessionFn,
    _c_close_session: *mut c_void,
    _c_close_all_sessions: *mut c_void,
    _c_get_session_info: *mut c_void,
    _c_get_operation_state: *mut c_void,
    _c_set_operation_state: *mut c_void,
    c_login: CkLoginFn,
    _c_logout: *mut c_void,
    _c_create_object: *mut c_void,
    _c_copy_object: *mut c_void,
    _c_destroy_object: *mut c_void,
    _c_get_object_size: *mut c_void,
    c_get_attribute_value: CkGetAttributeValueFn,
    _c_set_attribute_value: *mut c_void,
    c_find_objects_init: CkFindObjectsInitFn,
    c_find_objects: CkFindObjectsFn,
    c_find_objects_final: CkFindObjectsFinalFn,
    _c_encrypt_init: *mut c_void,
    _c_encrypt: *mut c_void,
    _c_encrypt_update: *mut c_void,
    _c_encrypt_final: *mut c_void,
    _c_decrypt_init: *mut c_void,
    _c_decrypt: *mut c_void,
    _c_decrypt_update: *mut c_void,
    _c_decrypt_final: *mut c_void,
    _c_digest_init: *mut c_void,
    _c_digest: *mut c_void,
    _c_digest_update: *mut c_void,
    _c_digest_key: *mut c_void,
    _c_digest_final: *mut c_void,
    c_sign_init: CkSignInitFn,
    c_sign: CkSignFn,
}

unsafe extern "C" {
    fn dlopen(filename: *const c_char, flags: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
    fn dlclose(handle: *mut c_void) -> c_int;
    fn dlerror() -> *mut c_char;
}

const RTLD_NOW: c_int = 0x2;
const RTLD_LOCAL: c_int = 0x1;

/// A loaded PKCS #11 module: its `dlopen` handle (so it stays loaded) and its function
/// list, with `C_Initialize` already called.
struct Raw {
    dl: *mut c_void,
    functions: *mut FunctionList,
}

// The PKCS #11 standard requires the function list to stay valid and the module to be
// thread-safe for these calls; PdfCraft only shares it behind `Arc`.
unsafe impl Send for Raw {}
unsafe impl Sync for Raw {}

impl Raw {
    /// `dlopen` the module and get its function list, initializing it once per process.
    fn load(path: &str) -> Result<Arc<Raw>, SignError> {
        let cpath = CString::new(path).map_err(|_| SignError::Crypto(format!("{path}: not a valid module path")))?;
        // The handle is kept for the process lifetime: sessions reference the module.
        let dl = unsafe { dlopen(cpath.as_ptr(), RTLD_NOW | RTLD_LOCAL) };
        if dl.is_null() {
            let err = unsafe { dlerror() };
            let reason = if err.is_null() { "dlopen failed".to_string() } else { unsafe { CStr::from_ptr(err) }.to_string_lossy().into_owned() };
            return Err(SignError::Crypto(format!("{path}: {reason}")));
        }
        let symbol = CString::new("C_GetFunctionList").map_err(|_| SignError::Crypto("internal: bad symbol name".into()))?;
        let get_list = unsafe { dlsym(dl, symbol.as_ptr()) };
        if get_list.is_null() {
            return Err(SignError::Crypto(format!("{path}: not a PKCS #11 module (no C_GetFunctionList)")));
        }
        let get_list: unsafe extern "C" fn(*mut *mut FunctionList) -> CkRv = unsafe { std::mem::transmute(get_list) };
        let mut functions: *mut FunctionList = std::ptr::null_mut();
        let rv = unsafe { get_list(&mut functions) };
        if rv != CKR_OK || functions.is_null() {
            return Err(SignError::Crypto(format!("{path}: C_GetFunctionList failed (0x{rv:X})")));
        }
        let raw = Arc::new(Raw { dl, functions });
        raw.initialize();
        Ok(raw)
    }

    /// `C_Initialize` once per module; already-initialized (the environment did it) is fine.
    fn initialize(&self) {
        let rv = unsafe { ((*self.functions).c_initialize)(std::ptr::null_mut()) };
        if rv != CKR_OK && rv != CKR_CRYPTOKI_ALREADY_INITIALIZED {
            // A module that fails to initialize simply yields no identities; unrelated
            // tokens keep working.
        }
    }

    fn slots(&self) -> Vec<CkSlotId> {
        let mut count: CkUlong = 0;
        let rv = unsafe { ((*self.functions).c_get_slot_list)(CKF_TOKEN_PRESENT, std::ptr::null_mut(), &mut count) };
        if rv != CKR_OK || count == 0 {
            return Vec::new();
        }
        let mut slots = vec![0u64; count as usize];
        let rv = unsafe { ((*self.functions).c_get_slot_list)(CKF_TOKEN_PRESENT, slots.as_mut_ptr(), &mut count) };
        if rv != CKR_OK {
            return Vec::new();
        }
        slots.truncate(count as usize);
        slots
    }

    fn token(&self, slot: CkSlotId) -> Option<CkTokenInfo> {
        let mut info = CkTokenInfo {
            label: [0; 32],
            _manufacturer: [0; 32],
            _model: [0; 16],
            _serial: [0; 16],
            flags: 0,
            _max_session_count: 0,
            _session_count: 0,
            _max_rw_session_count: 0,
            _rw_session_count: 0,
            _max_pin_len: 0,
            _min_pin_len: 0,
            _total_public_memory: 0,
            _free_public_memory: 0,
            _total_private_memory: 0,
            _free_private_memory: 0,
            _hardware_version: CkVersion { major: 0, minor: 0 },
            _firmware_version: CkVersion { major: 0, minor: 0 },
            _utc_time: [0; 16],
        };
        let rv = unsafe { ((*self.functions).c_get_token_info)(slot, &mut info) };
        (rv == CKR_OK).then_some(info)
    }

    fn open_session(&self, slot: CkSlotId) -> Result<CkSessionHandle, SignError> {
        open_session_at(self, slot, CKF_SERIAL_SESSION | CKF_RW_SESSION)
    }

    fn login(&self, session: CkSessionHandle, pin: &str) -> Result<(), SignError> {
        let rv = unsafe { ((*self.functions).c_login)(session, CKU_USER, pin.as_ptr(), pin.len() as CkUlong) };
        match rv {
            CKR_OK | 0x100 => Ok(()), // 0x100: the user is already signed in on this session.
            _ => Err(SignError::Crypto(match rv {
                0xA0 => "the PIN is incorrect".into(),
                0xA4 => "too many failed PIN attempts; the token is locked".into(),
                _ => format!("the token rejected the sign-in (0x{rv:X})"),
            })),
        }
    }
}

impl Drop for Raw {
    fn drop(&mut self) {
        unsafe { dlclose(self.dl) };
    }
}

/// A session on this slot; reads work on either flag set, but some modules (SoftHSM among
/// them) only take a login on a read-write session.
fn open_session_at(raw: &Raw, slot: CkSlotId, flags: CkUlong) -> Result<CkSessionHandle, SignError> {
    let mut session: CkSessionHandle = 0;
    let rv = unsafe { ((*raw.functions).c_open_session)(slot, flags, std::ptr::null_mut(), std::ptr::null(), &mut session) };
    if rv != CKR_OK {
        return Err(SignError::Crypto(format!("the token didn't open a session (0x{rv:X})")));
    }
    Ok(session)
}

// --- object searches and attributes; every buffer lives in the caller's scope ---

/// The objects matching `template` on this session.
fn find_objects(raw: &Raw, session: CkSessionHandle, template: &mut [CkAttribute]) -> Result<Vec<CkObjectHandle>, SignError> {
    let rv = unsafe { ((*raw.functions).c_find_objects_init)(session, template.as_mut_ptr(), template.len() as CkUlong) };
    if rv != CKR_OK {
        return Err(SignError::Crypto(format!("the token didn't start a search (0x{rv:X})")));
    }
    let mut objects = Vec::new();
    loop {
        let mut batch = [0u64; 16];
        let mut count: CkUlong = 0;
        let rv = unsafe { ((*raw.functions).c_find_objects)(session, batch.as_mut_ptr(), batch.len() as CkUlong, &mut count) };
        if rv != CKR_OK {
            break;
        }
        objects.extend(batch.iter().take(count as usize));
        if count < batch.len() as CkUlong {
            break;
        }
    }
    unsafe { ((*raw.functions).c_find_objects_final)(session) };
    Ok(objects)
}

/// A byte-valued attribute: query its length, then read it.
fn get_bytes(raw: &Raw, session: CkSessionHandle, object: CkObjectHandle, attr_type: CkUlong) -> Result<Vec<u8>, SignError> {
    let mut length_query = [CkAttribute { attr_type, p_value: std::ptr::null_mut(), value_len: 0 }];
    let rv = unsafe { ((*raw.functions).c_get_attribute_value)(session, object, length_query.as_mut_ptr(), 1) };
    let len = match rv {
        CKR_OK => length_query[0].value_len as usize,
        CKR_ATTRIBUTE_SENSITIVE | CKR_ATTRIBUTE_TYPE_INVALID => return Ok(Vec::new()),
        _ => return Err(SignError::Crypto(format!("the token didn't return an attribute (0x{rv:X})"))),
    };
    if len == 0 || len > 1 << 20 {
        return Ok(Vec::new());
    }
    let mut buf = vec![0u8; len];
    let mut read = [CkAttribute { attr_type, p_value: buf.as_mut_ptr() as *mut c_void, value_len: len as CkUlong }];
    let rv = unsafe { ((*raw.functions).c_get_attribute_value)(session, object, read.as_mut_ptr(), 1) };
    if rv != CKR_OK {
        return Err(SignError::Crypto(format!("the token didn't return an attribute (0x{rv:X})")));
    }
    buf.truncate(read[0].value_len as usize);
    Ok(buf)
}

/// A `CK_ULONG`-valued attribute; `None` when the token doesn't provide it.
fn get_ulong(raw: &Raw, session: CkSessionHandle, object: CkObjectHandle, attr_type: CkUlong) -> Option<CkUlong> {
    let mut value: CkUlong = 0;
    let mut attr =
        [CkAttribute { attr_type, p_value: (&mut value) as *mut CkUlong as *mut c_void, value_len: std::mem::size_of::<CkUlong>() as CkUlong }];
    let rv = unsafe { ((*raw.functions).c_get_attribute_value)(session, object, attr.as_mut_ptr(), 1) };
    (rv == CKR_OK).then_some(value)
}

// --- identity discovery ---

/// Modules PdfCraft reads identities from: the `PDFCRAFT_PKCS11_MODULE` environment
/// variable (a `:`-separated list, for tests and non-standard setups), then the system
/// p11-kit proxy, which exposes every module configured in the OS.
fn module_paths() -> Vec<String> {
    if let Ok(list) = std::env::var("PDFCRAFT_PKCS11_MODULE") {
        return list.split(':').filter(|p| !p.is_empty()).map(String::from).collect();
    }
    // The p11-kit proxy is the system-wide aggregate; `p11-kit list-modules` shows what it
    // covers. Its install path varies by multiarch tuple.
    ["/usr/lib/x86_64-linux-gnu", "/usr/lib/aarch64-linux-gnu", "/usr/lib64", "/usr/lib"]
        .iter()
        .map(|dir| format!("{dir}/p11-kit-proxy.so"))
        .collect()
}

/// Loaded modules, initialized once and kept for the process (sessions reference them).
fn modules() -> Vec<Arc<Raw>> {
    static LOADED: OnceLock<Mutex<Vec<(String, Option<Arc<Raw>>)>>> = OnceLock::new();
    let loaded = LOADED.get_or_init(|| Mutex::new(Vec::new()));
    let mut guard = match loaded.lock() {
        Ok(g) => g,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    for path in module_paths() {
        if let Some((_, raw)) = guard.iter().find(|(p, _)| *p == path) {
            if let Some(raw) = raw {
                out.push(Arc::clone(raw));
            }
            continue;
        }
        let raw = Raw::load(&path).ok();
        if let Some(raw) = &raw {
            out.push(Arc::clone(raw));
        }
        guard.push((path, raw));
    }
    out
}

/// One X.509 certificate object on a token, with the `CKA_ID` linking it to its key.
struct TokenCertificate {
    certificate: Certificate,
    id: Vec<u8>,
}

/// The X.509 certificate objects on this session the app could use.
fn token_certificates(raw: &Raw, session: CkSessionHandle) -> Vec<TokenCertificate> {
    let class = CKO_CERTIFICATE.to_ne_bytes();
    let cert_type = CKC_X_509.to_ne_bytes();
    let mut template = [CkAttribute { attr_type: CKA_CLASS, p_value: class.as_ptr() as *mut c_void, value_len: class.len() as CkUlong }];
    let objects = match find_objects(raw, session, &mut template) {
        Ok(o) => o,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    for object in objects {
        let Ok(value) = get_bytes(raw, session, object, CKA_VALUE) else { continue };
        if value.is_empty() {
            continue;
        }
        let Ok(certificate) = Certificate::parse(&value) else { continue };
        // Keys PdfCraft can't represent yet (GOST, Ed25519 on tokens) are left for their
        // stage; an identity must be able to sign.
        if matches!(certificate.public_key, PublicKey::Unsupported { .. }) {
            continue;
        }
        let id = get_bytes(raw, session, object, CKA_ID).unwrap_or_default();
        out.push(TokenCertificate { certificate, id });
    }
    out
}

/// The private key on this session matching `ckaid`, with whether it is an RSA key.
fn session_key(raw: &Raw, session: CkSessionHandle, ckaid: &[u8]) -> Option<(CkObjectHandle, bool)> {
    let class = CKO_PRIVATE_KEY.to_ne_bytes();
    let mut id = ckaid.to_vec();
    let mut template = [
        CkAttribute { attr_type: CKA_CLASS, p_value: class.as_ptr() as *mut c_void, value_len: class.len() as CkUlong },
        CkAttribute { attr_type: CKA_ID, p_value: id.as_mut_ptr() as *mut c_void, value_len: id.len() as CkUlong },
    ];
    let objects = find_objects(raw, session, &mut template).ok()?;
    let object = *objects.first()?;
    let key_type = get_ulong(raw, session, object, CKA_KEY_TYPE);
    // An unknown key type is left to the sign call to refuse.
    match key_type {
        None => Some((object, false)),
        Some(t) if t == CKK_RSA || t == CKK_EC => Some((object, t == CKK_RSA)),
        Some(_) => None,
    }
}

/// The `pkcs11:<SHA-256 of the certificate>` reference PdfCraft keeps for an identity.
pub fn reference(c: &Certificate) -> String {
    let d = DigestAlg::Sha256.digest(&[&c.raw]);
    format!("pkcs11:{}", d.iter().map(|b| format!("{b:02x}")).collect::<String>())
}

fn trimmed_label(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).trim().to_string()
}

/// The other certificates on the same token (the issuers), best effort like the Keychain's.
fn token_chain(raw: &Raw, session: CkSessionHandle, signer: &Certificate) -> Vec<Certificate> {
    token_certificates(&raw, session).into_iter().filter(|c| c.certificate.raw != signer.raw).map(|c| c.certificate).collect()
}

/// The signing identities across all PKCS #11 modules the environment configures: a
/// certificate with a matching private key that may sign. Tokens that need authentication
/// still list their certificates (they are readable); signing asks for the PIN then.
pub fn list() -> Result<Vec<DigitalId>, SignError> {
    let mut out: Vec<DigitalId> = Vec::new();
    let mut seen: Vec<String> = Vec::new();
    let mut any_module = false;
    for raw in modules() {
        any_module = true;
        for &slot in &raw.slots() {
            let token_label = raw.token(slot).map(|info| trimmed_label(&info.label)).unwrap_or_default();
            let Ok(session) = raw.open_session(slot) else { continue };
            let login_required = raw.token(slot).is_some_and(|info| info.flags & CKF_LOGIN_REQUIRED != 0);
            for cert in token_certificates(&raw, session) {
                if session_key(&raw, session, &cert.id).is_none() && !login_required {
                    // No visible key: without login, keys are hidden (CKA_PRIVATE), so a
                    // token that requires login keeps the pairing unproven until the PIN
                    // flow at sign time; a token that doesn't simply has no key.
                    continue;
                }
                let key_reference = reference(&cert.certificate);
                if seen.contains(&key_reference) {
                    continue; // The proxy may surface a module's token more than once.
                }
                seen.push(key_reference);
                let chain = token_chain(&raw, session, &cert.certificate);
                out.push(DigitalId {
                    key: PrivateKey::external(
                        cert.certificate.public_key.clone(),
                        Arc::new(Pkcs11Key { module: Arc::clone(&raw), slot, ckaid: cert.id.clone(), pin: Mutex::new(None) }),
                    ),
                    certificate: cert.certificate,
                    chain,
                    friendly_name: (!token_label.is_empty()).then(|| token_label.clone()),
                });
            }
        }
    }
    if !any_module {
        return Err(SignError::Crypto("no PKCS #11 module was found (p11-kit or PDFCRAFT_PKCS11_MODULE)".into()));
    }
    Ok(out)
}

/// The identity a `pkcs11:` reference (or a certificate common name) names, optionally
/// signed in with its PIN for tokens that require it.
pub fn find_with_pin(reference_or_name: &str, pin: Option<&str>) -> Result<DigitalId, SignError> {
    for raw in modules() {
        for &slot in &raw.slots() {
            let Ok(session) = raw.open_session(slot) else { continue };
            if let Some(pin) = pin {
                // Log in before the search when the token wants it: the private keys are
                // hidden (CKA_PRIVATE) until then. A wrong PIN surfaces at the sign call,
                // so a lookup that finds nothing shouldn't mask why.
                let login_required = raw.token(slot).is_some_and(|info| info.flags & CKF_LOGIN_REQUIRED != 0);
                if login_required {
                    let _ = raw.login(session, pin);
                }
            }
            for cert in token_certificates(&raw, session) {
                let by_name = cert.certificate.subject.common_name() == Some(reference_or_name.trim_start_matches("pkcs11:"));
                if reference(&cert.certificate) != reference_or_name && !by_name {
                    continue;
                }
                let login_required = raw.token(slot).is_some_and(|info| info.flags & CKF_LOGIN_REQUIRED != 0);
                if session_key(&raw, session, &cert.id).is_none() && !login_required {
                    continue; // The key isn't there and can't be hiding behind a login.
                }
                let chain = token_chain(&raw, session, &cert.certificate);
                return Ok(DigitalId {
                    key: PrivateKey::external(
                        cert.certificate.public_key.clone(),
                        Arc::new(Pkcs11Key { module: Arc::clone(&raw), slot, ckaid: cert.id.clone(), pin: Mutex::new(pin.map(String::from)) }),
                    ),
                    certificate: cert.certificate,
                    chain,
                    friendly_name: None,
                });
            }
        }
    }
    Err(SignError::Crypto(format!("no PKCS #11 identity {reference_or_name}")))
}

/// The identity a reference (or certificate common name) names, without a PIN.
pub fn find(reference_or_name: &str) -> Result<DigitalId, SignError> {
    find_with_pin(reference_or_name, None)
}

/// A key that stays on the token: PdfCraft asks the device to sign, session by session.
struct Pkcs11Key {
    module: Arc<Raw>,
    slot: CkSlotId,
    ckaid: Vec<u8>,
    /// The PIN, when `find_with_pin` was given one; sessions opened at sign time log in
    /// with it when the token requires authentication.
    pin: Mutex<Option<String>>,
}

impl ExternalKey for Pkcs11Key {
    /// Sign `msg`, hashing it with `alg` (PKCS #1 v1.5 for RSA, DER-encoded ECDSA).
    fn sign(&self, alg: DigestAlg, msg: &[u8]) -> Result<Vec<u8>, SignError> {
        // One retry: a session can go stale (the token was re-plugged, the daemon reset
        // it); a fresh session on the second pass picks the key up again.
        let mut last = Err(SignError::Crypto("the token didn't sign".into()));
        for attempt in 0..2 {
            match self.sign_once(alg, msg) {
                Ok(sig) => return Ok(sig),
                Err(SignError::Crypto(e)) if attempt == 0 && e.starts_with("session") => last = Err(SignError::Crypto(e)),
                Err(e) => return Err(e),
            }
        }
        last
    }
}

impl Pkcs11Key {
    fn sign_once(&self, alg: DigestAlg, msg: &[u8]) -> Result<Vec<u8>, SignError> {
        let raw = &self.module;
        let Some(info) = raw.token(self.slot) else { return Err(SignError::Crypto("the token is not present".into())) };
        let session = raw
            .open_session(self.slot)
            .map_err(|e| SignError::Crypto(format!("session: {}", strip_prefix(&e.to_string(), "the token didn't open a session "))))?;
        if info.flags & CKF_LOGIN_REQUIRED != 0 {
            let pin = self.pin.lock().ok().and_then(|p| p.clone());
            match (pin, info.flags & CKF_LOGIN_REQUIRED != 0) {
                (Some(pin), true) => raw.login(session, &pin)?,
                (None, true) => {} // Signed without authentication; the token refuses
                // below with a message the UI can act on.
                _ => {}
            }
        }
        let Some((key, rsa)) = session_key(&raw, session, &self.ckaid) else {
            return Err(SignError::Crypto("the token lost its private key".into()));
        };
        let digest = alg.digest(&[msg]);
        let data: Vec<u8> = if rsa { crate::rsa_pad::digest_info(alg, &digest, true) } else { digest };
        let mut mechanism =
            CkMechanism { mechanism: if rsa { CKM_RSA_PKCS } else { CKM_ECDSA }, p_parameter: std::ptr::null_mut(), parameter_len: 0 };
        let rv = unsafe { ((*raw.functions).c_sign_init)(session, &mut mechanism, key) };
        if rv != CKR_OK {
            return Err(SignError::Crypto(match rv {
                CKR_USER_NOT_LOGGED_IN => "the token requires its PIN to sign".into(),
                _ => format!("the token refused to start signing (0x{rv:X})"),
            }));
        }
        let mut len: CkUlong = 0;
        let rv = unsafe { ((*raw.functions).c_sign)(session, data.as_ptr(), data.len() as CkUlong, std::ptr::null_mut(), &mut len) };
        if rv != CKR_BUFFER_TOO_SMALL && rv != CKR_OK {
            return Err(SignError::Crypto(format!("the token didn't sign (0x{rv:X})")));
        }
        let mut signature = vec![0u8; len.max(1) as usize];
        let mut signature_len = len;
        let rv = unsafe { ((*raw.functions).c_sign)(session, data.as_ptr(), data.len() as CkUlong, signature.as_mut_ptr(), &mut signature_len) };
        if rv != CKR_OK {
            return Err(SignError::Crypto(format!("the token didn't sign (0x{rv:X})")));
        }
        signature.truncate(signature_len as usize);
        if rsa {
            return Ok(signature);
        }
        // ECDSA signatures come back as raw `r || s`; PdfCraft carries DER.
        ecdsa_raw_to_der(&signature).ok_or_else(|| SignError::Crypto("the token returned a malformed ECDSA signature".into()))
    }
}

fn strip_prefix(s: &str, prefix: &str) -> String {
    s.strip_prefix(prefix).unwrap_or(s).to_string()
}

/// `r || s` of equal halves → DER `SEQUENCE { r INTEGER, s INTEGER }`.
fn ecdsa_raw_to_der(raw: &[u8]) -> Option<Vec<u8>> {
    if raw.is_empty() || raw.len() % 2 != 0 {
        return None;
    }
    let half = raw.len() / 2;
    let (r, s) = (der_integer(&raw[..half])?, der_integer(&raw[half..])?);
    let len = r.len() + s.len();
    let mut out = Vec::with_capacity(len + 4);
    out.push(0x30);
    if len < 128 {
        out.push(len as u8);
    } else {
        out.push(0x81);
        out.push(len as u8);
    }
    out.extend(r);
    out.extend(s);
    Some(out)
}

fn der_integer(bytes: &[u8]) -> Option<Vec<u8>> {
    let start = bytes.iter().position(|b| *b != 0)?;
    let body = &bytes[start..];
    let needs_pad = body[0] & 0x80 != 0;
    let len = body.len() + usize::from(needs_pad);
    if len >= 128 {
        return None; // A signature half is far shorter than 128 bytes.
    }
    let mut out = Vec::with_capacity(len + 2);
    out.push(0x02);
    out.push(len as u8);
    if needs_pad {
        out.push(0);
    }
    out.extend_from_slice(body);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ecdsa_raw_signature_becomes_der() {
        // r = 1, s = 0x81 (needs a zero pad): minimal encodings.
        let raw = [0, 0, 0, 1, 0, 0, 0, 0x81];
        // r = 1 → `02 01 01`; s = 0x81 → `02 02 00 81`; SEQUENCE of the two = 7 bytes.
        let der = ecdsa_raw_to_der(&raw).expect("encodes");
        assert_eq!(der, vec![0x30, 0x07, 0x02, 0x01, 0x01, 0x02, 0x02, 0x00, 0x81]);
    }

    #[test]
    fn ecdsa_raw_signature_rejects_odd_input() {
        assert!(ecdsa_raw_to_der(&[1, 2, 3]).is_none());
        assert!(ecdsa_raw_to_der(&[]).is_none());
    }

    #[test]
    fn reference_is_a_sha256_fingerprint() {
        // The test CA fixture, PEM-wrapped.
        let pem = include_str!("../tests/data/ca.crt.pem");
        let b64: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
        let der = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64).expect("PEM decodes");
        let cert = crate::x509::Certificate::parse(&der).expect("test CA parses");
        let r = reference(&cert);
        assert!(r.starts_with("pkcs11:"), "{r}");
        assert_eq!(r.len(), "pkcs11:".len() + 64);
    }
}
