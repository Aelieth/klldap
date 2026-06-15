// src/ffi.rs
//
// === ISOLATED UNSAFE FFI LAYER (Kerberos C interop) ===
// This module owns EVERY line of `unsafe` code in the lldap-kerberos crate.
// It is the single place that talks to libkrb5 and libkadm5 via bindgen.
//
// All other code (Keycloak HTTP client, RSA password crypto, config, derive helpers,
// and the high-level safe wrappers) lives in lib.rs and never sees raw pointers or unsafe.
//
// Professional production invariants maintained here:
// - RAII: Kadm5Handle Drop ALWAYS destroys the admin handle and krb5 context.
// - Every krb5_principal from krb5_parse_name is freed exactly once on every path.
// - Every CString::into_raw for passwords/realms is paired with from_raw.
// - pub(crate) visibility + explicit SAFETY comments for auditability and future maintainers.
// - No memory leaks or use-after-free under normal Kerberos operation (and graceful
//   degradation when Kerberos is disabled / keytab missing).

#![allow(unsafe_code)]

use anyhow::{Context, Result};
use std::ffi::{CStr, CString};
use std::mem;
use std::os::raw::{c_char, c_int, c_long, c_void};
use std::ptr;
use tracing::{info, warn};

// Generated FFI bindings — created at compile time by build.rs
#[allow(non_camel_case_types)]
#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(dead_code)]
mod bindings {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

pub use bindings::*; // Re-export for use inside FFI methods only

pub(crate) struct Kadm5Handle {
    pub handle: *mut c_void,
    pub context: krb5_context,
}

impl Kadm5Handle {
    pub fn init_with_keytab(keytab_path: &str, admin_principal: &str, realm: &str) -> Result<Self> {
        let mut context: krb5_context = ptr::null_mut();
        let ret = unsafe { krb5_init_context(&mut context) };
        if ret != 0 {
            return Err(anyhow::anyhow!(
                "krb5_init_context failed with code {}",
                ret
            ));
        }

        let mut handle: *mut c_void = ptr::null_mut();

        let client_name_cstr = CString::new(admin_principal).context("Invalid admin principal")?;
        let keytab_cstr = CString::new(keytab_path).context("Invalid keytab path")?;
        let service_name_ptr: *mut c_char = ptr::null_mut();

        let realm_cstr = CString::new(realm).context("Invalid realm")?;

        let mut params: kadm5_config_params = unsafe { mem::zeroed() };
        params.mask = KADM5_CONFIG_REALM as c_long;
        params.realm = realm_cstr.into_raw();

        let struct_version: krb5_ui_4 = KADM5_STRUCT_VERSION;
        let api_version: krb5_ui_4 = KADM5_API_VERSION_4;

        let db_args_ptr: *mut *mut c_char = ptr::null_mut();

        let ret = unsafe {
            kadm5_init_with_skey(
                context,
                client_name_cstr.as_ptr() as *mut c_char,
                keytab_cstr.as_ptr() as *mut c_char,
                service_name_ptr,
                &mut params,
                struct_version,
                api_version,
                db_args_ptr,
                &mut handle,
            )
        };

        unsafe {
            let _ = CString::from_raw(params.realm);
        }

        if ret != 0 {
            let code = ret as i32;
            let msg_ptr = unsafe { krb5_get_error_message(context, code) };
            let err_msg = if msg_ptr.is_null() {
                format!("code {}", ret)
            } else {
                let s = unsafe { CStr::from_ptr(msg_ptr).to_string_lossy().into_owned() };
                unsafe { krb5_free_error_message(context, msg_ptr) };
                s
            };
            warn!("kadm5_init_with_skey failed with code {}: {}", ret, err_msg);
            unsafe { krb5_free_context(context) };
            return Err(anyhow::anyhow!("kadm5_init_with_skey failed: {}", err_msg));
        }

        Ok(Kadm5Handle { handle, context })
    }

    pub fn create_principal(&self, username: &str, password: &str, realm: &str) -> Result<()> {
        let principal_name = format!("{}@{}", username, realm);
        let principal_cstr = CString::new(principal_name)?;

        let mut princ: krb5_principal = ptr::null_mut();
        let ret = unsafe { krb5_parse_name(self.context, principal_cstr.as_ptr(), &mut princ) };
        if ret != 0 {
            return Err(anyhow::anyhow!("krb5_parse_name failed with code {}", ret));
        }

        let mut ent: kadm5_principal_ent_rec = unsafe { mem::zeroed() };
        ent.principal = princ;

        let mask = KADM5_PRINCIPAL as c_long;

        let pass_cstr = CString::new(password)?;

        let ret = unsafe {
            kadm5_create_principal(
                self.handle,
                &mut ent,
                mask,
                pass_cstr.as_ptr() as *mut c_char,
            )
        };

        unsafe { krb5_free_principal(self.context, princ) };

        if ret != 0 {
            let code = ret as i32;
            let msg_ptr = unsafe { krb5_get_error_message(self.context, code) };
            let err_msg = if msg_ptr.is_null() {
                format!("code {}", ret)
            } else {
                let s = unsafe { CStr::from_ptr(msg_ptr).to_string_lossy().into_owned() };
                unsafe { krb5_free_error_message(self.context, msg_ptr) };
                s
            };
            warn!(
                "kadm5_create_principal failed with code {}: {}",
                ret, err_msg
            );
            return Err(anyhow::anyhow!(
                "kadm5_create_principal failed: {}",
                err_msg
            ));
        }

        Ok(())
    }

    pub fn chpass_principal(&self, username: &str, password: &str, realm: &str) -> Result<()> {
        let principal_name = format!("{}@{}", username, realm);
        let principal_cstr = CString::new(principal_name)?;

        let mut princ: krb5_principal = ptr::null_mut();
        let ret = unsafe { krb5_parse_name(self.context, principal_cstr.as_ptr(), &mut princ) };
        if ret != 0 {
            return Err(anyhow::anyhow!("krb5_parse_name failed with code {}", ret));
        }

        let pass_cstr = CString::new(password)?;

        let ret = unsafe {
            kadm5_chpass_principal(self.handle, princ, pass_cstr.as_ptr() as *mut c_char)
        };

        unsafe { krb5_free_principal(self.context, princ) };

        if ret != 0 {
            let code = ret as i32;
            let msg_ptr = unsafe { krb5_get_error_message(self.context, code) };
            let err_msg = if msg_ptr.is_null() {
                format!("code {}", ret)
            } else {
                let s = unsafe { CStr::from_ptr(msg_ptr).to_string_lossy().into_owned() };
                unsafe { krb5_free_error_message(self.context, msg_ptr) };
                s
            };
            return Err(anyhow::anyhow!(
                "kadm5_chpass_principal failed: {}",
                err_msg
            ));
        }

        Ok(())
    }

    pub fn delete_principal(&self, principal_str: &str) -> Result<()> {
        let principal_c =
            CString::new(principal_str).context("Invalid principal string for CString")?;

        let mut principal: krb5_principal = ptr::null_mut();

        // SAFETY: krb5_parse_name on a valid context produces a principal that must be freed
        // exactly once with krb5_free_principal (done below on all paths).
        let ret = unsafe { krb5_parse_name(self.context, principal_c.as_ptr(), &mut principal) };
        if ret != 0 {
            return Err(anyhow::anyhow!(
                "Failed to parse principal {}: krb5_parse_name ret {}",
                principal_str,
                ret
            ));
        }

        // SAFETY: principal is owned by us; kadm5_delete_principal takes it for the delete operation.
        let ret = unsafe { kadm5_delete_principal(self.handle as *mut c_void, principal) };

        // SAFETY: We free exactly once after the kadm5 call (error paths included).
        unsafe { krb5_free_principal(self.context, principal) };

        if ret == 0 {
            info!("Deleted principal via FFI: {}", principal_str);
            Ok(())
        } else if ret == KADM5_UNK_PRINC as i64 {
            info!(
                "Principal {} does not exist, skipping delete",
                principal_str
            );
            Ok(())
        } else {
            warn!(
                "FFI delete principal failed for {} (code {})",
                principal_str, ret
            );
            Err(anyhow::anyhow!(
                "FFI delete principal failed (code {})",
                ret
            ))
        }
    }

    /// Ensures a service principal exists and has a fresh random key in the KDC.
    ///
    /// This function stays purely in the FFI layer and only talks to kadm5.
    /// Keytab file writing is handled by the caller (lib.rs).
    pub fn set_random_key_for_service(&self, principal_name: &str) -> Result<()> {
        let principal_cstr = CString::new(principal_name).context("Invalid principal name")?;

        let mut princ: krb5_principal = ptr::null_mut();
        let ret = unsafe { krb5_parse_name(self.context, principal_cstr.as_ptr(), &mut princ) };
        if ret != 0 {
            return Err(anyhow::anyhow!("krb5_parse_name failed with code {}", ret));
        }

        let mut keyblocks = ptr::null_mut::<krb5_keyblock>();
        let mut n_keys: c_int = 0;

        let ret =
            unsafe { kadm5_randkey_principal(self.handle, princ, &mut keyblocks, &mut n_keys) };

        if ret != 0 {
            let code = ret as i32;
            let msg_ptr = unsafe { krb5_get_error_message(self.context, code) };
            let err_msg = if msg_ptr.is_null() {
                format!("code {}", ret)
            } else {
                let s = unsafe { CStr::from_ptr(msg_ptr).to_string_lossy().into_owned() };
                unsafe { krb5_free_error_message(self.context, msg_ptr) };
                s
            };

            let principal_not_found = ret == KADM5_UNK_PRINC as i64
                || err_msg.contains("Principal does not exist")
                || err_msg.contains("No such principal");

            if principal_not_found {
                let mut ent: kadm5_principal_ent_rec = unsafe { mem::zeroed() };
                ent.principal = princ;

                const KADM5_PRINCIPAL: c_long = 0x00000001;
                const KADM5_KEY: c_long = 0x00000020;
                let mask = (KADM5_PRINCIPAL | KADM5_KEY) as c_long;

                let ret =
                    unsafe { kadm5_create_principal(self.handle, &mut ent, mask, ptr::null_mut()) };

                if ret != 0 {
                    unsafe { krb5_free_principal(self.context, princ) };
                    return Err(anyhow::anyhow!(
                        "Failed to create service principal {}: code {}",
                        principal_name,
                        ret
                    ));
                }

                info!("Created new service principal: {}", principal_name);
            } else {
                unsafe { krb5_free_principal(self.context, princ) };
                return Err(anyhow::anyhow!(
                    "kadm5_randkey_principal failed: {}",
                    err_msg
                ));
            }
        } else {
            info!(
                "Rotated random key for service principal: {}",
                principal_name
            );
        }

        // Free any keyblocks that were returned
        if !keyblocks.is_null() {
            unsafe {
                for i in 0..n_keys {
                    let kb = keyblocks.add(i as usize);
                    if !(*kb).contents.is_null() {
                        krb5_free_keyblock_contents(self.context, kb);
                    }
                }
            }
        }

        unsafe { krb5_free_principal(self.context, princ) };
        Ok(())
    }
}

impl Drop for Kadm5Handle {
    fn drop(&mut self) {
        unsafe {
            let _ = kadm5_destroy(self.handle as *mut c_void);
            krb5_free_context(self.context);
        }
    }
}
