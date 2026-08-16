//! libkrb5/libkadm5 FFI; the only unsafe code in the crate.

#![allow(unsafe_code)]

use anyhow::{Context, Result};
use std::ffi::{CStr, CString};
use std::mem;
use std::os::raw::{c_char, c_int, c_long, c_void};
use std::ptr;
use tracing::{info, warn};

#[allow(non_camel_case_types)]
#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(dead_code)]
#[allow(clippy::undocumented_unsafe_blocks)]
mod bindings {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

use bindings::*;

// MIT kdb.h DISALLOW_ALL_TIX; bindgen does not emit it.
const KRB5_KDB_DISALLOW_ALL_TIX: krb5_flags = 0x0040;

pub(crate) struct Kadm5Handle {
    handle: *mut c_void,
    context: krb5_context,
}

fn krb5_error_string(context: krb5_context, ret: i64) -> String {
    // SAFETY: live context; copy the message then free it once.
    unsafe {
        let msg_ptr = krb5_get_error_message(context, ret as i32);
        if msg_ptr.is_null() {
            return format!("code {}", ret);
        }
        let message = CStr::from_ptr(msg_ptr).to_string_lossy().into_owned();
        krb5_free_error_message(context, msg_ptr);
        message
    }
}

impl Kadm5Handle {
    pub fn init_with_keytab(keytab_path: &str, admin_principal: &str, realm: &str) -> Result<Self> {
        let mut context: krb5_context = ptr::null_mut();
        // SAFETY: out-pointer; null on failure.
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

        // SAFETY: all-zero kadm5 struct is unset.
        let mut params: kadm5_config_params = unsafe { mem::zeroed() };
        params.mask = KADM5_CONFIG_REALM as c_long;
        params.realm = realm_cstr.into_raw();

        let struct_version: krb5_ui_4 = KADM5_STRUCT_VERSION;
        let api_version: krb5_ui_4 = KADM5_API_VERSION_4;

        let db_args_ptr: *mut *mut c_char = ptr::null_mut();

        // SAFETY: pointers live for the call; kadm5 copies; handle is written only on success.
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

        // SAFETY: `into_raw` pair; kadm5 does not retain the pointer.
        unsafe {
            let _ = CString::from_raw(params.realm);
        }

        if ret != 0 {
            let err_msg = krb5_error_string(context, ret as i64);
            warn!("kadm5_init_with_skey failed with code {}: {}", ret, err_msg);
            // SAFETY: no handle; free the context only.
            unsafe { krb5_free_context(context) };
            return Err(anyhow::anyhow!("kadm5_init_with_skey failed: {}", err_msg));
        }

        Ok(Kadm5Handle { handle, context })
    }

    fn parse_principal(&self, principal_name: &str) -> Result<krb5_principal> {
        let principal_cstr = CString::new(principal_name).context("Invalid principal name")?;
        let mut princ: krb5_principal = ptr::null_mut();
        // SAFETY: live context; caller frees the principal.
        let ret = unsafe { krb5_parse_name(self.context, principal_cstr.as_ptr(), &mut princ) };
        if ret != 0 {
            return Err(anyhow::anyhow!("krb5_parse_name failed with code {}", ret));
        }
        Ok(princ)
    }

    fn free_principal(&self, princ: krb5_principal) {
        // SAFETY: parsed on this context; freed once.
        unsafe { krb5_free_principal(self.context, princ) };
    }

    pub fn create_principal(&self, username: &str, password: &str, realm: &str) -> Result<()> {
        let princ = self.parse_principal(&format!("{}@{}", username, realm))?;

        // SAFETY: all-zero kadm5 struct is unset.
        let mut ent: kadm5_principal_ent_rec = unsafe { mem::zeroed() };
        ent.principal = princ;

        let mask = KADM5_PRINCIPAL as c_long;
        let pass_cstr = CString::new(password)?;

        // SAFETY: handle, ent, and password live for the call; kadm5 copies.
        let ret = unsafe {
            kadm5_create_principal(
                self.handle,
                &mut ent,
                mask,
                pass_cstr.as_ptr() as *mut c_char,
            )
        };

        self.free_principal(princ);

        if ret != 0 {
            let err_msg = krb5_error_string(self.context, ret as i64);
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
        let princ = self.parse_principal(&format!("{}@{}", username, realm))?;
        let pass_cstr = CString::new(password)?;

        // SAFETY: handle and princ live; password outlives the call.
        let ret = unsafe {
            kadm5_chpass_principal(self.handle, princ, pass_cstr.as_ptr() as *mut c_char)
        };

        self.free_principal(princ);

        if ret != 0 {
            let err_msg = krb5_error_string(self.context, ret as i64);
            return Err(anyhow::anyhow!(
                "kadm5_chpass_principal failed: {}",
                err_msg
            ));
        }

        Ok(())
    }

    pub fn delete_principal(&self, principal_str: &str) -> Result<()> {
        let principal = self.parse_principal(principal_str)?;

        // SAFETY: handle and principal live; kadm5 only reads the principal.
        let ret = unsafe { kadm5_delete_principal(self.handle, principal) };

        self.free_principal(principal);

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

    pub fn set_random_key_for_service(&self, principal_name: &str) -> Result<()> {
        let princ = self.parse_principal(principal_name)?;

        let mut keyblocks = ptr::null_mut::<krb5_keyblock>();
        let mut n_keys: c_int = 0;

        // SAFETY: handle and princ live; keyblocks are released below on success.
        let ret =
            unsafe { kadm5_randkey_principal(self.handle, princ, &mut keyblocks, &mut n_keys) };

        if ret != 0 {
            let err_msg = krb5_error_string(self.context, ret as i64);

            let principal_not_found = ret == KADM5_UNK_PRINC as i64
                || err_msg.contains("Principal does not exist")
                || err_msg.contains("No such principal");

            if principal_not_found {
                // SAFETY: all-zero kadm5 struct is unset.
                let mut ent: kadm5_principal_ent_rec = unsafe { mem::zeroed() };
                ent.principal = princ;

                let mask = (KADM5_PRINCIPAL | KADM5_MAX_LIFE) as c_long;

                // SAFETY: handle and ent live; null password means kadm5 picks a random key.
                let ret =
                    unsafe { kadm5_create_principal(self.handle, &mut ent, mask, ptr::null_mut()) };

                if ret != 0 {
                    self.free_principal(princ);
                    return Err(anyhow::anyhow!(
                        "Failed to create service principal {}: code {}",
                        principal_name,
                        ret
                    ));
                }

                info!("Created new service principal: {}", principal_name);
            } else {
                self.free_principal(princ);
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

        if !keyblocks.is_null() {
            // SAFETY: free each keyblock's contents; the kadm5 array is left, as MIT tools do.
            unsafe {
                for i in 0..n_keys {
                    let kb = keyblocks.add(i as usize);
                    if !(*kb).contents.is_null() {
                        krb5_free_keyblock_contents(self.context, kb);
                    }
                }
            }
        }

        self.free_principal(princ);
        Ok(())
    }

    pub fn set_principal_allow_tickets(
        &self,
        username: &str,
        realm: &str,
        allow: bool,
    ) -> Result<()> {
        let principal_name = format!("{}@{}", username, realm);
        let princ = self.parse_principal(&principal_name)?;

        // SAFETY: all-zero kadm5 struct is unset.
        let mut ent: kadm5_principal_ent_rec = unsafe { mem::zeroed() };
        // SAFETY: handle, princ, and ent live for the call.
        let ret = unsafe {
            kadm5_get_principal(
                self.handle,
                princ,
                &mut ent,
                KADM5_PRINCIPAL_NORMAL_MASK as c_long,
            )
        };
        if ret == KADM5_UNK_PRINC as i64 {
            self.free_principal(princ);
            info!(
                "Principal {} does not exist, skipping allow_tix update",
                principal_name
            );
            return Ok(());
        }
        if ret != 0 {
            let err_msg = krb5_error_string(self.context, ret as i64);
            self.free_principal(princ);
            return Err(anyhow::anyhow!("kadm5_get_principal failed: {}", err_msg));
        }

        if allow {
            ent.attributes &= !KRB5_KDB_DISALLOW_ALL_TIX;
        } else {
            ent.attributes |= KRB5_KDB_DISALLOW_ALL_TIX;
        }

        // SAFETY: `ent` came from get_principal on this handle; mask is attributes only.
        let ret =
            unsafe { kadm5_modify_principal(self.handle, &mut ent, KADM5_ATTRIBUTES as c_long) };

        // SAFETY: frees kadm5's copy in `ent`; lookup `princ` is separate.
        unsafe { kadm5_free_principal_ent(self.handle, &mut ent) };
        self.free_principal(princ);

        if ret != 0 {
            let err_msg = krb5_error_string(self.context, ret as i64);
            warn!(
                "kadm5_modify_principal (allow_tix) failed with code {}: {}",
                ret, err_msg
            );
            return Err(anyhow::anyhow!(
                "kadm5_modify_principal failed: {}",
                err_msg
            ));
        }

        info!("Set allow_tix={} for principal {}", allow, principal_name);
        Ok(())
    }
}

impl Drop for Kadm5Handle {
    fn drop(&mut self) {
        // SAFETY: created in init_with_keytab; handle then the context it depends on.
        unsafe {
            let _ = kadm5_destroy(self.handle);
            krb5_free_context(self.context);
        }
    }
}
