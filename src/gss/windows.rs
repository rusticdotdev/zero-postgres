use std::ffi::c_void;
use std::ptr;

use windows_sys::Win32::Foundation::{SEC_E_OK, SEC_I_CONTINUE_NEEDED};
use windows_sys::Win32::Security::Authentication::Identity::{
    AcquireCredentialsHandleW, DeleteSecurityContext, FreeContextBuffer, FreeCredentialsHandle,
    ISC_REQ_ALLOCATE_MEMORY, InitializeSecurityContextW, SECBUFFER_TOKEN, SECBUFFER_VERSION,
    SECPKG_CRED_OUTBOUND, SECURITY_NETWORK_DREP, SecBuffer, SecBufferDesc,
};
use windows_sys::Win32::Security::Credentials::SecHandle;

use crate::error::{Error, Result};

const KERBEROS_PACKAGE: &str = "kerberos";
const NEGOTIATE_PACKAGE: &str = "negotiate";

pub(crate) struct GssClient {
    package: &'static str,
    credentials: Option<SecHandle>,
    context: Option<SecHandle>,
    target: Vec<u16>,
    complete: bool,
}

impl GssClient {
    pub(crate) fn for_gss_request(host: &str) -> Result<Self> {
        Self::new(host, KERBEROS_PACKAGE)
    }

    pub(crate) fn for_sspi_request(host: &str) -> Result<Self> {
        Self::new(host, NEGOTIATE_PACKAGE)
    }

    fn new(host: &str, package: &'static str) -> Result<Self> {
        Ok(Self {
            package,
            credentials: None,
            context: None,
            target: null_terminated_utf16(&format!("{}/{host}", super::SERVICE_NAME)),
            complete: false,
        })
    }

    fn acquire_credentials(&mut self) -> Result<SecHandle> {
        if let Some(credentials) = self.credentials {
            return Ok(credentials);
        }

        let package_name = null_terminated_utf16(self.package);
        let mut credentials = SecHandle {
            dwLower: 0,
            dwUpper: 0,
        };
        let mut expiry = 0i64;

        let status = unsafe {
            AcquireCredentialsHandleW(
                ptr::null(),
                package_name.as_ptr(),
                SECPKG_CRED_OUTBOUND,
                ptr::null(),
                ptr::null(),
                None,
                ptr::null(),
                &mut credentials,
                &mut expiry,
            )
        };
        if status != SEC_E_OK {
            return Err(Error::Auth(format!(
                "could not acquire SSPI credentials: {status:#010x}"
            )));
        }

        self.credentials = Some(credentials);
        Ok(credentials)
    }

    pub(crate) fn step(&mut self, server_token: Option<&[u8]>) -> Result<Option<Vec<u8>>> {
        let credentials = self.acquire_credentials()?;
        let mut input_buffer = match server_token {
            Some(token) => Some(SecBuffer {
                cbBuffer: u32::try_from(token.len())
                    .map_err(|e| Error::Auth(format!("SSPI token too large: {e}")))?,
                BufferType: SECBUFFER_TOKEN,
                pvBuffer: token.as_ptr().cast_mut().cast::<c_void>(),
            }),
            None => None,
        };
        let input = input_buffer.as_mut().map(|buffer| SecBufferDesc {
            ulVersion: SECBUFFER_VERSION,
            cBuffers: 1,
            pBuffers: buffer,
        });

        let mut output_buffer = SecBuffer {
            cbBuffer: 0,
            BufferType: SECBUFFER_TOKEN,
            pvBuffer: ptr::null_mut(),
        };
        let mut output = SecBufferDesc {
            ulVersion: SECBUFFER_VERSION,
            cBuffers: 1,
            pBuffers: &mut output_buffer,
        };

        let mut new_context = SecHandle {
            dwLower: 0,
            dwUpper: 0,
        };
        let mut context_attributes = 0u32;
        let mut expiry = 0i64;

        let status = unsafe {
            InitializeSecurityContextW(
                &credentials,
                self.context.as_ref().map_or(ptr::null(), ptr::from_ref),
                self.target.as_ptr(),
                ISC_REQ_ALLOCATE_MEMORY,
                0,
                SECURITY_NETWORK_DREP,
                input.as_ref().map_or(ptr::null(), ptr::from_ref),
                0,
                &mut new_context,
                &mut output,
                &mut context_attributes,
                &mut expiry,
            )
        };
        if status != SEC_E_OK && status != SEC_I_CONTINUE_NEEDED {
            return Err(Error::Auth(format!(
                "SSPI continuation error: {status:#010x}"
            )));
        }
        self.context = Some(new_context);
        self.complete = status == SEC_E_OK;

        if output_buffer.pvBuffer.is_null() {
            return Ok(None);
        }
        let token = unsafe {
            std::slice::from_raw_parts(
                output_buffer.pvBuffer.cast::<u8>(),
                output_buffer.cbBuffer as usize,
            )
        }
        .to_vec();
        unsafe {
            FreeContextBuffer(output_buffer.pvBuffer);
        }

        Ok((!token.is_empty()).then_some(token))
    }

    pub(crate) fn is_complete(&self) -> bool {
        self.complete
    }
}

impl Drop for GssClient {
    fn drop(&mut self) {
        if let Some(context) = &self.context {
            unsafe {
                DeleteSecurityContext(context);
            }
        }
        if let Some(credentials) = &self.credentials {
            unsafe {
                FreeCredentialsHandle(credentials);
            }
        }
    }
}

fn null_terminated_utf16(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}
