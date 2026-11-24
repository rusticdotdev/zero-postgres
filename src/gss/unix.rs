use libgssapi::context::{ClientCtx, CtxFlags, SecurityContext};
use libgssapi::name::Name;
use libgssapi::oid::GSS_NT_HOSTBASED_SERVICE;

use crate::error::{Error, Result};

pub(crate) struct GssClient {
    context: ClientCtx,
}

impl GssClient {
    pub(crate) fn for_gss_request(host: &str) -> Result<Self> {
        let target = Name::new(
            format!("{}@{host}", super::SERVICE_NAME).as_bytes(),
            Some(GSS_NT_HOSTBASED_SERVICE),
        )
        .map_err(|e| Error::Auth(format!("GSSAPI name import error: {e}")))?;

        Ok(Self {
            context: ClientCtx::new(None, target, CtxFlags::GSS_C_MUTUAL_FLAG, None),
        })
    }

    pub(crate) fn for_sspi_request(host: &str) -> Result<Self> {
        Self::for_gss_request(host)
    }

    pub(crate) fn step(&mut self, server_token: Option<&[u8]>) -> Result<Option<Vec<u8>>> {
        let token = self
            .context
            .step(server_token, None)
            .map_err(|e| Error::Auth(format!("GSSAPI continuation error: {e}")))?;
        Ok(token.map(|token| token.to_vec()))
    }

    pub(crate) fn is_complete(&self) -> bool {
        self.context.is_complete()
    }
}
