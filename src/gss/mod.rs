#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

#[cfg(unix)]
pub(crate) use unix::GssClient;
#[cfg(windows)]
pub(crate) use windows::GssClient;

#[cfg(not(any(unix, windows)))]
compile_error!("feature `auth-gss` is supported only on unix and windows targets");

const SERVICE_NAME: &str = "postgres";

pub(crate) struct GssStep {
    pub(crate) client: GssClient,
    pub(crate) server_token: Option<Vec<u8>>,
    pub(crate) response: Option<Vec<u8>>,
}

impl GssStep {
    pub(crate) fn new(client: GssClient, server_token: Option<Vec<u8>>) -> Self {
        Self {
            client,
            server_token,
            response: None,
        }
    }

    pub(crate) fn run(mut self) -> crate::error::Result<Self> {
        self.response = self.client.step(self.server_token.as_deref())?;
        Ok(self)
    }
}
