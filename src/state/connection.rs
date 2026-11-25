//! Connection startup and authentication state machine.

use std::borrow::Cow;

use crate::error::{Error, Result};
#[cfg(feature = "auth-gss")]
use crate::gss::{GssClient, GssStep};
use crate::opts::Opts;
use crate::protocol::backend::{
    AuthenticationMessage, BackendKeyData, ErrorResponse, NegotiateProtocolVersion,
    ParameterStatus, RawMessage, ReadyForQuery, msg_type,
};
use crate::protocol::frontend::auth::{ScramClient, md5_password};
#[cfg(feature = "auth-gss")]
use crate::protocol::frontend::write_gss_response;
use crate::protocol::frontend::{
    startup::{PROTOCOL_VERSION_3_0, PROTOCOL_VERSION_3_2, write_ssl_request},
    write_password, write_sasl_initial_response, write_sasl_response, write_startup,
};
use crate::protocol::types::TransactionStatus;

use super::StateMachine;
use super::action::{Action, AsyncMessage};
use crate::buffer_set::BufferSet;

/// Connection state during startup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Initial,
    WaitingSslResponse,
    WaitingTlsHandshake,
    WaitingAuth,
    SaslInProgress,
    OauthInProgress,
    OauthFailed,
    #[cfg(feature = "auth-gss")]
    GssStepPending,
    #[cfg(feature = "auth-gss")]
    GssStepFinished,
    #[cfg(feature = "auth-gss")]
    GssInProgress,
    WaitingAuthResult,
    WaitingReady,
    Finished,
}

/// Connection startup state machine.
pub struct ConnectionStateMachine<'a> {
    state: State,
    options: &'a Opts,
    backend_key: Option<BackendKeyData>,
    server_params: Vec<(String, String)>,
    transaction_status: TransactionStatus,
    scram_client: Option<ScramClient>,
    #[cfg(feature = "auth-gss")]
    gss_client: Option<GssClient>,
    #[cfg(feature = "auth-gss")]
    gss_step: Option<GssStep>,
    /// SSL response byte, set by driver after ReadByte
    ssl_response: u8,
    /// Whether the driver can perform a TLS handshake
    tls_supported: bool,
    server_certificate_der: Option<Vec<u8>>,
}

impl<'a> ConnectionStateMachine<'a> {
    /// Create a new connection state machine.
    ///
    /// `tls_supported` tells whether the driver can handle [`Action::TlsHandshake`].
    pub fn new(options: &'a Opts, tls_supported: bool) -> Self {
        Self {
            state: State::Initial,
            options,
            backend_key: None,
            server_params: Vec::new(),
            transaction_status: TransactionStatus::Idle,
            scram_client: None,
            #[cfg(feature = "auth-gss")]
            gss_client: None,
            #[cfg(feature = "auth-gss")]
            gss_step: None,
            ssl_response: 0,
            tls_supported,
            server_certificate_der: None,
        }
    }

    pub fn set_server_certificate_der(&mut self, server_certificate_der: Vec<u8>) {
        self.server_certificate_der = Some(server_certificate_der);
    }

    fn tls_server_end_point(&self) -> Option<Vec<u8>> {
        #[cfg(any(feature = "sync-tls", feature = "tokio-tls", feature = "compio-tls"))]
        {
            let server_certificate_der = self.server_certificate_der.as_deref()?;
            crate::tls::tls_server_end_point(&rustls::pki_types::CertificateDer::from(
                server_certificate_der,
            ))
        }
        #[cfg(not(any(feature = "sync-tls", feature = "tokio-tls", feature = "compio-tls")))]
        {
            None
        }
    }

    /// Get the backend key data (for cancellation).
    pub fn backend_key(&self) -> Option<&BackendKeyData> {
        self.backend_key.as_ref()
    }

    /// Take server parameters.
    pub fn take_server_params(&mut self) -> Vec<(String, String)> {
        std::mem::take(&mut self.server_params)
    }

    /// Set the SSL response byte (called by driver after ReadByte).
    pub fn set_ssl_response(&mut self, response: u8) {
        self.ssl_response = response;
    }

    fn handle_initial(&mut self, buffer_set: &mut BufferSet) -> Result<Action> {
        buffer_set.write_buffer.clear();

        if self.options.tls_mode.requires_tls() && !self.tls_supported {
            return Err(Error::Unsupported(
                "TLS requested but TLS feature not enabled".into(),
            ));
        }
        let send_ssl_request = self.tls_supported;

        if send_ssl_request {
            write_ssl_request(&mut buffer_set.write_buffer);
            self.state = State::WaitingSslResponse;
            Ok(Action::WriteAndReadByte)
        } else {
            self.write_startup_message(&mut buffer_set.write_buffer);
            self.state = State::WaitingAuth;
            Ok(Action::WriteAndReadMessage)
        }
    }

    fn handle_ssl_response(&mut self, buffer_set: &mut BufferSet) -> Result<Action> {
        match self.ssl_response {
            b'S' => {
                self.state = State::WaitingTlsHandshake;
                Ok(Action::TlsHandshake)
            }
            b'N' => {
                if self.options.tls_mode.requires_tls() {
                    return Err(Error::Auth(
                        "TLS requested but not supported by server".into(),
                    ));
                }
                // SSL not supported, continue with plain connection
                buffer_set.write_buffer.clear();
                self.write_startup_message(&mut buffer_set.write_buffer);
                self.state = State::WaitingAuth;
                Ok(Action::WriteAndReadMessage)
            }
            _ => Err(Error::LibraryBug(format!(
                "Unexpected SSL response: {}",
                self.ssl_response
            ))),
        }
    }

    fn handle_tls_handshake_complete(&mut self, buffer_set: &mut BufferSet) -> Result<Action> {
        buffer_set.write_buffer.clear();
        self.write_startup_message(&mut buffer_set.write_buffer);
        self.state = State::WaitingAuth;
        Ok(Action::WriteAndReadMessage)
    }

    fn write_startup_message(&self, write_buffer: &mut Vec<u8>) {
        let mut params: Vec<(&str, &str)> =
            vec![("user", &self.options.user), ("client_encoding", "UTF8")];

        if let Some(db) = &self.options.database {
            params.push(("database", db));
        }

        if let Some(app) = &self.options.application_name {
            params.push(("application_name", app));
        }

        for (name, value) in &self.options.params {
            params.push((name, value));
        }

        write_startup(write_buffer, &params);
    }

    fn required_password(&self) -> Result<Cow<'_, str>> {
        self.options
            .get_password()?
            .ok_or_else(|| Error::Auth("Password required but not provided".into()))
    }

    fn start_scram(
        &mut self,
        mechanism: &str,
        scram: ScramClient,
        buffer_set: &mut BufferSet,
    ) -> Action {
        buffer_set.write_buffer.clear();
        write_sasl_initial_response(
            &mut buffer_set.write_buffer,
            mechanism,
            scram.client_first_message().as_bytes(),
        );

        self.scram_client = Some(scram);
        self.state = State::SaslInProgress;
        Action::WriteAndReadMessage
    }

    fn handle_auth_message(&mut self, buffer_set: &mut BufferSet) -> Result<Action> {
        let type_byte = buffer_set.type_byte;

        if type_byte == msg_type::NEGOTIATE_PROTOCOL_VERSION {
            let sent_option_count = self
                .options
                .params
                .iter()
                .filter(|(name, _)| name.starts_with("_pq_."))
                .count();
            let negotiate =
                NegotiateProtocolVersion::parse(&buffer_set.read_buffer, sent_option_count)?;
            if !matches!(
                negotiate.newest_version,
                PROTOCOL_VERSION_3_0 | PROTOCOL_VERSION_3_2
            ) {
                return Err(Error::Unsupported(format!(
                    "Server offered protocol version {}.{}; only 3.0 and 3.2 are supported",
                    negotiate.newest_version >> 16,
                    negotiate.newest_version & 0xFFFF
                )));
            }
            if !negotiate.unrecognized_options.is_empty() {
                return Err(Error::Unsupported(format!(
                    "Server rejected protocol options: {:?}",
                    negotiate.unrecognized_options
                )));
            }
            self.state = State::WaitingAuth;
            return Ok(Action::ReadMessage);
        }

        if type_byte != msg_type::AUTHENTICATION {
            return Err(Error::LibraryBug(format!(
                "Expected Authentication message, got '{}'",
                type_byte as char
            )));
        }

        let auth = AuthenticationMessage::parse(&buffer_set.read_buffer)?;

        if self.options.tls_mode.requires_channel_binding()
            && !matches!(auth, AuthenticationMessage::Sasl { .. })
        {
            return Err(Error::Auth(format!(
                "Channel binding is required but the server requested {:?}",
                auth
            )));
        }

        match auth {
            AuthenticationMessage::Ok => {
                self.state = State::WaitingReady;
                Ok(Action::ReadMessage)
            }
            AuthenticationMessage::CleartextPassword => {
                let password = self.required_password()?;

                buffer_set.write_buffer.clear();
                write_password(&mut buffer_set.write_buffer, &password);
                self.state = State::WaitingAuthResult;
                Ok(Action::WriteAndReadMessage)
            }
            AuthenticationMessage::Md5Password { salt } => {
                let password = self.required_password()?;

                let hashed = md5_password(&self.options.user, &password, &salt);
                buffer_set.write_buffer.clear();
                write_password(&mut buffer_set.write_buffer, &hashed);
                self.state = State::WaitingAuthResult;
                Ok(Action::WriteAndReadMessage)
            }
            AuthenticationMessage::Sasl { mechanisms } => {
                let tls_server_end_point = self.tls_server_end_point();

                if let Some(channel_binding_data) = &tls_server_end_point
                    && mechanisms.contains(&"SCRAM-SHA-256-PLUS")
                {
                    let password = self.required_password()?;
                    let scram =
                        ScramClient::new_with_channel_binding(&password, channel_binding_data);
                    return Ok(self.start_scram("SCRAM-SHA-256-PLUS", scram, buffer_set));
                }

                if self.options.tls_mode.requires_channel_binding() {
                    return Err(Error::Auth(if mechanisms.contains(&"SCRAM-SHA-256-PLUS") {
                        "Channel binding is required but tls-server-end-point is undefined for the server certificate".into()
                    } else {
                        format!(
                            "Channel binding is required but the server does not offer SCRAM-SHA-256-PLUS. Server offers: {:?}",
                            mechanisms
                        )
                    }));
                }

                if mechanisms.contains(&"SCRAM-SHA-256") {
                    let password = self.required_password()?;
                    let scram = if tls_server_end_point.is_some() {
                        ScramClient::new_with_unadvertised_channel_binding(&password)
                    } else {
                        ScramClient::new(&password)
                    };
                    return Ok(self.start_scram("SCRAM-SHA-256", scram, buffer_set));
                }

                if mechanisms.contains(&"OAUTHBEARER") {
                    let initial_response = match &self.options.oauth_bearer_token_fn {
                        Some(oauth_bearer_token_fn) => {
                            format!("n,,\x01auth=Bearer {}\x01\x01", oauth_bearer_token_fn()?)
                        }
                        None if self.options.oauth_discovery_fn.is_some() => {
                            "n,,\x01auth=\x01\x01".to_string()
                        }
                        None => {
                            return Err(Error::Auth(
                                "OAuth bearer token required but not provided".into(),
                            ));
                        }
                    };

                    buffer_set.write_buffer.clear();
                    write_sasl_initial_response(
                        &mut buffer_set.write_buffer,
                        "OAUTHBEARER",
                        initial_response.as_bytes(),
                    );
                    self.state = State::OauthInProgress;
                    return Ok(Action::WriteAndReadMessage);
                }

                Err(Error::Auth(format!(
                    "No supported SASL mechanism. Server offers: {:?}",
                    mechanisms
                )))
            }
            #[cfg(feature = "auth-gss")]
            AuthenticationMessage::Gss => {
                let gss = GssClient::for_gss_request(self.gss_target_host()?)?;
                Ok(self.request_gss_step(gss, None))
            }
            #[cfg(feature = "auth-gss")]
            AuthenticationMessage::Sspi => {
                let gss = GssClient::for_sspi_request(self.gss_target_host()?)?;
                Ok(self.request_gss_step(gss, None))
            }
            _ => Err(Error::Unsupported(format!(
                "Unsupported authentication method: {:?}",
                auth
            ))),
        }
    }

    #[cfg(feature = "auth-gss")]
    fn gss_target_host(&self) -> Result<&str> {
        if self.options.host.is_empty() {
            return Err(Error::Auth(
                "Host name required for GSS authentication".into(),
            ));
        }
        Ok(&self.options.host)
    }

    #[cfg(feature = "auth-gss")]
    fn request_gss_step(&mut self, gss: GssClient, server_token: Option<Vec<u8>>) -> Action {
        self.gss_step = Some(GssStep::new(gss, server_token));
        self.state = State::GssStepPending;
        Action::GssStep
    }

    #[cfg(feature = "auth-gss")]
    pub(crate) fn take_gss_step(&mut self) -> Result<GssStep> {
        if self.state != State::GssStepPending {
            return Err(Error::LibraryBug("No GSS step is pending".into()));
        }
        self.gss_step
            .take()
            .ok_or_else(|| Error::LibraryBug("GSS step already taken".into()))
    }

    #[cfg(feature = "auth-gss")]
    pub(crate) fn finish_gss_step(&mut self, gss_step: GssStep) {
        self.gss_step = Some(gss_step);
        self.state = State::GssStepFinished;
    }

    #[cfg(feature = "auth-gss")]
    fn handle_gss_step_finished(&mut self, buffer_set: &mut BufferSet) -> Result<Action> {
        let GssStep {
            client, response, ..
        } = self
            .gss_step
            .take()
            .ok_or_else(|| Error::LibraryBug("GSS step not finished".into()))?;
        let complete = client.is_complete();
        self.gss_client = Some(client);

        match response {
            Some(token) => {
                buffer_set.write_buffer.clear();
                write_gss_response(&mut buffer_set.write_buffer, &token);
                self.state = State::GssInProgress;
                Ok(Action::WriteAndReadMessage)
            }
            None if complete => {
                self.state = State::GssInProgress;
                Ok(Action::ReadMessage)
            }
            None => Err(Error::Auth(
                "GSS context is incomplete but produced no token".into(),
            )),
        }
    }

    #[cfg(feature = "auth-gss")]
    fn handle_gss_message(&mut self, buffer_set: &mut BufferSet) -> Result<Action> {
        let type_byte = buffer_set.type_byte;
        if type_byte != msg_type::AUTHENTICATION {
            return Err(Error::LibraryBug(format!(
                "Expected Authentication message, got '{}'",
                type_byte as char
            )));
        }

        let auth = AuthenticationMessage::parse(&buffer_set.read_buffer)?;

        match auth {
            AuthenticationMessage::Ok => {
                let complete = self.gss_client.as_ref().is_some_and(GssClient::is_complete);
                if !complete {
                    return Err(Error::Auth(
                        "Server accepted authentication before the GSS context was established"
                            .into(),
                    ));
                }
                self.state = State::WaitingReady;
                Ok(Action::ReadMessage)
            }
            AuthenticationMessage::GssContinue { data } => {
                let gss = self
                    .gss_client
                    .take()
                    .ok_or_else(|| Error::LibraryBug("GSS client not initialized".into()))?;
                Ok(self.request_gss_step(gss, Some(data.to_vec())))
            }
            _ => Err(Error::Auth(format!("Unexpected GSS message: {:?}", auth))),
        }
    }

    fn handle_oauth_message(&mut self, buffer_set: &mut BufferSet) -> Result<Action> {
        let type_byte = buffer_set.type_byte;
        if type_byte != msg_type::AUTHENTICATION {
            return Err(Error::LibraryBug(format!(
                "Expected Authentication message, got '{}'",
                type_byte as char
            )));
        }

        let auth = AuthenticationMessage::parse(&buffer_set.read_buffer)?;

        match auth {
            AuthenticationMessage::Ok => {
                self.state = State::WaitingReady;
                Ok(Action::ReadMessage)
            }
            AuthenticationMessage::SaslContinue { data } => {
                let error_json = simdutf8::compat::from_utf8(data)
                    .map_err(|e| Error::Auth(format!("Invalid OAUTHBEARER error: {}", e)))?;

                if let Some(oauth_discovery_fn) = &self.options.oauth_discovery_fn {
                    oauth_discovery_fn(error_json);
                }

                buffer_set.write_buffer.clear();
                write_sasl_response(&mut buffer_set.write_buffer, b"\x01");
                self.state = State::OauthFailed;
                Ok(Action::WriteAndReadMessage)
            }
            _ => Err(Error::Auth(format!(
                "Unexpected OAUTHBEARER message: {:?}",
                auth
            ))),
        }
    }

    fn handle_sasl_message(&mut self, buffer_set: &mut BufferSet) -> Result<Action> {
        let type_byte = buffer_set.type_byte;
        if type_byte != msg_type::AUTHENTICATION {
            return Err(Error::LibraryBug(format!(
                "Expected Authentication message, got '{}'",
                type_byte as char
            )));
        }

        let auth = AuthenticationMessage::parse(&buffer_set.read_buffer)?;

        match auth {
            AuthenticationMessage::SaslContinue { data } => {
                let scram = self
                    .scram_client
                    .as_mut()
                    .ok_or_else(|| Error::LibraryBug("SCRAM client not initialized".into()))?;

                let server_first = simdutf8::compat::from_utf8(data)
                    .map_err(|e| Error::Auth(format!("Invalid server-first-message: {}", e)))?;

                let client_final = scram
                    .process_server_first(server_first)
                    .map_err(Error::Auth)?;

                buffer_set.write_buffer.clear();
                write_sasl_response(&mut buffer_set.write_buffer, client_final.as_bytes());
                self.state = State::SaslInProgress;
                Ok(Action::WriteAndReadMessage)
            }
            AuthenticationMessage::SaslFinal { data } => {
                let scram = self
                    .scram_client
                    .as_ref()
                    .ok_or_else(|| Error::LibraryBug("SCRAM client not initialized".into()))?;

                let server_final = simdutf8::compat::from_utf8(data)
                    .map_err(|e| Error::Auth(format!("Invalid server-final-message: {}", e)))?;

                scram
                    .verify_server_final(server_final)
                    .map_err(Error::Auth)?;

                self.state = State::WaitingAuthResult;
                Ok(Action::ReadMessage)
            }
            _ => Err(Error::LibraryBug(format!(
                "Unexpected SASL message: {:?}",
                auth
            ))),
        }
    }

    fn handle_auth_result(&mut self, buffer_set: &BufferSet) -> Result<Action> {
        let type_byte = buffer_set.type_byte;
        if type_byte != msg_type::AUTHENTICATION {
            return Err(Error::LibraryBug(format!(
                "Expected AuthenticationOk, got '{}'",
                type_byte as char
            )));
        }

        let auth = AuthenticationMessage::parse(&buffer_set.read_buffer)?;

        match auth {
            AuthenticationMessage::Ok => {
                self.state = State::WaitingReady;
                Ok(Action::ReadMessage)
            }
            _ => Err(Error::Auth(format!("Unexpected auth result: {:?}", auth))),
        }
    }

    fn handle_ready_message(&mut self, buffer_set: &BufferSet) -> Result<Action> {
        let type_byte = buffer_set.type_byte;
        let payload = &buffer_set.read_buffer;

        match type_byte {
            msg_type::BACKEND_KEY_DATA => {
                let key = BackendKeyData::parse(payload)?;
                self.backend_key = Some(key);
                Ok(Action::ReadMessage)
            }
            msg_type::PARAMETER_STATUS => {
                let param = ParameterStatus::parse(payload)?;
                self.server_params
                    .push((param.name.to_string(), param.value.to_string()));
                Ok(Action::ReadMessage)
            }
            msg_type::READY_FOR_QUERY => {
                let ready = ReadyForQuery::parse(payload)?;
                self.transaction_status = ready.transaction_status()?;
                self.state = State::Finished;
                Ok(Action::Finished)
            }
            _ => Err(Error::LibraryBug(format!(
                "Unexpected message during startup: '{}'",
                type_byte as char
            ))),
        }
    }

    fn handle_async_message(&self, msg: &RawMessage<'_>) -> Result<Action> {
        match msg.type_byte {
            msg_type::NOTICE_RESPONSE => {
                let notice = crate::protocol::backend::NoticeResponse::parse(msg.payload)?;
                Ok(Action::HandleAsyncMessageAndReadMessage(
                    AsyncMessage::Notice(notice.0),
                ))
            }
            msg_type::PARAMETER_STATUS => {
                let param = ParameterStatus::parse(msg.payload)?;
                Ok(Action::HandleAsyncMessageAndReadMessage(
                    AsyncMessage::ParameterChanged {
                        name: param.name.to_string(),
                        value: param.value.to_string(),
                    },
                ))
            }
            msg_type::NOTIFICATION_RESPONSE => {
                let notification =
                    crate::protocol::backend::auth::NotificationResponse::parse(msg.payload)?;
                Ok(Action::HandleAsyncMessageAndReadMessage(
                    AsyncMessage::Notification {
                        pid: notification.pid,
                        channel: notification.channel.to_string(),
                        payload: notification.payload.to_string(),
                    },
                ))
            }
            _ => Err(Error::LibraryBug(format!(
                "Unknown async message type: '{}'",
                msg.type_byte as char
            ))),
        }
    }
}

impl StateMachine for ConnectionStateMachine<'_> {
    fn step(&mut self, buffer_set: &mut BufferSet) -> Result<Action> {
        // Handle states that don't need to read buffer_set
        match self.state {
            State::Initial => return self.handle_initial(buffer_set),
            State::WaitingSslResponse => return self.handle_ssl_response(buffer_set),
            State::WaitingTlsHandshake => return self.handle_tls_handshake_complete(buffer_set),
            #[cfg(feature = "auth-gss")]
            State::GssStepPending => {
                return Err(Error::LibraryBug(
                    "step() called before the GSS step finished".into(),
                ));
            }
            #[cfg(feature = "auth-gss")]
            State::GssStepFinished => return self.handle_gss_step_finished(buffer_set),
            _ => {}
        }

        let type_byte = buffer_set.type_byte;

        // Handle async messages that can arrive at any time
        // Note: PARAMETER_STATUS during WaitingReady is part of normal startup, not async
        if RawMessage::is_async_type(type_byte)
            && !(self.state == State::WaitingReady && type_byte == msg_type::PARAMETER_STATUS)
        {
            let msg = RawMessage::new(type_byte, &buffer_set.read_buffer);
            return self.handle_async_message(&msg);
        }

        // Handle error response
        if type_byte == msg_type::ERROR_RESPONSE {
            let error = ErrorResponse::parse(&buffer_set.read_buffer)?;
            return Err(error.into_error());
        }

        match self.state {
            State::WaitingAuth => self.handle_auth_message(buffer_set),
            State::SaslInProgress => self.handle_sasl_message(buffer_set),
            State::OauthInProgress => self.handle_oauth_message(buffer_set),
            State::OauthFailed => Err(Error::Auth(format!(
                "Expected ErrorResponse after OAUTHBEARER failure, got '{}'",
                type_byte as char
            ))),
            #[cfg(feature = "auth-gss")]
            State::GssInProgress => self.handle_gss_message(buffer_set),
            State::WaitingAuthResult => self.handle_auth_result(buffer_set),
            State::WaitingReady => self.handle_ready_message(buffer_set),
            _ => Err(Error::LibraryBug(format!(
                "Unexpected state {:?}",
                self.state
            ))),
        }
    }

    fn transaction_status(&self) -> TransactionStatus {
        self.transaction_status
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::opts::TlsMode;
    use std::sync::Arc;

    fn negotiate_message(newest_version: i32, options: &[&str]) -> Vec<u8> {
        let mut payload = newest_version.to_be_bytes().to_vec();
        payload.extend_from_slice(&(options.len() as i32).to_be_bytes());
        for option in options {
            payload.extend_from_slice(option.as_bytes());
            payload.push(0);
        }
        payload
    }

    fn opts_with_params(params: &[(&str, &str)]) -> Opts {
        Opts {
            params: params
                .iter()
                .map(|(name, value)| (name.to_string(), value.to_string()))
                .collect(),
            ..Opts::default()
        }
    }

    fn step_negotiate(newest_version: i32, options: &[&str]) -> Result<Action> {
        let opts = Opts::default();
        let mut machine = auth_machine(&opts);
        feed(
            &mut machine,
            &mut BufferSet::new(),
            msg_type::NEGOTIATE_PROTOCOL_VERSION,
            &negotiate_message(newest_version, options),
        )
    }

    #[test]
    fn negotiate_accepts_3_0() {
        assert!(matches!(
            step_negotiate(PROTOCOL_VERSION_3_0, &[]),
            Ok(Action::ReadMessage)
        ));
    }

    #[test]
    fn negotiate_rejects_3_1() {
        let err = step_negotiate(0x0003_0001, &[]).unwrap_err();
        assert!(err.to_string().contains("3.1"), "{err}");
    }

    #[test]
    fn negotiate_rejects_other_major() {
        let err = step_negotiate(0x0002_0000, &[]).unwrap_err();
        assert!(err.to_string().contains("2.0"), "{err}");
    }

    #[test]
    fn negotiate_rejects_unrecognized_options() {
        for sent in [
            &[("_pq_.unknown", "on")][..],
            &[("search_path", "public"), ("_pq_.unknown", "on")],
            &[("_pq_.other", "1"), ("_pq_.unknown", "on")],
        ] {
            let options = opts_with_params(sent);
            let mut machine = auth_machine(&options);
            let mut buffer_set = BufferSet::new();
            let err = feed(
                &mut machine,
                &mut buffer_set,
                msg_type::NEGOTIATE_PROTOCOL_VERSION,
                &negotiate_message(PROTOCOL_VERSION_3_0, &["_pq_.unknown"]),
            )
            .unwrap_err();
            assert!(
                matches!(&err, Error::Unsupported(message) if message.starts_with("Server rejected protocol options") && message.contains("_pq_.unknown")),
                "{sent:?}: {err}"
            );
        }
    }

    #[test]
    fn negotiate_rejects_option_count_above_sent_options() {
        for (sent, options) in [
            (&[][..], &["_pq_.unknown"][..]),
            (&[("search_path", "public")], &["_pq_.unknown"]),
            (
                &[
                    ("search_path", "public"),
                    ("pq_.almost", "1"),
                    ("x_pq_.y", "1"),
                ],
                &["_pq_.unknown"],
            ),
            (&[("_pq_.a", "1")], &["_pq_.a", "_pq_.b"]),
        ] {
            let opts = opts_with_params(sent);
            let mut machine = auth_machine(&opts);
            let mut buffer_set = BufferSet::new();
            let err = feed(
                &mut machine,
                &mut buffer_set,
                msg_type::NEGOTIATE_PROTOCOL_VERSION,
                &negotiate_message(PROTOCOL_VERSION_3_0, options),
            )
            .unwrap_err();
            assert!(
                matches!(&err, Error::LibraryBug(message) if message.starts_with("NegotiateProtocolVersion: server rejected")),
                "{sent:?} {options:?}: {err}"
            );
        }
    }

    #[test]
    fn negotiate_rejects_u32_max_option_count() {
        let mut payload = PROTOCOL_VERSION_3_0.to_be_bytes().to_vec();
        payload.extend_from_slice(&u32::MAX.to_be_bytes());
        let options = opts_with_params(&[("_pq_.a", "1"), ("_pq_.b", "2")]);
        let mut machine = auth_machine(&options);
        let mut buffer_set = BufferSet::new();
        let err = feed(
            &mut machine,
            &mut buffer_set,
            msg_type::NEGOTIATE_PROTOCOL_VERSION,
            &payload,
        )
        .unwrap_err();
        assert!(
            matches!(&err, Error::LibraryBug(message) if message.starts_with("NegotiateProtocolVersion: server rejected")),
            "{err}"
        );
    }

    #[test]
    fn negotiate_without_rejected_options_continues_to_authentication() {
        for version in [PROTOCOL_VERSION_3_0, PROTOCOL_VERSION_3_2] {
            let options = opts_with_params(&[("search_path", "public"), ("_pq_.a", "1")]);
            let mut machine = auth_machine(&options);
            let mut buffer_set = BufferSet::new();
            assert!(matches!(
                feed(
                    &mut machine,
                    &mut buffer_set,
                    msg_type::NEGOTIATE_PROTOCOL_VERSION,
                    &negotiate_message(version, &[]),
                ),
                Ok(Action::ReadMessage)
            ));
            assert_eq!(machine.state, State::WaitingAuth);
            assert!(matches!(
                feed(
                    &mut machine,
                    &mut buffer_set,
                    msg_type::AUTHENTICATION,
                    &auth_payload(0, &[]),
                ),
                Ok(Action::ReadMessage)
            ));
            assert_eq!(machine.state, State::WaitingReady);
        }
    }

    const SSL_REQUEST: [u8; 8] = [0, 0, 0, 8, 0x04, 0xD2, 0x16, 0x2F];

    #[test]
    fn initial_step_sends_ssl_request_when_tls_supported() {
        for tls_mode in TlsMode::ALL {
            let options = Opts {
                tls_mode,
                ..Opts::default()
            };
            let mut machine = ConnectionStateMachine::new(&options, true);
            let mut buffer_set = BufferSet::new();
            buffer_set.write_buffer.extend_from_slice(b"stale");
            let action = machine.step(&mut buffer_set);
            assert!(
                matches!(action, Ok(Action::WriteAndReadByte)),
                "{tls_mode:?}"
            );
            assert_eq!(buffer_set.write_buffer, SSL_REQUEST, "{tls_mode:?}");
            assert_eq!(machine.state, State::WaitingSslResponse, "{tls_mode:?}");
        }
    }

    #[test]
    fn initial_step_without_tls_support_allows_only_insecure() {
        for tls_mode in TlsMode::ALL {
            let options = Opts {
                user: "alice".into(),
                tls_mode,
                ..Opts::default()
            };
            let mut machine = ConnectionStateMachine::new(&options, false);
            let mut buffer_set = BufferSet::new();
            let result = machine.step(&mut buffer_set);
            if tls_mode == TlsMode::Insecure {
                assert!(
                    matches!(result, Ok(Action::WriteAndReadMessage)),
                    "{tls_mode:?}"
                );
                assert_eq!(machine.state, State::WaitingAuth);
                assert_ne!(buffer_set.write_buffer[..], SSL_REQUEST);
                assert!(
                    buffer_set
                        .write_buffer
                        .windows(b"user\0alice\0".len())
                        .any(|window| window == b"user\0alice\0")
                );
            } else {
                let err = result.unwrap_err();
                assert!(matches!(err, Error::Unsupported(_)), "{tls_mode:?}: {err}");
                assert_eq!(machine.state, State::Initial, "{tls_mode:?}");
                assert!(buffer_set.write_buffer.is_empty(), "{tls_mode:?}");
            }
        }
    }

    fn ssl_response_opts(tls_mode: TlsMode) -> Opts {
        Opts {
            user: "alice".into(),
            tls_mode,
            ..Opts::default()
        }
    }

    fn ssl_response_machine(options: &Opts) -> (ConnectionStateMachine<'_>, BufferSet) {
        let mut machine = ConnectionStateMachine::new(options, true);
        let mut buffer_set = BufferSet::new();
        assert!(matches!(
            machine.step(&mut buffer_set),
            Ok(Action::WriteAndReadByte)
        ));
        (machine, buffer_set)
    }

    #[test]
    fn ssl_response_refused_allows_only_insecure() {
        for tls_mode in TlsMode::ALL {
            let options = ssl_response_opts(tls_mode);
            let (mut machine, mut buffer_set) = ssl_response_machine(&options);
            machine.set_ssl_response(b'N');
            let result = machine.step(&mut buffer_set);
            if tls_mode == TlsMode::Insecure {
                assert!(
                    matches!(result, Ok(Action::WriteAndReadMessage)),
                    "{tls_mode:?}"
                );
                assert_eq!(machine.state, State::WaitingAuth);
                assert_ne!(buffer_set.write_buffer[..], SSL_REQUEST);
                assert!(
                    buffer_set
                        .write_buffer
                        .windows(b"user\0alice\0".len())
                        .any(|window| window == b"user\0alice\0")
                );
                assert_eq!(machine.state, State::WaitingAuth);
            } else {
                let err = result.unwrap_err();
                assert!(
                    matches!(&err, Error::Auth(message) if message.contains("not supported by server")),
                    "{tls_mode:?}: {err}"
                );
                assert_eq!(machine.state, State::WaitingSslResponse, "{tls_mode:?}");
            }
        }
    }

    #[test]
    fn ssl_response_accepted_starts_tls_handshake_for_every_tls_mode() {
        for tls_mode in TlsMode::ALL {
            let options = ssl_response_opts(tls_mode);
            let (mut machine, mut buffer_set) = ssl_response_machine(&options);
            machine.set_ssl_response(b'S');
            assert!(
                matches!(machine.step(&mut buffer_set), Ok(Action::TlsHandshake)),
                "{tls_mode:?}"
            );
            assert_eq!(machine.state, State::WaitingTlsHandshake);
            assert!(matches!(
                machine.step(&mut buffer_set),
                Ok(Action::WriteAndReadMessage)
            ));
            assert_eq!(machine.state, State::WaitingAuth);
        }
    }

    #[test]
    fn ssl_response_unexpected_byte_is_library_bug_for_every_tls_mode() {
        for tls_mode in TlsMode::ALL {
            for response in [0, b'E', b's', b'n'] {
                let options = ssl_response_opts(tls_mode);
                let (mut machine, mut buffer_set) = ssl_response_machine(&options);
                machine.set_ssl_response(response);
                let err = machine.step(&mut buffer_set).unwrap_err();
                assert!(
                    matches!(err, Error::LibraryBug(_)),
                    "{tls_mode:?} {response}: {err}"
                );
            }
        }
    }

    fn auth_machine(options: &Opts) -> ConnectionStateMachine<'_> {
        let mut machine = ConnectionStateMachine::new(options, false);
        machine.state = State::WaitingAuth;
        machine
    }

    fn feed(
        machine: &mut ConnectionStateMachine,
        buffer_set: &mut BufferSet,
        type_byte: u8,
        payload: &[u8],
    ) -> Result<Action> {
        buffer_set.type_byte = type_byte;
        buffer_set.read_buffer.clear();
        buffer_set.read_buffer.extend_from_slice(payload);
        machine.step(buffer_set)
    }

    fn auth_payload(code: i32, data: &[u8]) -> Vec<u8> {
        let mut payload = code.to_be_bytes().to_vec();
        payload.extend_from_slice(data);
        payload
    }

    fn sasl_payload(mechanisms: &[&str]) -> Vec<u8> {
        let mut data = Vec::new();
        for mechanism in mechanisms {
            data.extend_from_slice(mechanism.as_bytes());
            data.push(0);
        }
        data.push(0);
        auth_payload(10, &data)
    }

    fn password_message(body: &[u8]) -> Vec<u8> {
        let mut message = vec![b'p'];
        message.extend_from_slice(&(body.len() as i32 + 4).to_be_bytes());
        message.extend_from_slice(body);
        message
    }

    #[test]
    fn sasl_rejects_unsupported_mechanisms() {
        for mechanisms in [
            &[][..],
            &["SCRAM-SHA-256-PLUS"],
            &["oauthbearer", "scram-sha-256"],
            &["PLAIN"],
        ] {
            let options = Opts {
                password: Some("secret".into()),
                ..Opts::default()
            };
            let mut machine = auth_machine(&options);
            let mut buffer_set = BufferSet::new();
            let err = feed(
                &mut machine,
                &mut buffer_set,
                msg_type::AUTHENTICATION,
                &sasl_payload(mechanisms),
            )
            .unwrap_err();
            assert!(matches!(err, Error::Auth(_)), "{err}");
            assert!(
                err.to_string().contains("No supported SASL mechanism"),
                "{err}"
            );
        }
    }

    #[test]
    fn password_fn_used_for_cleartext() {
        let options = Opts {
            password_fn: Some(Arc::new(|| Ok("from-fn".into()))),
            ..Opts::default()
        };
        let mut machine = auth_machine(&options);
        let mut buffer_set = BufferSet::new();
        let action = feed(
            &mut machine,
            &mut buffer_set,
            msg_type::AUTHENTICATION,
            &auth_payload(3, &[]),
        );
        assert!(matches!(action, Ok(Action::WriteAndReadMessage)));
        assert_eq!(buffer_set.write_buffer, password_message(b"from-fn\0"));
        assert_eq!(machine.state, State::WaitingAuthResult);

        let ok_action = feed(
            &mut machine,
            &mut buffer_set,
            msg_type::AUTHENTICATION,
            &auth_payload(0, &[]),
        );
        assert!(matches!(ok_action, Ok(Action::ReadMessage)));
        assert_eq!(machine.state, State::WaitingReady);
    }

    #[test]
    fn password_fn_takes_precedence_over_password() {
        let options = Opts {
            user: "alice".into(),
            password: Some("static".into()),
            password_fn: Some(Arc::new(|| Ok("dynamic".into()))),
            ..Opts::default()
        };

        let mut cleartext_machine = auth_machine(&options);
        let mut cleartext_buffer_set = BufferSet::new();
        feed(
            &mut cleartext_machine,
            &mut cleartext_buffer_set,
            msg_type::AUTHENTICATION,
            &auth_payload(3, &[]),
        )
        .unwrap();
        assert_eq!(
            cleartext_buffer_set.write_buffer,
            password_message(b"dynamic\0")
        );

        let salt = [0x01, 0x02, 0x03, 0x04];
        let mut md5_machine = auth_machine(&options);
        let mut md5_buffer_set = BufferSet::new();
        feed(
            &mut md5_machine,
            &mut md5_buffer_set,
            msg_type::AUTHENTICATION,
            &auth_payload(5, &salt),
        )
        .unwrap();
        let mut expected = md5_password("alice", "dynamic", &salt).into_bytes();
        expected.push(0);
        assert_eq!(md5_buffer_set.write_buffer, password_message(&expected));
    }

    #[test]
    fn password_fn_called_once_per_request() {
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = std::sync::Arc::clone(&calls);
        let options = Opts {
            password_fn: Some(Arc::new(move || {
                let call = counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(format!("pw{call}"))
            })),
            ..Opts::default()
        };

        let mut cleartext_machine = auth_machine(&options);
        let mut cleartext_buffer_set = BufferSet::new();
        feed(
            &mut cleartext_machine,
            &mut cleartext_buffer_set,
            msg_type::AUTHENTICATION,
            &auth_payload(3, &[]),
        )
        .unwrap();
        assert_eq!(
            cleartext_buffer_set.write_buffer,
            password_message(b"pw0\0")
        );

        let mut scram_machine = auth_machine(&options);
        let mut scram_buffer_set = BufferSet::new();
        feed(
            &mut scram_machine,
            &mut scram_buffer_set,
            msg_type::AUTHENTICATION,
            &sasl_payload(&["SCRAM-SHA-256"]),
        )
        .unwrap();
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    #[test]
    fn password_fn_error_propagates() {
        let options = Opts {
            password: Some("static".into()),
            password_fn: Some(Arc::new(|| Err(Error::Auth("vault unavailable".into())))),
            ..Opts::default()
        };
        let payloads = [
            auth_payload(3, &[]),
            auth_payload(5, &[0, 0, 0, 0]),
            sasl_payload(&["SCRAM-SHA-256"]),
        ];
        for payload in payloads {
            let mut machine = auth_machine(&options);
            let mut buffer_set = BufferSet::new();
            let err = feed(
                &mut machine,
                &mut buffer_set,
                msg_type::AUTHENTICATION,
                &payload,
            )
            .unwrap_err();
            assert!(
                matches!(&err, Error::Auth(message) if message == "vault unavailable"),
                "{err}"
            );
            assert!(buffer_set.write_buffer.is_empty());
            assert!(machine.scram_client.is_none());
        }
    }

    #[test]
    fn password_fn_may_return_empty_password() {
        let options = Opts {
            password_fn: Some(Arc::new(|| Ok(String::new()))),
            ..Opts::default()
        };
        let mut machine = auth_machine(&options);
        let mut buffer_set = BufferSet::new();
        feed(
            &mut machine,
            &mut buffer_set,
            msg_type::AUTHENTICATION,
            &auth_payload(3, &[]),
        )
        .unwrap();
        assert_eq!(buffer_set.write_buffer, password_message(b"\0"));
    }

    #[test]
    fn password_used_without_password_fn() {
        let options = Opts {
            password: Some("static".into()),
            ..Opts::default()
        };
        let mut machine = auth_machine(&options);
        let mut buffer_set = BufferSet::new();
        feed(
            &mut machine,
            &mut buffer_set,
            msg_type::AUTHENTICATION,
            &auth_payload(3, &[]),
        )
        .unwrap();
        assert_eq!(buffer_set.write_buffer, password_message(b"static\0"));
    }

    #[test]
    fn password_required_without_password_or_password_fn() {
        let payloads = [
            auth_payload(3, &[]),
            auth_payload(5, &[0, 0, 0, 0]),
            sasl_payload(&["SCRAM-SHA-256"]),
        ];
        for payload in payloads {
            let options = Opts::default();
            let mut machine = auth_machine(&options);
            let mut buffer_set = BufferSet::new();
            let err = feed(
                &mut machine,
                &mut buffer_set,
                msg_type::AUTHENTICATION,
                &payload,
            )
            .unwrap_err();
            assert!(
                matches!(&err, Error::Auth(message) if message.contains("Password required")),
                "{err}"
            );
        }
    }

    #[cfg(not(feature = "auth-gss"))]
    #[test]
    fn gss_and_sspi_unsupported_without_auth_gss() {
        for code in [7, 9] {
            let options = Opts::default();
            let mut machine = auth_machine(&options);
            let mut buffer_set = BufferSet::new();
            let err = feed(
                &mut machine,
                &mut buffer_set,
                msg_type::AUTHENTICATION,
                &auth_payload(code, &[]),
            )
            .unwrap_err();
            assert!(matches!(err, Error::Unsupported(_)), "{err}");
            assert!(buffer_set.write_buffer.is_empty());
        }
    }

    #[cfg(feature = "auth-gss")]
    #[test]
    fn gss_and_sspi_require_host() {
        for code in [7, 9] {
            let options = Opts::default();
            let mut machine = auth_machine(&options);
            let mut buffer_set = BufferSet::new();
            let err = feed(
                &mut machine,
                &mut buffer_set,
                msg_type::AUTHENTICATION,
                &auth_payload(code, &[]),
            )
            .unwrap_err();
            assert!(
                matches!(&err, Error::Auth(message) if message.contains("Host name required")),
                "{err}"
            );
            assert!(buffer_set.write_buffer.is_empty());
            assert!(machine.gss_client.is_none());
        }
    }

    #[cfg(feature = "auth-gss")]
    #[test]
    fn gss_and_sspi_hand_token_creation_to_driver() {
        for code in [7, 9] {
            let options = Opts {
                host: "db.example.test".into(),
                ..Opts::default()
            };
            let mut machine = auth_machine(&options);
            let mut buffer_set = BufferSet::new();
            let action = feed(
                &mut machine,
                &mut buffer_set,
                msg_type::AUTHENTICATION,
                &auth_payload(code, &[]),
            )
            .unwrap();
            assert!(matches!(action, Action::GssStep), "{action:?}");
            assert!(buffer_set.write_buffer.is_empty());

            let err = machine.step(&mut buffer_set).unwrap_err();
            assert!(matches!(err, Error::LibraryBug(_)), "{err}");

            let gss_step = machine.take_gss_step().unwrap();
            assert!(gss_step.server_token.is_none());
            assert!(machine.take_gss_step().is_err());
        }
    }

    fn oauth_initial_response_message(token: &str) -> Vec<u8> {
        oauth_message_with_auth(&format!("Bearer {token}"))
    }

    fn oauth_message_with_auth(auth: &str) -> Vec<u8> {
        let initial_response = format!("n,,\x01auth={auth}\x01\x01");
        let mut body = b"OAUTHBEARER\0".to_vec();
        body.extend_from_slice(&(initial_response.len() as i32).to_be_bytes());
        body.extend_from_slice(initial_response.as_bytes());
        password_message(&body)
    }

    fn error_response_payload(code: &str, message: &str) -> Vec<u8> {
        let mut payload = Vec::new();
        for (field, value) in [(b'S', "FATAL"), (b'C', code), (b'M', message)] {
            payload.push(field);
            payload.extend_from_slice(value.as_bytes());
            payload.push(0);
        }
        payload.push(0);
        payload
    }

    fn recording_discovery_fn() -> (
        Arc<std::sync::Mutex<Vec<String>>>,
        Arc<dyn Fn(&str) + Send + Sync>,
    ) {
        let calls = Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorder = Arc::clone(&calls);
        let discovery_fn: Arc<dyn Fn(&str) + Send + Sync> =
            Arc::new(move |json: &str| recorder.lock().unwrap().push(json.to_string()));
        (calls, discovery_fn)
    }

    const OAUTH_ERROR_JSON: &str = r#"{"status":"invalid_token","openid-configuration":"https://issuer.example/.well-known/openid-configuration","scope":"openid"}"#;

    fn oauth_rejected_machine<'a>(
        options: &'a Opts,
        buffer_set: &mut BufferSet,
        error_json: &[u8],
    ) -> (ConnectionStateMachine<'a>, Result<Action>) {
        let mut machine = auth_machine(options);
        feed(
            &mut machine,
            buffer_set,
            msg_type::AUTHENTICATION,
            &sasl_payload(&["OAUTHBEARER"]),
        )
        .unwrap();
        assert_eq!(machine.state, State::OauthInProgress);
        let action = feed(
            &mut machine,
            buffer_set,
            msg_type::AUTHENTICATION,
            &auth_payload(11, error_json),
        );
        (machine, action)
    }

    #[test]
    fn oauth_bearer_token_sent_and_accepted() {
        let (discovery_calls, discovery_fn) = recording_discovery_fn();
        let options = Opts {
            oauth_bearer_token_fn: Some(Arc::new(|| Ok("token-abc.def_ghi".into()))),
            oauth_discovery_fn: Some(discovery_fn),
            ..Opts::default()
        };
        let mut machine = auth_machine(&options);
        let mut buffer_set = BufferSet::new();
        let action = feed(
            &mut machine,
            &mut buffer_set,
            msg_type::AUTHENTICATION,
            &sasl_payload(&["OAUTHBEARER"]),
        );
        assert!(matches!(action, Ok(Action::WriteAndReadMessage)));
        assert_eq!(
            buffer_set.write_buffer,
            oauth_initial_response_message("token-abc.def_ghi")
        );
        assert_eq!(machine.state, State::OauthInProgress);
        assert!(machine.scram_client.is_none());

        assert_eq!(machine.state, State::OauthInProgress);

        let ok_action = feed(
            &mut machine,
            &mut buffer_set,
            msg_type::AUTHENTICATION,
            &auth_payload(0, &[]),
        );
        assert!(matches!(ok_action, Ok(Action::ReadMessage)));
        assert_eq!(machine.state, State::WaitingReady);
        assert!(discovery_calls.lock().unwrap().is_empty());
    }

    #[test]
    fn oauth_bearer_rejection_calls_discovery_fn_and_fails_on_error_response() {
        let (discovery_calls, discovery_fn) = recording_discovery_fn();
        let options = Opts {
            oauth_bearer_token_fn: Some(Arc::new(|| Ok("expired".into()))),
            oauth_discovery_fn: Some(discovery_fn),
            ..Opts::default()
        };
        let mut buffer_set = BufferSet::new();
        let (mut machine, action) =
            oauth_rejected_machine(&options, &mut buffer_set, OAUTH_ERROR_JSON.as_bytes());
        assert!(matches!(action, Ok(Action::WriteAndReadMessage)));
        assert_eq!(buffer_set.write_buffer, password_message(b"\x01"));
        assert_eq!(machine.state, State::OauthFailed);
        assert_eq!(*discovery_calls.lock().unwrap(), vec![OAUTH_ERROR_JSON]);

        assert_eq!(machine.state, State::OauthFailed);

        let err = feed(
            &mut machine,
            &mut buffer_set,
            msg_type::ERROR_RESPONSE,
            &error_response_payload("28000", "OAuth bearer authentication failed"),
        )
        .unwrap_err();
        assert!(
            matches!(&err, Error::Server(server) if server.code() == "28000"
                && server.message() == "OAuth bearer authentication failed"),
            "{err}"
        );
        assert_eq!(discovery_calls.lock().unwrap().len(), 1);
    }

    #[test]
    fn oauth_bearer_rejection_without_discovery_fn() {
        let options = Opts {
            oauth_bearer_token_fn: Some(Arc::new(|| Ok("expired".into()))),
            ..Opts::default()
        };
        for error_json in [OAUTH_ERROR_JSON.as_bytes(), b"", b"{}"] {
            let mut buffer_set = BufferSet::new();
            let (mut machine, action) =
                oauth_rejected_machine(&options, &mut buffer_set, error_json);
            assert!(matches!(action, Ok(Action::WriteAndReadMessage)));
            assert_eq!(buffer_set.write_buffer, password_message(b"\x01"));
            let err = feed(
                &mut machine,
                &mut buffer_set,
                msg_type::ERROR_RESPONSE,
                &error_response_payload("28000", "rejected"),
            )
            .unwrap_err();
            assert!(matches!(&err, Error::Server(_)), "{err}");
        }
    }

    #[test]
    fn oauth_bearer_rejection_refuses_authentication_ok() {
        let options = Opts {
            oauth_bearer_token_fn: Some(Arc::new(|| Ok("expired".into()))),
            ..Opts::default()
        };
        let mut buffer_set = BufferSet::new();
        let (mut machine, action) =
            oauth_rejected_machine(&options, &mut buffer_set, OAUTH_ERROR_JSON.as_bytes());
        assert!(matches!(action, Ok(Action::WriteAndReadMessage)));
        let err = feed(
            &mut machine,
            &mut buffer_set,
            msg_type::AUTHENTICATION,
            &auth_payload(0, &[]),
        )
        .unwrap_err();
        assert!(
            matches!(&err, Error::Auth(message) if message.contains("Expected ErrorResponse")),
            "{err}"
        );
        assert_ne!(machine.state, State::WaitingReady);
    }

    #[test]
    fn oauth_bearer_rejects_non_utf8_error_data() {
        let (discovery_calls, discovery_fn) = recording_discovery_fn();
        let options = Opts {
            oauth_bearer_token_fn: Some(Arc::new(|| Ok("tok".into()))),
            oauth_discovery_fn: Some(discovery_fn),
            ..Opts::default()
        };
        for error_json in [&b"\xff\xfe"[..], b"{\"status\":\"\xc3\x28\"}"] {
            let mut buffer_set = BufferSet::new();
            let (_, action) = oauth_rejected_machine(&options, &mut buffer_set, error_json);
            let err = action.unwrap_err();
            assert!(matches!(&err, Error::Auth(_)), "{err}");
        }
        assert!(discovery_calls.lock().unwrap().is_empty());
    }

    #[test]
    fn oauth_bearer_token_fn_error_propagates() {
        let options = Opts {
            password: Some("static".into()),
            oauth_bearer_token_fn: Some(Arc::new(|| Err(Error::Auth("issuer unreachable".into())))),
            ..Opts::default()
        };
        let mut machine = auth_machine(&options);
        let mut buffer_set = BufferSet::new();
        let err = feed(
            &mut machine,
            &mut buffer_set,
            msg_type::AUTHENTICATION,
            &sasl_payload(&["OAUTHBEARER"]),
        )
        .unwrap_err();
        assert!(
            matches!(&err, Error::Auth(message) if message == "issuer unreachable"),
            "{err}"
        );
        assert!(buffer_set.write_buffer.is_empty());
    }

    #[test]
    fn oauth_bearer_token_fn_called_once_per_connection_attempt() {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = Arc::clone(&calls);
        let options = Opts {
            oauth_bearer_token_fn: Some(Arc::new(move || {
                let call = counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(format!("tok{call}").into())
            })),
            ..Opts::default()
        };

        for attempt in 0..2 {
            let mut machine = auth_machine(&options);
            let mut buffer_set = BufferSet::new();
            feed(
                &mut machine,
                &mut buffer_set,
                msg_type::AUTHENTICATION,
                &sasl_payload(&["OAUTHBEARER"]),
            )
            .unwrap();
            assert_eq!(
                buffer_set.write_buffer,
                oauth_initial_response_message(&format!("tok{attempt}"))
            );
            feed(
                &mut machine,
                &mut buffer_set,
                msg_type::AUTHENTICATION,
                &auth_payload(0, &[]),
            )
            .unwrap();
            assert_eq!(machine.state, State::WaitingReady);
            assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), attempt + 1);
        }
    }

    #[test]
    fn oauth_discovery_requested_without_token_fn() {
        let (discovery_calls, discovery_fn) = recording_discovery_fn();
        let options = Opts {
            oauth_discovery_fn: Some(discovery_fn),
            ..Opts::default()
        };
        let mut machine = auth_machine(&options);
        let mut buffer_set = BufferSet::new();
        let action = feed(
            &mut machine,
            &mut buffer_set,
            msg_type::AUTHENTICATION,
            &sasl_payload(&["OAUTHBEARER"]),
        );
        assert!(matches!(action, Ok(Action::WriteAndReadMessage)));
        assert_eq!(buffer_set.write_buffer, oauth_message_with_auth(""));
        assert!(discovery_calls.lock().unwrap().is_empty());

        let rejected_action = feed(
            &mut machine,
            &mut buffer_set,
            msg_type::AUTHENTICATION,
            &auth_payload(11, OAUTH_ERROR_JSON.as_bytes()),
        );
        assert!(matches!(rejected_action, Ok(Action::WriteAndReadMessage)));
        assert_eq!(buffer_set.write_buffer, password_message(b"\x01"));
        assert_eq!(*discovery_calls.lock().unwrap(), [OAUTH_ERROR_JSON]);

        let err = feed(
            &mut machine,
            &mut buffer_set,
            msg_type::ERROR_RESPONSE,
            &error_response_payload("28000", "OAuth bearer authentication failed"),
        )
        .unwrap_err();
        assert!(matches!(err, Error::Server(_)), "{err}");
    }

    #[test]
    fn oauth_bearer_empty_token_sent_verbatim() {
        let options = Opts {
            oauth_bearer_token_fn: Some(Arc::new(|| Ok("".into()))),
            ..Opts::default()
        };
        let mut machine = auth_machine(&options);
        let mut buffer_set = BufferSet::new();
        let action = feed(
            &mut machine,
            &mut buffer_set,
            msg_type::AUTHENTICATION,
            &sasl_payload(&["OAUTHBEARER"]),
        );
        assert!(matches!(action, Ok(Action::WriteAndReadMessage)));
        assert_eq!(buffer_set.write_buffer, oauth_initial_response_message(""));
        assert_eq!(machine.state, State::OauthInProgress);
    }

    #[test]
    fn oauth_bearer_token_required_without_oauth_fn() {
        for options in [
            Opts::default(),
            Opts {
                password: Some("secret".into()),
                ..Opts::default()
            },
        ] {
            let mut machine = auth_machine(&options);
            let mut buffer_set = BufferSet::new();
            let err = feed(
                &mut machine,
                &mut buffer_set,
                msg_type::AUTHENTICATION,
                &sasl_payload(&["OAUTHBEARER"]),
            )
            .unwrap_err();
            assert!(
                matches!(&err, Error::Auth(message) if message.contains("OAuth bearer token required")),
                "{err}"
            );
            assert!(buffer_set.write_buffer.is_empty());
        }
    }

    #[test]
    fn oauth_bearer_token_fn_unused_when_only_scram_offered() {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = Arc::clone(&calls);
        let options = Opts {
            password: Some("secret".into()),
            oauth_bearer_token_fn: Some(Arc::new(move || {
                counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok("tok".into())
            })),
            ..Opts::default()
        };
        let mut machine = auth_machine(&options);
        let mut buffer_set = BufferSet::new();
        let action = feed(
            &mut machine,
            &mut buffer_set,
            msg_type::AUTHENTICATION,
            &sasl_payload(&["SCRAM-SHA-256"]),
        );
        assert!(matches!(action, Ok(Action::WriteAndReadMessage)));
        assert_eq!(machine.state, State::SaslInProgress);
        assert!(machine.scram_client.is_some());
        assert!(buffer_set.write_buffer[5..].starts_with(b"SCRAM-SHA-256\0"));
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    fn decode_base64(encoded: &str) -> Vec<u8> {
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded).unwrap()
    }

    fn secret_password_opts() -> Opts {
        Opts {
            password: Some("secret".into()),
            ..Opts::default()
        }
    }

    fn start_sasl<'a>(
        options: &'a Opts,
        encoded_certificate: Option<&str>,
        mechanisms: &[&str],
    ) -> (ConnectionStateMachine<'a>, BufferSet) {
        let mut machine = auth_machine(options);
        if let Some(encoded_certificate) = encoded_certificate {
            machine.set_server_certificate_der(decode_base64(encoded_certificate));
        }
        let mut buffer_set = BufferSet::new();
        let action = feed(
            &mut machine,
            &mut buffer_set,
            msg_type::AUTHENTICATION,
            &sasl_payload(mechanisms),
        );
        assert!(matches!(action, Ok(Action::WriteAndReadMessage)));
        assert_eq!(machine.state, State::SaslInProgress);
        assert!(machine.scram_client.is_some());
        (machine, buffer_set)
    }

    fn sasl_initial_response(write_buffer: &[u8]) -> (String, String) {
        let (header, body) = write_buffer.split_at(5);
        assert_eq!(header[0], b'p');
        let message_length = i32::from_be_bytes(header[1..].try_into().unwrap());
        assert_eq!(message_length as usize, write_buffer.len() - 1);
        let mechanism_end = body.iter().position(|&byte| byte == 0).unwrap();
        let mechanism = std::str::from_utf8(&body[..mechanism_end]).unwrap();
        let rest = &body[mechanism_end + 1..];
        let response_length = i32::from_be_bytes(rest[..4].try_into().unwrap());
        let client_first = std::str::from_utf8(&rest[4..]).unwrap();
        assert_eq!(response_length as usize, client_first.len());
        (mechanism.to_string(), client_first.to_string())
    }

    #[test]
    fn sasl_without_server_certificate_uses_scram_without_channel_binding() {
        for mechanisms in [
            &["SCRAM-SHA-256-PLUS", "SCRAM-SHA-256"][..],
            &["SCRAM-SHA-256", "SCRAM-SHA-256-PLUS"],
            &["SCRAM-SHA-256"],
        ] {
            let options = secret_password_opts();
            let (_, buffer_set) = start_sasl(&options, None, mechanisms);
            let (mechanism, client_first) = sasl_initial_response(&buffer_set.write_buffer);
            assert_eq!(mechanism, "SCRAM-SHA-256");
            assert!(client_first.starts_with("n,,n=,r="), "{client_first}");
        }
    }

    #[cfg(any(feature = "sync-tls", feature = "tokio-tls", feature = "compio-tls"))]
    #[test]
    fn sasl_with_server_certificate_prefers_scram_plus() {
        use crate::tls::tests::ECDSA_SHA256_CERTIFICATE;

        for mechanisms in [
            &["SCRAM-SHA-256-PLUS", "SCRAM-SHA-256"][..],
            &["SCRAM-SHA-256", "SCRAM-SHA-256-PLUS"],
            &["SCRAM-SHA-256-PLUS"],
        ] {
            let options = secret_password_opts();
            let (_, buffer_set) = start_sasl(&options, Some(ECDSA_SHA256_CERTIFICATE), mechanisms);
            let (mechanism, client_first) = sasl_initial_response(&buffer_set.write_buffer);
            assert_eq!(mechanism, "SCRAM-SHA-256-PLUS");
            assert!(
                client_first.starts_with("p=tls-server-end-point,,n=,r="),
                "{client_first}"
            );
        }
    }

    #[cfg(any(feature = "sync-tls", feature = "tokio-tls", feature = "compio-tls"))]
    #[test]
    fn sasl_with_server_certificate_without_plus_offered_uses_unadvertised_channel_binding() {
        use crate::tls::tests::ECDSA_SHA256_CERTIFICATE;

        let options = secret_password_opts();
        let (_, buffer_set) =
            start_sasl(&options, Some(ECDSA_SHA256_CERTIFICATE), &["SCRAM-SHA-256"]);
        let (mechanism, client_first) = sasl_initial_response(&buffer_set.write_buffer);
        assert_eq!(mechanism, "SCRAM-SHA-256");
        assert!(client_first.starts_with("y,,n=,r="), "{client_first}");
    }

    #[cfg(any(feature = "sync-tls", feature = "tokio-tls", feature = "compio-tls"))]
    #[test]
    fn sasl_with_unhashable_server_certificate_uses_scram_without_channel_binding() {
        use crate::tls::tests::ED25519_CERTIFICATE;

        for encoded_certificate in [ED25519_CERTIFICATE, "bm90IGEgY2VydGlmaWNhdGU="] {
            let options = secret_password_opts();
            let (_, buffer_set) = start_sasl(
                &options,
                Some(encoded_certificate),
                &["SCRAM-SHA-256-PLUS", "SCRAM-SHA-256"],
            );
            let (mechanism, client_first) = sasl_initial_response(&buffer_set.write_buffer);
            assert_eq!(mechanism, "SCRAM-SHA-256");
            assert!(client_first.starts_with("n,,n=,r="), "{client_first}");
        }
    }

    #[cfg(any(feature = "sync-tls", feature = "tokio-tls", feature = "compio-tls"))]
    #[test]
    fn sasl_with_unhashable_server_certificate_rejects_plus_only() {
        use crate::tls::tests::ED25519_CERTIFICATE;

        let options = Opts {
            password: Some("secret".into()),
            ..Opts::default()
        };
        let mut machine = auth_machine(&options);
        machine.set_server_certificate_der(decode_base64(ED25519_CERTIFICATE));
        let mut buffer_set = BufferSet::new();
        let err = feed(
            &mut machine,
            &mut buffer_set,
            msg_type::AUTHENTICATION,
            &sasl_payload(&["SCRAM-SHA-256-PLUS"]),
        )
        .unwrap_err();
        assert!(
            matches!(&err, Error::Auth(message) if message.contains("No supported SASL mechanism")),
            "{err}"
        );
        assert!(buffer_set.write_buffer.is_empty());
    }

    #[cfg(any(feature = "sync-tls", feature = "tokio-tls", feature = "compio-tls"))]
    #[test]
    fn sasl_plus_client_final_binds_server_end_point() {
        use crate::tls::tests::{ECDSA_SHA256_CERTIFICATE, ECDSA_SHA256_END_POINT};

        let options = secret_password_opts();
        let (mut machine, mut buffer_set) = start_sasl(
            &options,
            Some(ECDSA_SHA256_CERTIFICATE),
            &["SCRAM-SHA-256-PLUS", "SCRAM-SHA-256"],
        );
        let (_, client_first) = sasl_initial_response(&buffer_set.write_buffer);
        let client_nonce = client_first
            .strip_prefix("p=tls-server-end-point,,n=,r=")
            .unwrap();

        assert_eq!(machine.state, State::SaslInProgress);

        let server_first = format!("r={client_nonce}server,s=c2FsdA==,i=4096");
        let action = feed(
            &mut machine,
            &mut buffer_set,
            msg_type::AUTHENTICATION,
            &auth_payload(11, server_first.as_bytes()),
        );
        assert!(matches!(action, Ok(Action::WriteAndReadMessage)));
        assert_eq!(machine.state, State::SaslInProgress);

        assert_eq!(buffer_set.write_buffer[0], b'p');
        let client_final = std::str::from_utf8(&buffer_set.write_buffer[5..]).unwrap();
        let channel_binding = client_final
            .split(',')
            .next()
            .unwrap()
            .strip_prefix("c=")
            .unwrap();
        assert_eq!(
            decode_base64(channel_binding),
            [
                b"p=tls-server-end-point,,".as_slice(),
                &decode_base64(ECDSA_SHA256_END_POINT)
            ]
            .concat()
        );
        assert!(
            client_final.contains(&format!(",r={client_nonce}server,p=")),
            "{client_final}"
        );
    }

    const CHANNEL_BINDING_TLS_MODES: [TlsMode; 2] = [TlsMode::ChannelBinding, TlsMode::Hardened];

    fn tls_mode_opts(tls_mode: TlsMode) -> Opts {
        Opts {
            password: Some("secret".into()),
            oauth_bearer_token_fn: Some(Arc::new(|| Ok("token".into()))),
            tls_mode,
            ..Opts::default()
        }
    }

    fn tls_mode_auth_machine<'a>(
        options: &'a Opts,
        encoded_certificate: Option<&str>,
    ) -> ConnectionStateMachine<'a> {
        let mut machine = auth_machine(options);
        if let Some(encoded_certificate) = encoded_certificate {
            machine.set_server_certificate_der(decode_base64(encoded_certificate));
        }
        machine
    }

    fn assert_channel_binding_error(
        machine: &ConnectionStateMachine,
        buffer_set: &BufferSet,
        result: Result<Action>,
        expected: &str,
    ) {
        let err = result.unwrap_err();
        assert!(
            matches!(&err, Error::Auth(message) if message.contains(expected)),
            "{err}"
        );
        assert!(buffer_set.write_buffer.is_empty());
        assert!(machine.scram_client.is_none());
        assert_eq!(machine.state, State::WaitingAuth);
    }

    #[test]
    fn channel_binding_rejects_non_sasl_authentication() {
        let payloads = [
            auth_payload(0, &[]),
            auth_payload(2, &[]),
            auth_payload(3, &[]),
            auth_payload(5, &[0x01, 0x02, 0x03, 0x04]),
            auth_payload(7, &[]),
            auth_payload(8, b"token"),
            auth_payload(9, &[]),
            auth_payload(11, b"r=nonce,s=c2FsdA==,i=4096"),
            auth_payload(12, b"v=c2lnbmF0dXJl"),
        ];
        for tls_mode in CHANNEL_BINDING_TLS_MODES {
            for payload in &payloads {
                let options = tls_mode_opts(tls_mode);
                let mut machine = tls_mode_auth_machine(&options, None);
                let mut buffer_set = BufferSet::new();
                let result = feed(
                    &mut machine,
                    &mut buffer_set,
                    msg_type::AUTHENTICATION,
                    payload,
                );
                assert_channel_binding_error(
                    &machine,
                    &buffer_set,
                    result,
                    "Channel binding is required but the server requested",
                );
            }
        }
    }

    #[test]
    fn channel_binding_rejects_sasl_without_plus() {
        for tls_mode in CHANNEL_BINDING_TLS_MODES {
            for mechanisms in [
                &[][..],
                &["SCRAM-SHA-256"],
                &["OAUTHBEARER"],
                &["SCRAM-SHA-256", "OAUTHBEARER"],
                &["scram-sha-256-plus", "SCRAM-SHA-256"],
                &[
                    "SCRAM-SHA-256-PLU",
                    "SCRAM-SHA-256-PLUS ",
                    "SCRAM-SHA-1-PLUS",
                ],
            ] {
                let options = tls_mode_opts(tls_mode);
                let mut machine = tls_mode_auth_machine(&options, None);
                let mut buffer_set = BufferSet::new();
                let result = feed(
                    &mut machine,
                    &mut buffer_set,
                    msg_type::AUTHENTICATION,
                    &sasl_payload(mechanisms),
                );
                assert_channel_binding_error(
                    &machine,
                    &buffer_set,
                    result,
                    "server does not offer SCRAM-SHA-256-PLUS",
                );
            }
        }
    }

    #[test]
    fn channel_binding_rejects_plus_without_server_certificate() {
        for tls_mode in CHANNEL_BINDING_TLS_MODES {
            for mechanisms in [
                &["SCRAM-SHA-256-PLUS"][..],
                &["SCRAM-SHA-256-PLUS", "SCRAM-SHA-256"],
                &["SCRAM-SHA-256", "SCRAM-SHA-256-PLUS", "OAUTHBEARER"],
            ] {
                let options = tls_mode_opts(tls_mode);
                let mut machine = tls_mode_auth_machine(&options, None);
                let mut buffer_set = BufferSet::new();
                let result = feed(
                    &mut machine,
                    &mut buffer_set,
                    msg_type::AUTHENTICATION,
                    &sasl_payload(mechanisms),
                );
                assert_channel_binding_error(
                    &machine,
                    &buffer_set,
                    result,
                    "tls-server-end-point is undefined",
                );
            }
        }
    }

    #[cfg(any(feature = "sync-tls", feature = "tokio-tls", feature = "compio-tls"))]
    #[test]
    fn channel_binding_rejects_plus_with_unhashable_server_certificate() {
        use crate::tls::tests::ED25519_CERTIFICATE;

        for tls_mode in CHANNEL_BINDING_TLS_MODES {
            for encoded_certificate in [ED25519_CERTIFICATE, "bm90IGEgY2VydGlmaWNhdGU=", ""] {
                let options = tls_mode_opts(tls_mode);
                let mut machine = tls_mode_auth_machine(&options, Some(encoded_certificate));
                let mut buffer_set = BufferSet::new();
                let result = feed(
                    &mut machine,
                    &mut buffer_set,
                    msg_type::AUTHENTICATION,
                    &sasl_payload(&["SCRAM-SHA-256-PLUS", "SCRAM-SHA-256"]),
                );
                assert_channel_binding_error(
                    &machine,
                    &buffer_set,
                    result,
                    "tls-server-end-point is undefined",
                );
            }
        }
    }

    #[cfg(any(feature = "sync-tls", feature = "tokio-tls", feature = "compio-tls"))]
    #[test]
    fn channel_binding_rejects_sasl_without_plus_even_with_server_certificate() {
        use crate::tls::tests::ECDSA_SHA256_CERTIFICATE;

        for tls_mode in CHANNEL_BINDING_TLS_MODES {
            for mechanisms in [&["SCRAM-SHA-256"][..], &["OAUTHBEARER"], &[]] {
                let options = tls_mode_opts(tls_mode);
                let mut machine = tls_mode_auth_machine(&options, Some(ECDSA_SHA256_CERTIFICATE));
                let mut buffer_set = BufferSet::new();
                let result = feed(
                    &mut machine,
                    &mut buffer_set,
                    msg_type::AUTHENTICATION,
                    &sasl_payload(mechanisms),
                );
                assert_channel_binding_error(
                    &machine,
                    &buffer_set,
                    result,
                    "server does not offer SCRAM-SHA-256-PLUS",
                );
            }
        }
    }

    #[cfg(any(feature = "sync-tls", feature = "tokio-tls", feature = "compio-tls"))]
    #[test]
    fn channel_binding_starts_scram_plus_with_server_certificate() {
        use crate::tls::tests::ECDSA_SHA256_CERTIFICATE;

        for tls_mode in CHANNEL_BINDING_TLS_MODES {
            for mechanisms in [
                &["SCRAM-SHA-256-PLUS"][..],
                &["SCRAM-SHA-256", "SCRAM-SHA-256-PLUS"],
                &["OAUTHBEARER", "SCRAM-SHA-256-PLUS", "SCRAM-SHA-256"],
            ] {
                let options = tls_mode_opts(tls_mode);
                let mut machine = tls_mode_auth_machine(&options, Some(ECDSA_SHA256_CERTIFICATE));
                let mut buffer_set = BufferSet::new();
                let action = feed(
                    &mut machine,
                    &mut buffer_set,
                    msg_type::AUTHENTICATION,
                    &sasl_payload(mechanisms),
                );
                assert!(
                    matches!(action, Ok(Action::WriteAndReadMessage)),
                    "{tls_mode:?}"
                );
                assert_eq!(machine.state, State::SaslInProgress);
                assert!(machine.scram_client.is_some());
                let (mechanism, client_first) = sasl_initial_response(&buffer_set.write_buffer);
                assert_eq!(mechanism, "SCRAM-SHA-256-PLUS");
                assert!(
                    client_first.starts_with("p=tls-server-end-point,,n=,r="),
                    "{client_first}"
                );
                assert_eq!(machine.state, State::SaslInProgress);
            }
        }
    }

    #[cfg(any(feature = "sync-tls", feature = "tokio-tls", feature = "compio-tls"))]
    fn scram_plus_after_client_first(options: &Opts) -> (ConnectionStateMachine<'_>, BufferSet) {
        use crate::tls::tests::ECDSA_SHA256_CERTIFICATE;

        let mut machine = tls_mode_auth_machine(options, Some(ECDSA_SHA256_CERTIFICATE));
        let mut buffer_set = BufferSet::new();
        feed(
            &mut machine,
            &mut buffer_set,
            msg_type::AUTHENTICATION,
            &sasl_payload(&["SCRAM-SHA-256-PLUS"]),
        )
        .unwrap();
        assert_eq!(machine.state, State::SaslInProgress);
        (machine, buffer_set)
    }

    #[cfg(any(feature = "sync-tls", feature = "tokio-tls", feature = "compio-tls"))]
    fn scram_plus_after_client_final(options: &Opts) -> (ConnectionStateMachine<'_>, BufferSet) {
        let (mut machine, mut buffer_set) = scram_plus_after_client_first(options);
        let (_, client_first) = sasl_initial_response(&buffer_set.write_buffer);
        let client_nonce = client_first
            .strip_prefix("p=tls-server-end-point,,n=,r=")
            .unwrap()
            .to_string();
        let server_first = format!("r={client_nonce}server,s=c2FsdA==,i=4096");
        assert!(matches!(
            feed(
                &mut machine,
                &mut buffer_set,
                msg_type::AUTHENTICATION,
                &auth_payload(11, server_first.as_bytes()),
            ),
            Ok(Action::WriteAndReadMessage)
        ));
        assert_eq!(machine.state, State::SaslInProgress);
        (machine, buffer_set)
    }

    #[cfg(any(feature = "sync-tls", feature = "tokio-tls", feature = "compio-tls"))]
    #[test]
    fn channel_binding_rejects_authentication_ok_after_client_first() {
        for tls_mode in CHANNEL_BINDING_TLS_MODES {
            let options = tls_mode_opts(tls_mode);
            let (mut machine, mut buffer_set) = scram_plus_after_client_first(&options);
            feed(
                &mut machine,
                &mut buffer_set,
                msg_type::AUTHENTICATION,
                &auth_payload(0, &[]),
            )
            .unwrap_err();
            assert_ne!(machine.state, State::WaitingReady);
        }
    }

    #[cfg(any(feature = "sync-tls", feature = "tokio-tls", feature = "compio-tls"))]
    #[test]
    fn channel_binding_rejects_authentication_ok_after_client_final() {
        for tls_mode in CHANNEL_BINDING_TLS_MODES {
            let options = tls_mode_opts(tls_mode);
            let (mut machine, mut buffer_set) = scram_plus_after_client_final(&options);
            feed(
                &mut machine,
                &mut buffer_set,
                msg_type::AUTHENTICATION,
                &auth_payload(0, &[]),
            )
            .unwrap_err();
            assert_ne!(machine.state, State::WaitingReady);
        }
    }

    #[cfg(any(feature = "sync-tls", feature = "tokio-tls", feature = "compio-tls"))]
    #[test]
    fn channel_binding_rejects_forged_server_final() {
        for tls_mode in CHANNEL_BINDING_TLS_MODES {
            let options = tls_mode_opts(tls_mode);
            let (mut machine, mut buffer_set) = scram_plus_after_client_final(&options);
            let err = feed(
                &mut machine,
                &mut buffer_set,
                msg_type::AUTHENTICATION,
                &auth_payload(12, b"v=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="),
            )
            .unwrap_err();
            assert!(matches!(err, Error::Auth(_)), "{err}");
            assert_ne!(machine.state, State::WaitingReady);
        }
    }

    #[cfg(any(feature = "sync-tls", feature = "tokio-tls", feature = "compio-tls"))]
    #[test]
    fn channel_binding_requires_password_for_scram_plus() {
        use crate::tls::tests::ECDSA_SHA256_CERTIFICATE;

        for tls_mode in CHANNEL_BINDING_TLS_MODES {
            let options = Opts {
                tls_mode,
                ..Opts::default()
            };
            let mut machine = auth_machine(&options);
            machine.set_server_certificate_der(decode_base64(ECDSA_SHA256_CERTIFICATE));
            let mut buffer_set = BufferSet::new();
            let result = feed(
                &mut machine,
                &mut buffer_set,
                msg_type::AUTHENTICATION,
                &sasl_payload(&["SCRAM-SHA-256-PLUS"]),
            );
            assert_channel_binding_error(&machine, &buffer_set, result, "Password required");
        }
    }

    #[test]
    fn non_channel_binding_tls_mode_accepts_authentication_ok() {
        for tls_mode in [TlsMode::Insecure, TlsMode::Pki] {
            let options = tls_mode_opts(tls_mode);
            let mut machine = tls_mode_auth_machine(&options, None);
            let mut buffer_set = BufferSet::new();
            let action = feed(
                &mut machine,
                &mut buffer_set,
                msg_type::AUTHENTICATION,
                &auth_payload(0, &[]),
            );
            assert!(matches!(action, Ok(Action::ReadMessage)), "{tls_mode:?}");
            assert_eq!(machine.state, State::WaitingReady);
        }
    }

    #[test]
    fn non_channel_binding_tls_mode_accepts_password_authentication() {
        for tls_mode in [TlsMode::Insecure, TlsMode::Pki] {
            let options = tls_mode_opts(tls_mode);
            let mut cleartext_machine = tls_mode_auth_machine(&options, None);
            let mut cleartext_buffer_set = BufferSet::new();
            let cleartext_action = feed(
                &mut cleartext_machine,
                &mut cleartext_buffer_set,
                msg_type::AUTHENTICATION,
                &auth_payload(3, &[]),
            );
            assert!(
                matches!(cleartext_action, Ok(Action::WriteAndReadMessage)),
                "{tls_mode:?}"
            );
            assert_eq!(
                cleartext_buffer_set.write_buffer,
                password_message(b"secret\0")
            );

            let mut md5_machine = tls_mode_auth_machine(&options, None);
            let mut md5_buffer_set = BufferSet::new();
            let md5_action = feed(
                &mut md5_machine,
                &mut md5_buffer_set,
                msg_type::AUTHENTICATION,
                &auth_payload(5, &[0x01, 0x02, 0x03, 0x04]),
            );
            assert!(
                matches!(md5_action, Ok(Action::WriteAndReadMessage)),
                "{tls_mode:?}"
            );
            assert_eq!(md5_machine.state, State::WaitingAuthResult);
        }
    }

    #[test]
    fn non_channel_binding_tls_mode_falls_back_to_scram_and_oauth() {
        for tls_mode in [TlsMode::Insecure, TlsMode::Pki] {
            for mechanisms in [
                &["SCRAM-SHA-256"][..],
                &["SCRAM-SHA-256-PLUS", "SCRAM-SHA-256"],
            ] {
                let options = tls_mode_opts(tls_mode);
                let mut machine = tls_mode_auth_machine(&options, None);
                let mut buffer_set = BufferSet::new();
                let action = feed(
                    &mut machine,
                    &mut buffer_set,
                    msg_type::AUTHENTICATION,
                    &sasl_payload(mechanisms),
                );
                assert!(
                    matches!(action, Ok(Action::WriteAndReadMessage)),
                    "{tls_mode:?}"
                );
                let (mechanism, client_first) = sasl_initial_response(&buffer_set.write_buffer);
                assert_eq!(mechanism, "SCRAM-SHA-256");
                assert!(client_first.starts_with("n,,n=,r="), "{client_first}");
            }

            let options = tls_mode_opts(tls_mode);
            let mut machine = tls_mode_auth_machine(&options, None);
            let mut buffer_set = BufferSet::new();
            let action = feed(
                &mut machine,
                &mut buffer_set,
                msg_type::AUTHENTICATION,
                &sasl_payload(&["OAUTHBEARER"]),
            );
            assert!(
                matches!(action, Ok(Action::WriteAndReadMessage)),
                "{tls_mode:?}"
            );
            assert_eq!(
                buffer_set.write_buffer,
                oauth_initial_response_message("token")
            );
            assert_eq!(machine.state, State::OauthInProgress);
        }
    }

    #[cfg(any(feature = "sync-tls", feature = "tokio-tls", feature = "compio-tls"))]
    #[test]
    fn pki_keeps_channel_binding_preferences() {
        use crate::tls::tests::{ECDSA_SHA256_CERTIFICATE, ED25519_CERTIFICATE};

        for (encoded_certificate, mechanisms, expected_mechanism, expected_prefix) in [
            (
                ECDSA_SHA256_CERTIFICATE,
                &["SCRAM-SHA-256", "SCRAM-SHA-256-PLUS"][..],
                "SCRAM-SHA-256-PLUS",
                "p=tls-server-end-point,,n=,r=",
            ),
            (
                ECDSA_SHA256_CERTIFICATE,
                &["SCRAM-SHA-256"],
                "SCRAM-SHA-256",
                "y,,n=,r=",
            ),
            (
                ED25519_CERTIFICATE,
                &["SCRAM-SHA-256-PLUS", "SCRAM-SHA-256"],
                "SCRAM-SHA-256",
                "n,,n=,r=",
            ),
        ] {
            let options = tls_mode_opts(TlsMode::Pki);
            let mut machine = tls_mode_auth_machine(&options, Some(encoded_certificate));
            let mut buffer_set = BufferSet::new();
            let action = feed(
                &mut machine,
                &mut buffer_set,
                msg_type::AUTHENTICATION,
                &sasl_payload(mechanisms),
            );
            assert!(matches!(action, Ok(Action::WriteAndReadMessage)));
            let (mechanism, client_first) = sasl_initial_response(&buffer_set.write_buffer);
            assert_eq!(mechanism, expected_mechanism);
            assert!(client_first.starts_with(expected_prefix), "{client_first}");
        }
    }

    #[test]
    fn ready_for_query_rejects_invalid_status_byte() {
        for status in [0, b'i', b'X', 0xFF] {
            let options = Opts::default();
            let mut machine = auth_machine(&options);
            machine.state = State::WaitingReady;
            let err = feed(
                &mut machine,
                &mut BufferSet::new(),
                msg_type::READY_FOR_QUERY,
                &[status],
            )
            .unwrap_err();
            assert!(
                matches!(&err, Error::LibraryBug(message) if message.starts_with("ReadyForQuery: invalid transaction status byte")),
                "{status}: {err}"
            );
            assert_ne!(machine.state, State::Finished);
        }
    }

    #[test]
    fn ready_for_query_idle_finishes_startup() {
        let options = Opts::default();
        let mut machine = auth_machine(&options);
        machine.state = State::WaitingReady;
        let action = feed(
            &mut machine,
            &mut BufferSet::new(),
            msg_type::READY_FOR_QUERY,
            b"I",
        );
        assert!(matches!(action, Ok(Action::Finished)));
        assert_eq!(machine.state, State::Finished);
        assert_eq!(machine.transaction_status, TransactionStatus::Idle);
    }
}
