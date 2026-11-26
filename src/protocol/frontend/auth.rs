//! Authentication messages.

use std::ffi::{CStr, CString};

use crate::protocol::codec::MessageBuilder;

const MIN_SCRAM_ITERATIONS: u32 = 4096;
const MAX_SCRAM_ITERATIONS: u32 = 10_000_000;

/// Write a PasswordMessage (cleartext or MD5 hashed password).
pub fn write_password(buf: &mut Vec<u8>, password: &CStr) {
    let mut msg = MessageBuilder::new(buf, super::msg_type::PASSWORD);
    msg.write_bytes(password.to_bytes_with_nul());
    msg.finish();
}

pub fn write_md5_password(buf: &mut Vec<u8>, username: &[u8], password: &CStr, salt: &[u8; 4]) {
    let hashed = md5_password(username, password, salt);
    let mut msg = MessageBuilder::new(buf, super::msg_type::PASSWORD);
    msg.write_cstr(&hashed);
    msg.finish();
}

fn lowercase_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";

    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(DIGITS[(byte >> 4) as usize] as char);
        encoded.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    encoded
}

/// Compute MD5 password hash.
///
/// PostgreSQL MD5 password format: "md5" + md5(md5(password + username) + salt)
pub fn md5_password(username: &[u8], password: &CStr, salt: &[u8; 4]) -> String {
    use md5::{Digest, Md5};

    // First hash: md5(password + username)
    let first_hash = {
        let mut hasher = Md5::new();
        hasher.update(password.to_bytes());
        hasher.update(username);
        hasher.finalize()
    };
    let first_hash_hex = lowercase_hex(&first_hash);

    // Second hash: md5(first_hash_hex + salt)
    let second_hash = {
        let mut hasher = Md5::new();
        hasher.update(first_hash_hex.as_bytes());
        hasher.update(salt);
        hasher.finalize()
    };

    format!("md5{}", lowercase_hex(&second_hash))
}

/// Write a SASLInitialResponse message.
///
/// mechanism: SASL mechanism name (e.g., "SCRAM-SHA-256")
/// initial_response: Client-first-message for SCRAM
pub fn write_sasl_initial_response(buf: &mut Vec<u8>, mechanism: &str, initial_response: &[u8]) {
    let mut msg = MessageBuilder::new(buf, super::msg_type::PASSWORD);
    msg.write_cstr(mechanism);
    msg.write_i32(initial_response.len() as i32);
    msg.write_bytes(initial_response);
    msg.finish();
}

/// Write a SASLResponse message.
///
/// response: Client-final-message for SCRAM
pub fn write_sasl_response(buf: &mut Vec<u8>, response: &[u8]) {
    let mut msg = MessageBuilder::new(buf, super::msg_type::PASSWORD);
    msg.write_bytes(response);
    msg.finish();
}

pub fn write_gss_response(buf: &mut Vec<u8>, token: &[u8]) {
    let mut msg = MessageBuilder::new(buf, super::msg_type::PASSWORD);
    msg.write_bytes(token);
    msg.finish();
}

/// SCRAM-SHA-256 client implementation.
pub struct ScramClient {
    /// Client nonce
    nonce: String,
    gs2_header: &'static str,
    channel_binding_data: Vec<u8>,
    /// Password
    password: CString,
    /// Auth message for signature verification
    auth_message: Option<String>,
    /// Salted password for server signature verification
    salted_password: Option<Vec<u8>>,
}

impl ScramClient {
    /// Create a new SCRAM client.
    pub fn new(password: &CStr) -> Self {
        Self::with_gs2_header(password, "n,,", &[])
    }

    /// Create a new SCRAM client with channel binding.
    pub fn new_with_channel_binding(password: &CStr, channel_binding_data: &[u8]) -> Self {
        Self::with_gs2_header(password, "p=tls-server-end-point,,", channel_binding_data)
    }

    pub fn new_with_unadvertised_channel_binding(password: &CStr) -> Self {
        Self::with_gs2_header(password, "y,,", &[])
    }

    fn with_gs2_header(
        password: &CStr,
        gs2_header: &'static str,
        channel_binding_data: &[u8],
    ) -> Self {
        use rand::RngExt;

        // Generate 24-byte random nonce, base64 encoded
        let mut nonce_bytes = [0u8; 24];
        rand::rng().fill(&mut nonce_bytes);
        let nonce = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, nonce_bytes);

        Self {
            nonce,
            gs2_header,
            channel_binding_data: channel_binding_data.to_vec(),
            password: password.to_owned(),
            auth_message: None,
            salted_password: None,
        }
    }

    /// Generate the client-first-message.
    pub fn client_first_message(&self) -> String {
        // n,,n=,r=<nonce>
        // Note: username is empty because PostgreSQL ignores it in SCRAM
        format!("{}n=,r={}", self.gs2_header, self.nonce)
    }

    /// Get the bare client-first-message (without channel binding prefix).
    fn client_first_message_bare(&self) -> String {
        format!("n=,r={}", self.nonce)
    }

    /// Process server-first-message and generate client-final-message.
    pub fn process_server_first(&mut self, server_first: &str) -> Result<String, String> {
        use base64::Engine;
        use hmac::{Hmac, KeyInit, Mac};
        use pbkdf2::pbkdf2_hmac;
        use sha2::{Digest, Sha256};

        // Parse server-first-message: r=<nonce>,s=<salt>,i=<iterations>
        let mut combined_nonce = None;
        let mut salt_b64 = None;
        let mut iterations = None;

        for part in server_first.split(',') {
            if let Some(value) = part.strip_prefix("r=") {
                combined_nonce = Some(value);
            } else if let Some(value) = part.strip_prefix("s=") {
                salt_b64 = Some(value);
            } else if let Some(value) = part.strip_prefix("i=") {
                if !matches!(value.as_bytes().first(), Some(b'1'..=b'9')) {
                    return Err(format!("Invalid SCRAM iteration count {value:?}"));
                }
                iterations = value.parse().ok();
            }
        }

        let combined_nonce = combined_nonce.ok_or("Missing nonce in server-first-message")?;
        let salt_b64 = salt_b64.ok_or("Missing salt in server-first-message")?;
        let iterations: u32 = iterations.ok_or("Missing iterations in server-first-message")?;
        if iterations < MIN_SCRAM_ITERATIONS {
            return Err(format!(
                "SCRAM iteration count {iterations} is below the minimum of {MIN_SCRAM_ITERATIONS}"
            ));
        }
        // Prevent DoS
        if iterations > MAX_SCRAM_ITERATIONS {
            return Err(format!(
                "SCRAM iteration count {iterations} exceeds the maximum of {MAX_SCRAM_ITERATIONS}"
            ));
        }

        // Verify nonce starts with our client nonce
        if !combined_nonce.starts_with(&self.nonce) {
            return Err("Server nonce doesn't start with client nonce".to_string());
        }
        if combined_nonce.len() == self.nonce.len() {
            return Err("Server did not append its own nonce to the client nonce".to_string());
        }

        // Decode salt
        let salt = base64::engine::general_purpose::STANDARD
            .decode(salt_b64)
            .map_err(|e| format!("Invalid salt: {}", e))?;

        // Compute SaltedPassword = Hi(Normalize(password), salt, iterations)
        let mut salted_password = vec![0u8; 32];
        pbkdf2_hmac::<Sha256>(
            self.password.to_bytes(),
            &salt,
            iterations,
            &mut salted_password,
        );

        // ClientKey = HMAC(SaltedPassword, "Client Key")
        let client_key = {
            let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&salted_password)
                .map_err(|e| format!("HMAC error: {}", e))?;
            mac.update(b"Client Key");
            mac.finalize().into_bytes()
        };
        self.salted_password = Some(salted_password);

        // StoredKey = H(ClientKey)
        let stored_key = Sha256::digest(client_key);

        let channel_binding_b64 = base64::engine::general_purpose::STANDARD
            .encode([self.gs2_header.as_bytes(), &self.channel_binding_data].concat());

        // client-final-message-without-proof = c=<channel-binding>,r=<nonce>
        let client_final_without_proof = format!("c={},r={}", channel_binding_b64, combined_nonce);

        // AuthMessage = client-first-message-bare + "," + server-first-message + "," + client-final-message-without-proof
        let auth_message = format!(
            "{},{},{}",
            self.client_first_message_bare(),
            server_first,
            client_final_without_proof
        );

        // ClientSignature = HMAC(StoredKey, AuthMessage)
        let client_signature = {
            let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&stored_key)
                .map_err(|e| format!("HMAC error: {}", e))?;
            mac.update(auth_message.as_bytes());
            mac.finalize().into_bytes()
        };
        self.auth_message = Some(auth_message);

        // ClientProof = ClientKey XOR ClientSignature
        let mut client_proof = [0u8; 32];
        for i in 0..32 {
            client_proof[i] = client_key[i] ^ client_signature[i];
        }

        let proof_b64 = base64::engine::general_purpose::STANDARD.encode(client_proof);

        // client-final-message = client-final-message-without-proof + ",p=" + base64(ClientProof)
        Ok(format!("{},p={}", client_final_without_proof, proof_b64))
    }

    /// Verify server-final-message.
    pub fn verify_server_final(&self, server_final: &str) -> Result<(), String> {
        use base64::Engine;
        use hmac::{Hmac, KeyInit, Mac};

        // Parse server-final-message: v=<server-signature>
        let server_signature_b64 = server_final
            .strip_prefix("v=")
            .ok_or("Invalid server-final-message format")?;

        let server_signature = base64::engine::general_purpose::STANDARD
            .decode(server_signature_b64)
            .map_err(|e| format!("Invalid server signature: {}", e))?;

        // Compute expected ServerSignature
        let salted_password = self
            .salted_password
            .as_ref()
            .ok_or("Missing salted password")?;
        let auth_message = self.auth_message.as_ref().ok_or("Missing auth message")?;

        // ServerKey = HMAC(SaltedPassword, "Server Key")
        let server_key = {
            let mut mac = <Hmac<sha2::Sha256> as KeyInit>::new_from_slice(salted_password)
                .map_err(|e| format!("HMAC error: {}", e))?;
            mac.update(b"Server Key");
            mac.finalize().into_bytes()
        };

        // ServerSignature = HMAC(ServerKey, AuthMessage)
        let expected_signature = {
            let mut mac = <Hmac<sha2::Sha256> as KeyInit>::new_from_slice(&server_key)
                .map_err(|e| format!("HMAC error: {}", e))?;
            mac.update(auth_message.as_bytes());
            mac.finalize().into_bytes()
        };

        if server_signature.as_slice() != expected_signature.as_slice() {
            return Err("Server signature verification failed".to_string());
        }

        Ok(())
    }
}

pub struct ScramStep {
    client: ScramClient,
    server_first: String,
    client_final: Option<String>,
}

impl ScramStep {
    pub(crate) fn new(client: ScramClient, server_first: String) -> Self {
        Self {
            client,
            server_first,
            client_final: None,
        }
    }

    pub fn run(mut self) -> crate::error::Result<Self> {
        let client_final = self
            .client
            .process_server_first(&self.server_first)
            .map_err(crate::error::Error::Auth)?;
        self.client_final = Some(client_final);
        Ok(self)
    }

    pub(crate) fn into_client_and_client_final(self) -> (ScramClient, Option<String>) {
        (self.client, self.client_final)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn md5_password_hash() {
        // Test vector from PostgreSQL
        let result = md5_password(b"postgres", c"password", &[0x01, 0x02, 0x03, 0x04]);
        assert_eq!(result, "md598511ceaec347a656f032c7f2a16ef17");
    }

    #[test]
    fn password_message() {
        let mut buf = Vec::new();
        write_password(&mut buf, c"secret");

        assert_eq!(buf[0], b'p');
        // Check that password is null-terminated in the message
        assert!(buf.ends_with(&[0]));
    }

    #[test]
    fn md5_password_message() {
        let mut buf = Vec::new();
        write_md5_password(
            &mut buf,
            b"postgres",
            c"password",
            &[0x01, 0x02, 0x03, 0x04],
        );

        let mut expected = vec![b'p'];
        expected.extend_from_slice(&40_i32.to_be_bytes());
        expected.extend_from_slice(b"md598511ceaec347a656f032c7f2a16ef17");
        expected.push(0);
        assert_eq!(buf, expected);
    }

    #[test]
    fn gss_response_carries_token_verbatim() {
        let mut buf = Vec::new();
        write_gss_response(&mut buf, &[0x60, 0x00, 0xff]);

        assert_eq!(buf, [b'p', 0, 0, 0, 7, 0x60, 0x00, 0xff]);
    }

    fn encode(bytes: &[u8]) -> String {
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, bytes)
    }

    fn channel_binding_attribute(scram: &mut ScramClient) -> String {
        let server_first = format!("r={}server,s={},i=4096", scram.nonce, encode(b"salt"));
        let client_final = scram.process_server_first(&server_first).unwrap();
        let channel_binding = client_final
            .split(',')
            .next()
            .unwrap()
            .strip_prefix("c=")
            .unwrap();
        channel_binding.to_string()
    }

    #[test]
    fn client_first_message_starts_with_gs2_header() {
        let channel_binding_data: Vec<u8> = (0..=255).collect();
        for (scram, header) in [
            (ScramClient::new(c"secret"), "n,,"),
            (
                ScramClient::new_with_unadvertised_channel_binding(c"secret"),
                "y,,",
            ),
            (
                ScramClient::new_with_channel_binding(c"secret", &channel_binding_data),
                "p=tls-server-end-point,,",
            ),
        ] {
            assert_eq!(
                scram.client_first_message(),
                format!("{header}n=,r={}", scram.nonce)
            );
            assert!(
                !scram
                    .client_first_message()
                    .contains(&encode(&channel_binding_data))
            );
        }
    }

    #[test]
    fn client_final_channel_binding_without_binding_data() {
        assert_eq!(
            channel_binding_attribute(&mut ScramClient::new(c"secret")),
            "biws"
        );
        assert_eq!(
            channel_binding_attribute(&mut ScramClient::new_with_unadvertised_channel_binding(
                c"secret"
            )),
            "eSws"
        );
    }

    #[test]
    fn client_final_channel_binding_carries_raw_binding_data() {
        for channel_binding_data in [
            vec![0xab; 32],
            vec![0x00, 0xff, 0xfe, 0x80, 0x00],
            (0..=255).collect::<Vec<u8>>(),
        ] {
            let mut scram = ScramClient::new_with_channel_binding(c"secret", &channel_binding_data);
            let expected = encode(
                &[
                    b"p=tls-server-end-point,,".as_slice(),
                    &channel_binding_data,
                ]
                .concat(),
            );
            assert_eq!(channel_binding_attribute(&mut scram), expected);
        }
    }

    #[test]
    fn channel_binding_known_answer() {
        let channel_binding_data: Vec<u8> = (0..32).collect();
        let mut scram = ScramClient::new_with_channel_binding(c"pencil", &channel_binding_data);
        scram.nonce = "rOprNGfwEbeRWgbNEkqO".to_string();
        assert_eq!(
            scram.client_first_message(),
            "p=tls-server-end-point,,n=,r=rOprNGfwEbeRWgbNEkqO"
        );

        let client_final = scram
            .process_server_first(
                "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096",
            )
            .unwrap();
        assert_eq!(
            client_final,
            "c=cD10bHMtc2VydmVyLWVuZC1wb2ludCwsAAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=Q8h71kjaoMzNI7dPksDrhRE/5mTUObF0fUHVIgBOWQg="
        );

        scram
            .verify_server_final("v=ykwoqH8mLqO5AQCeuwwf6lsj9f8zyJZT/CcvAbN4Ssc=")
            .unwrap();
        scram
            .verify_server_final("v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=")
            .unwrap_err();
    }

    #[test]
    fn channel_binding_data_changes_client_proof() {
        let server_first = "r=fixednonceserver,s=c2FsdA==,i=4096";
        let mut proofs = Vec::new();
        for channel_binding_data in [[0u8; 32], [1u8; 32]] {
            let mut scram = ScramClient::new_with_channel_binding(c"secret", &channel_binding_data);
            scram.nonce = "fixednonce".to_string();
            let client_final = scram.process_server_first(server_first).unwrap();
            proofs.push(client_final.rsplit_once(",p=").unwrap().1.to_string());
        }
        assert_ne!(proofs[0], proofs[1]);
    }

    #[test]
    fn scram_requires_server_nonce_extending_client_nonce() {
        let mut scram = ScramClient::new(c"secret");
        let client_nonce = scram
            .client_first_message()
            .strip_prefix("n,,n=,r=")
            .unwrap()
            .to_string();
        let truncated = &client_nonce[..client_nonce.len() - 1];
        for (server_nonce, expected) in [
            (
                String::new(),
                "Server nonce doesn't start with client nonce",
            ),
            (
                truncated.to_string(),
                "Server nonce doesn't start with client nonce",
            ),
            (
                format!("x{client_nonce}"),
                "Server nonce doesn't start with client nonce",
            ),
            (
                client_nonce.clone(),
                "Server did not append its own nonce to the client nonce",
            ),
        ] {
            let server_first = format!("r={server_nonce},s=c2FsdA==,i=4096");
            assert_eq!(
                scram.process_server_first(&server_first).unwrap_err(),
                expected
            );
            assert_eq!(
                scram.verify_server_final("v=AAAA").unwrap_err(),
                "Missing salted password"
            );
        }

        let server_first = format!("r={client_nonce}x,s=c2FsdA==,i=4096");
        let client_final = scram.process_server_first(&server_first).unwrap();
        assert!(client_final.starts_with(&format!("c=biws,r={client_nonce}x,p=")));
    }

    #[test]
    fn scram_rejects_iterations_above_maximum() {
        for iterations in [MAX_SCRAM_ITERATIONS + 1, u32::MAX] {
            let mut scram = ScramClient::new(c"secret");
            let server_first = format!(
                "r={}server,s={},i={iterations}",
                scram.nonce,
                encode(b"salt")
            );
            assert_eq!(
                scram.process_server_first(&server_first).unwrap_err(),
                format!("SCRAM iteration count {iterations} exceeds the maximum of 10000000")
            );
            assert_eq!(
                scram.verify_server_final("v=AAAA").unwrap_err(),
                "Missing salted password"
            );

            let accepted = format!("r={}server,s={},i=4096", scram.nonce, encode(b"salt"));
            let client_final = scram.process_server_first(&accepted).unwrap();
            assert!(client_final.starts_with(&format!("c=biws,r={}server,p=", scram.nonce)));
        }
    }

    #[test]
    fn scram_rejects_iterations_below_minimum() {
        for iterations in [1, MIN_SCRAM_ITERATIONS - 1] {
            let mut scram = ScramClient::new(c"secret");
            let server_first = format!(
                "r={}server,s={},i={iterations}",
                scram.nonce,
                encode(b"salt")
            );
            assert_eq!(
                scram.process_server_first(&server_first).unwrap_err(),
                format!("SCRAM iteration count {iterations} is below the minimum of 4096")
            );
            assert_eq!(
                scram.verify_server_final("v=AAAA").unwrap_err(),
                "Missing salted password"
            );
        }
    }

    #[test]
    fn scram_rejects_malformed_iterations() {
        for (iterations, expected) in [
            ("0", "Invalid SCRAM iteration count \"0\""),
            ("", "Invalid SCRAM iteration count \"\""),
            ("+4096", "Invalid SCRAM iteration count \"+4096\""),
            ("04096", "Invalid SCRAM iteration count \"04096\""),
            ("-1", "Invalid SCRAM iteration count \"-1\""),
            (" 4096", "Invalid SCRAM iteration count \" 4096\""),
            ("4096x", "Missing iterations in server-first-message"),
            ("99999999999", "Missing iterations in server-first-message"),
        ] {
            let mut scram = ScramClient::new(c"secret");
            let server_first = format!(
                "r={}server,s={},i={iterations}",
                scram.nonce,
                encode(b"salt")
            );
            assert_eq!(
                scram.process_server_first(&server_first).unwrap_err(),
                expected,
                "{iterations:?}"
            );
            assert_eq!(
                scram.verify_server_final("v=AAAA").unwrap_err(),
                "Missing salted password"
            );
        }
    }

    #[test]
    fn scram_accepts_iterations_within_bounds() {
        for iterations in [MIN_SCRAM_ITERATIONS, MIN_SCRAM_ITERATIONS + 1] {
            let mut scram = ScramClient::new(c"secret");
            let server_first = format!(
                "r={}server,s={},i={iterations}",
                scram.nonce,
                encode(b"salt")
            );
            let client_final = scram.process_server_first(&server_first).unwrap();
            assert!(client_final.starts_with(&format!("c=biws,r={}server,p=", scram.nonce)));
            assert_eq!(
                scram.verify_server_final("v=AAAA").unwrap_err(),
                "Server signature verification failed"
            );
        }
    }
}
