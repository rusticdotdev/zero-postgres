//! Authentication messages.

use crate::protocol::codec::MessageBuilder;

/// Write a PasswordMessage (cleartext or MD5 hashed password).
pub fn write_password(buf: &mut Vec<u8>, password: &str) {
    let mut msg = MessageBuilder::new(buf, super::msg_type::PASSWORD);
    msg.write_cstr(password);
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
pub fn md5_password(username: &str, password: &str, salt: &[u8; 4]) -> String {
    use md5::{Digest, Md5};

    // First hash: md5(password + username)
    let first_hash = {
        let mut hasher = Md5::new();
        hasher.update(password.as_bytes());
        hasher.update(username.as_bytes());
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
    password: String,
    /// Auth message for signature verification
    auth_message: Option<String>,
    /// Salted password for server signature verification
    salted_password: Option<Vec<u8>>,
}

impl ScramClient {
    /// Create a new SCRAM client.
    pub fn new(password: &str) -> Self {
        Self::with_gs2_header(password, "n,,", &[])
    }

    /// Create a new SCRAM client with channel binding.
    pub fn new_with_channel_binding(password: &str, channel_binding_data: &[u8]) -> Self {
        Self::with_gs2_header(password, "p=tls-server-end-point,,", channel_binding_data)
    }

    pub fn new_with_unadvertised_channel_binding(password: &str) -> Self {
        Self::with_gs2_header(password, "y,,", &[])
    }

    fn with_gs2_header(
        password: &str,
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
            password: password.to_string(),
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
                iterations = value.parse().ok();
            }
        }

        let combined_nonce = combined_nonce.ok_or("Missing nonce in server-first-message")?;
        let salt_b64 = salt_b64.ok_or("Missing salt in server-first-message")?;
        let iterations: u32 = iterations.ok_or("Missing iterations in server-first-message")?;

        // Verify nonce starts with our client nonce
        if !combined_nonce.starts_with(&self.nonce) {
            return Err("Server nonce doesn't start with client nonce".to_string());
        }

        // Decode salt
        let salt = base64::engine::general_purpose::STANDARD
            .decode(salt_b64)
            .map_err(|e| format!("Invalid salt: {}", e))?;

        // Compute SaltedPassword = Hi(Normalize(password), salt, iterations)
        let mut salted_password = vec![0u8; 32];
        pbkdf2_hmac::<Sha256>(
            self.password.as_bytes(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn md5_password_hash() {
        // Test vector from PostgreSQL
        let result = md5_password("postgres", "password", &[0x01, 0x02, 0x03, 0x04]);
        assert_eq!(result, "md598511ceaec347a656f032c7f2a16ef17");
    }

    #[test]
    fn password_message() {
        let mut buf = Vec::new();
        write_password(&mut buf, "secret");

        assert_eq!(buf[0], b'p');
        // Check that password is null-terminated in the message
        assert!(buf.ends_with(&[0]));
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
            (ScramClient::new("secret"), "n,,"),
            (
                ScramClient::new_with_unadvertised_channel_binding("secret"),
                "y,,",
            ),
            (
                ScramClient::new_with_channel_binding("secret", &channel_binding_data),
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
            channel_binding_attribute(&mut ScramClient::new("secret")),
            "biws"
        );
        assert_eq!(
            channel_binding_attribute(&mut ScramClient::new_with_unadvertised_channel_binding(
                "secret"
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
            let mut scram = ScramClient::new_with_channel_binding("secret", &channel_binding_data);
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
        let mut scram = ScramClient::new_with_channel_binding("pencil", &channel_binding_data);
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
            let mut scram = ScramClient::new_with_channel_binding("secret", &channel_binding_data);
            scram.nonce = "fixednonce".to_string();
            let client_final = scram.process_server_first(server_first).unwrap();
            proofs.push(client_final.rsplit_once(",p=").unwrap().1.to_string());
        }
        assert_ne!(proofs[0], proofs[1]);
    }
}
