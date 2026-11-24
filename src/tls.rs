use std::sync::{Arc, OnceLock};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use rustls_platform_verifier::BuilderVerifierExt;
use sha2::{Digest, Sha224, Sha256, Sha384, Sha512};
use x509_cert::Certificate;
use x509_cert::der::oid::ObjectIdentifier;
use x509_cert::der::oid::db::rfc5912::{
    ECDSA_WITH_SHA_224, ECDSA_WITH_SHA_256, ECDSA_WITH_SHA_384, ECDSA_WITH_SHA_512, ID_MD_5,
    ID_MGF_1, ID_RSASSA_PSS, ID_SHA_1, ID_SHA_224, ID_SHA_256, ID_SHA_384, ID_SHA_512,
    MD_5_WITH_RSA_ENCRYPTION, SHA_1_WITH_RSA_ENCRYPTION, SHA_224_WITH_RSA_ENCRYPTION,
    SHA_256_WITH_RSA_ENCRYPTION, SHA_384_WITH_RSA_ENCRYPTION, SHA_512_WITH_RSA_ENCRYPTION,
};
use x509_cert::der::{Any, Decode, Reader, TagMode, TagNumber};
use x509_cert::spki::AlgorithmIdentifierOwned;

use crate::error::{Error, Result};
use crate::opts::Opts;

pub fn client_config(opts: &Opts) -> Result<Arc<ClientConfig>> {
    match &opts.tls_config {
        Some(config) => Ok(Arc::clone(config)),
        None if opts.tls_mode.requires_certificate_verification() => platform_client_config(),
        None => unverified_client_config(),
    }
}

fn platform_client_config() -> Result<Arc<ClientConfig>> {
    static CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    if let Some(config) = CONFIG.get() {
        return Ok(Arc::clone(config));
    }
    let config = Arc::new(
        ClientConfig::builder_with_provider(crypto_provider())
            .with_safe_default_protocol_versions()?
            .with_platform_verifier()?
            .with_no_client_auth(),
    );
    Ok(Arc::clone(CONFIG.get_or_init(|| config)))
}

fn unverified_client_config() -> Result<Arc<ClientConfig>> {
    static CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    if let Some(config) = CONFIG.get() {
        return Ok(Arc::clone(config));
    }
    let provider = crypto_provider();
    let config = Arc::new(
        ClientConfig::builder_with_provider(Arc::clone(&provider))
            .with_safe_default_protocol_versions()?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoCertificateVerification { provider }))
            .with_no_client_auth(),
    );
    Ok(Arc::clone(CONFIG.get_or_init(|| config)))
}

fn crypto_provider() -> Arc<CryptoProvider> {
    // An explicit provider avoids a panic when both aws-lc-rs and ring are
    // enabled in the dependency graph and no process default is installed.
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

#[derive(Debug)]
struct NoCertificateVerification {
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

pub fn server_name(host: &str) -> Result<ServerName<'static>> {
    ServerName::try_from(host.to_owned())
        .map_err(|e| Error::InvalidUsage(format!("invalid TLS server name {host:?}: {e}")))
}

pub fn tls_server_end_point(certificate: &CertificateDer<'_>) -> Option<Vec<u8>> {
    let parsed_certificate = Certificate::from_der(certificate).ok()?;
    let signature_algorithm = parsed_certificate.signature_algorithm();
    let hash_algorithm = match signature_algorithm.oid {
        MD_5_WITH_RSA_ENCRYPTION => ID_MD_5,
        SHA_1_WITH_RSA_ENCRYPTION => ID_SHA_1,
        SHA_224_WITH_RSA_ENCRYPTION | ECDSA_WITH_SHA_224 => ID_SHA_224,
        SHA_256_WITH_RSA_ENCRYPTION | ECDSA_WITH_SHA_256 => ID_SHA_256,
        SHA_384_WITH_RSA_ENCRYPTION | ECDSA_WITH_SHA_384 => ID_SHA_384,
        SHA_512_WITH_RSA_ENCRYPTION | ECDSA_WITH_SHA_512 => ID_SHA_512,
        ID_RSASSA_PSS => rsassa_pss_hash_algorithm(signature_algorithm.parameters.as_ref()?)?,
        _ => return None,
    };
    match hash_algorithm {
        ID_MD_5 | ID_SHA_1 | ID_SHA_256 => Some(Sha256::digest(certificate).to_vec()),
        ID_SHA_224 => Some(Sha224::digest(certificate).to_vec()),
        ID_SHA_384 => Some(Sha384::digest(certificate).to_vec()),
        ID_SHA_512 => Some(Sha512::digest(certificate).to_vec()),
        _ => None,
    }
}

fn rsassa_pss_hash_algorithm(parameters: &Any) -> Option<ObjectIdentifier> {
    let (hash_algorithm, mask_gen_algorithm) = parameters
        .sequence(|reader| {
            let hash_algorithm = reader
                .context_specific::<AlgorithmIdentifierOwned>(TagNumber(0), TagMode::Explicit)?;
            let mask_gen_algorithm = reader
                .context_specific::<AlgorithmIdentifierOwned>(TagNumber(1), TagMode::Explicit)?;
            reader.read_slice(reader.remaining_len())?;
            Ok::<_, x509_cert::der::Error>((hash_algorithm, mask_gen_algorithm))
        })
        .ok()?;
    let hash_algorithm = hash_algorithm.map_or(ID_SHA_1, |algorithm| algorithm.oid);
    let mask_gen_hash_algorithm = match mask_gen_algorithm {
        Some(algorithm) if algorithm.oid == ID_MGF_1 => {
            algorithm
                .parameters?
                .decode_as::<AlgorithmIdentifierOwned>()
                .ok()?
                .oid
        }
        Some(_) => return None,
        None => ID_SHA_1,
    };
    (hash_algorithm == mask_gen_hash_algorithm).then_some(hash_algorithm)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;

    pub(crate) const ECDSA_SHA256_CERTIFICATE: &str = "MIIBbjCCAROgAwIBAgIUasFTZMaMUPyZ0QsjJUXoQBrtl+kwCgYIKoZIzj0EAwIwDDEKMAgGA1UEAwwBdDAeFw0yNjExMjQxMjAyMjZaFw0zNjExMjExMjAyMjZaMAwxCjAIBgNVBAMMAXQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAStZtOX3fJzpojISPph9ASAaYnVthqzXp6H0NpWKOPzJO0rDw9NV7luz5GGw6+IzdbHkdymddjJww5WFMjVGe7mo1MwUTAdBgNVHQ4EFgQUjY9ho5Q7UwbhRjpmjkd+GPwCL7kwHwYDVR0jBBgwFoAUjY9ho5Q7UwbhRjpmjkd+GPwCL7kwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNJADBGAiEAwYHeOfV8e+LZRkPrN54YtRK3Z77nzZNWl+XPEx8qm/gCIQCCHiR9ohH1MyZSkL5Mu2mBu2JfW4q29eDgRB8xsURQjA==";
    pub(crate) const ECDSA_SHA256_END_POINT: &str = "uOaTl9N0AszO9Xq50+zSSqtTcvdgy2WoIwLIpvRQwKI=";

    const ECDSA_SHA384_CERTIFICATE: &str = "MIIBbTCCAROgAwIBAgIUWBbjmLp4i1+Vz+6fxjE9IaUnNl0wCgYIKoZIzj0EAwMwDDEKMAgGA1UEAwwBdDAeFw0yNjExMjQxMjAyMjZaFw0zNjExMjExMjAyMjZaMAwxCjAIBgNVBAMMAXQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAStZtOX3fJzpojISPph9ASAaYnVthqzXp6H0NpWKOPzJO0rDw9NV7luz5GGw6+IzdbHkdymddjJww5WFMjVGe7mo1MwUTAdBgNVHQ4EFgQUjY9ho5Q7UwbhRjpmjkd+GPwCL7kwHwYDVR0jBBgwFoAUjY9ho5Q7UwbhRjpmjkd+GPwCL7kwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAwNIADBFAiEApki8wjwMWM8hrgB4zlZCFI76qy9/IyXGh+KVr5oYTZkCIDn3j24kXHeKmP76Wenz6wFEWCJQ24tr+JEZkNWco0qV";
    const ECDSA_SHA384_END_POINT: &str =
        "3bJ+x7Vld4HoJruu/z3f5fmN+KDo6iVHfs7D2qMpnXmdMsd8WAnBxP5BfqBKxVhq";

    const ECDSA_SHA512_CERTIFICATE: &str = "MIIBbTCCAROgAwIBAgIUNM8k5xZ+fVLzO7mGBywKmrxfWnIwCgYIKoZIzj0EAwQwDDEKMAgGA1UEAwwBdDAeFw0yNjExMjQxMjAyMjZaFw0zNjExMjExMjAyMjZaMAwxCjAIBgNVBAMMAXQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAStZtOX3fJzpojISPph9ASAaYnVthqzXp6H0NpWKOPzJO0rDw9NV7luz5GGw6+IzdbHkdymddjJww5WFMjVGe7mo1MwUTAdBgNVHQ4EFgQUjY9ho5Q7UwbhRjpmjkd+GPwCL7kwHwYDVR0jBBgwFoAUjY9ho5Q7UwbhRjpmjkd+GPwCL7kwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDBANIADBFAiEAk63vdkPOOMgtf6ZvPWPmt5znPS+IcNg/9EsCJIVamSMCIA5ruX/ifu4AeHfbeTY/YVEW6K5Z1El48xfMmMhRdM5U";
    const ECDSA_SHA512_END_POINT: &str =
        "dtI+xnLxSSpPYFjFk74gpU+KFtemmyrbucJJBBQMyL3lYaLjXSWrCUzBWXTqR3SKBh44FxNE6R3mP++tirfTNg==";

    const RSA_SHA256_CERTIFICATE: &str = "MIIB9DCCAV2gAwIBAgIUSosdcOqNowour/G35w8U46MFeqYwDQYJKoZIhvcNAQELBQAwDDEKMAgGA1UEAwwBdDAeFw0yNjExMjQxMjAyMjZaFw0zNjExMjExMjAyMjZaMAwxCjAIBgNVBAMMAXQwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAN2CgxzffyEMf1HklxiErM3zAIQuLiSpUhdnr4NC99Btlp0oziXXUE0zlADp+t+ASKsQ51gU0wNhfM9kf2wkNLcvBqaN3MDaXr78NL9NrmxaV8JfdtMMPpnW/nK3hAchK8GtsuzH7YFCC/+LUiAoUZOAdCGd1bhD17RbigK4LnD1AgMBAAGjUzBRMB0GA1UdDgQWBBTtWZM7zFYMXuGnKLEWie0SN2flXjAfBgNVHSMEGDAWgBTtWZM7zFYMXuGnKLEWie0SN2flXjAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4GBAK90e5aajlFtBZC7AQbgve1MPP/tO8wGxvX+olrrSt5qzB0OOFWFGo2gnHGtEFH+YyaQLGw+9xHpCvTNeJLjJlDVJB7LMv+luDdVx+kRVnaYTLJ1iBtWiWtcMYuhVWTwYb38IwZe8Pd4cDbt655gjKiTxQOLCLIZezdGLRSljw3v";
    const RSA_SHA256_END_POINT: &str = "3Jh/GMRofKru7lb0QyNh7efpkoNUga4lDWrqczZokqw=";

    const RSA_SHA1_CERTIFICATE: &str = "MIIB9DCCAV2gAwIBAgIUHt+arhdme9FGK2jJBG+ubgoAdWcwDQYJKoZIhvcNAQEFBQAwDDEKMAgGA1UEAwwBdDAeFw0yNjExMjQxMjAyMjZaFw0zNjExMjExMjAyMjZaMAwxCjAIBgNVBAMMAXQwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAN2CgxzffyEMf1HklxiErM3zAIQuLiSpUhdnr4NC99Btlp0oziXXUE0zlADp+t+ASKsQ51gU0wNhfM9kf2wkNLcvBqaN3MDaXr78NL9NrmxaV8JfdtMMPpnW/nK3hAchK8GtsuzH7YFCC/+LUiAoUZOAdCGd1bhD17RbigK4LnD1AgMBAAGjUzBRMB0GA1UdDgQWBBTtWZM7zFYMXuGnKLEWie0SN2flXjAfBgNVHSMEGDAWgBTtWZM7zFYMXuGnKLEWie0SN2flXjAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBBQUAA4GBALWLbMdCZ8AS44qKZA1JvTjjGQM+uz2QbD8WTpin5fmOLouASrExn/ZVMGrjxGr3jhh6cYGT4ZblGEbgJ1FCOOHwhwVPuJB0RX4l0TfcQofm6AB56qokgDh4hmQTkbFv1KLY8tcsqaOsbYfHNA78lve2LaHXsjHXQAponVKhaZRF";
    const RSA_SHA1_END_POINT: &str = "Qv47MT4jLNH88nKB6NZ12QARNmv8lLn7OF8iVnIO3Eo=";

    const RSA_PSS_SHA256_CERTIFICATE: &str = "MIICXDCCAZGgAwIBAgIUQ4sg8QNhlYeBS12rXsuumrdqqBgwQQYJKoZIhvcNAQEKMDSgDzANBglghkgBZQMEAgEFAKEcMBoGCSqGSIb3DQEBCDANBglghkgBZQMEAgEFAKIDAgEgMAwxCjAIBgNVBAMMAXQwHhcNMjYxMTI0MTY1NjIwWhcNMzYxMTIxMTY1NjIwWjAMMQowCAYDVQQDDAF0MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDILK/kWkzAmZRMbtMIJBrcKPxiedu1u478Axn/DScYdjYjUeyVorppdVdWzzc3/PK01WfmlmEQbBBgrYFP2ymCAxRzhMDDp3agQ3CAUwNhuwv+2hpH2MJGbtDHs8ve1IOkSJP5Dad7cL9+vUX6NfUUebKlXJFP7QChSLWCAq7KAQIDAQABo1MwUTAdBgNVHQ4EFgQU2xwnge2rLO8rtQk/kPynuXmOdaMwHwYDVR0jBBgwFoAU2xwnge2rLO8rtQk/kPynuXmOdaMwDwYDVR0TAQH/BAUwAwEB/zBBBgkqhkiG9w0BAQowNKAPMA0GCWCGSAFlAwQCAQUAoRwwGgYJKoZIhvcNAQEIMA0GCWCGSAFlAwQCAQUAogMCASADgYEAb8nsbXFJ+d2iOhbSY8goh8Jyw5QxmKRxsN/OcL4yRI3nVuMdufgxZbKarD0CQNVnAfiyW9Tm7ZI7KGHiLv13PjR3hq1VrQLutd2FXqryssK0Y5VHSmxP//ox9K/UOmTAygOc41B8MiM4t9evNqQwmEtxbBJ5z0BYXp1Js7TN+pA=";
    const RSA_PSS_SHA256_END_POINT: &str = "X5YPg0TzrFDG9nGH+iH3FExV5nOpSmrPoR5v6T9um4g=";

    const RSA_PSS_SHA384_CERTIFICATE: &str = "MIICXDCCAZGgAwIBAgIUeh0wupM7qppweWX217/T5AiZNV0wQQYJKoZIhvcNAQEKMDSgDzANBglghkgBZQMEAgIFAKEcMBoGCSqGSIb3DQEBCDANBglghkgBZQMEAgIFAKIDAgEwMAwxCjAIBgNVBAMMAXQwHhcNMjYxMTI0MTY1NjIwWhcNMzYxMTIxMTY1NjIwWjAMMQowCAYDVQQDDAF0MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDILK/kWkzAmZRMbtMIJBrcKPxiedu1u478Axn/DScYdjYjUeyVorppdVdWzzc3/PK01WfmlmEQbBBgrYFP2ymCAxRzhMDDp3agQ3CAUwNhuwv+2hpH2MJGbtDHs8ve1IOkSJP5Dad7cL9+vUX6NfUUebKlXJFP7QChSLWCAq7KAQIDAQABo1MwUTAdBgNVHQ4EFgQU2xwnge2rLO8rtQk/kPynuXmOdaMwHwYDVR0jBBgwFoAU2xwnge2rLO8rtQk/kPynuXmOdaMwDwYDVR0TAQH/BAUwAwEB/zBBBgkqhkiG9w0BAQowNKAPMA0GCWCGSAFlAwQCAgUAoRwwGgYJKoZIhvcNAQEIMA0GCWCGSAFlAwQCAgUAogMCATADgYEAIhD1vcPpxiNw3R2TdbehzkRcJ3tlM5TJypc9j7ixUskgLzZGNOXy7JPOi9z1hr/3YR2dFzZPCW2232vkQmyrAYNRVCpDHRHkbNnlSUwHI8nFLfZHvpmqK8kbtoeLtcPUv1ow66z70v7WlfKyse1MoPOwINzcwZBbA5H5CpSybdk=";
    const RSA_PSS_SHA384_END_POINT: &str =
        "jdbd1xkTdINFfGTrR6jgqO4z+i+Aep2hzX8eiaSKVjj9A4/V5g9Ws4L6anqmbHWN";

    const RSA_PSS_SHA512_CERTIFICATE: &str = "MIIDYTCCAhWgAwIBAgIUEjIrMo2XWXzRkIdKEazsCbKFVGswQQYJKoZIhvcNAQEKMDSgDzANBglghkgBZQMEAgMFAKEcMBoGCSqGSIb3DQEBCDANBglghkgBZQMEAgMFAKIDAgFAMAwxCjAIBgNVBAMMAXQwHhcNMjYxMTI0MTY1NjM1WhcNMzYxMTIxMTY1NjM1WjAMMQowCAYDVQQDDAF0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzeml6lhbOW4zh4BFRDH1kQF1T/cLJw4LPhB1xz5KXWPzkfft9LRFtWTWZmBxJFamp6XMFJpC/Aajo/UvOROI9CLx8z97SAHchN9zK7sUvDynF17AGbdiEgQw2UvPvFM4mmiFtrW+pLwYeO7lCWvMwbhAbWXEgktPiZ2hhhptYf38fcL9GJYf92jxxcUCU9z6wwZ9Mjy8apkcz+ipMkrH3Lyn1kfJlkdoGm0XAaDETECjlj7mQ/ykpnrcq9nnNFrrVO/YqBr64xomZW1I7LbBphqOXMzFvr25VZxdyG0kykd2G7slCLIbAVrHPlHfwQAm9sslkwSxclWFgRNbPaAfaQIDAQABo1MwUTAdBgNVHQ4EFgQUAwkByZURZzSfqX16tfH8lNaAh44wHwYDVR0jBBgwFoAUAwkByZURZzSfqX16tfH8lNaAh44wDwYDVR0TAQH/BAUwAwEB/zBBBgkqhkiG9w0BAQowNKAPMA0GCWCGSAFlAwQCAwUAoRwwGgYJKoZIhvcNAQEIMA0GCWCGSAFlAwQCAwUAogMCAUADggEBAIeHsyUy7mShi44NRKtVHUUPo5rJ8Pp1CvytTXSx1EfeC4OyZaDBVhoRwpaQbsxA6ywXqfhqsSjiysuDVh0m8PWtHfbY8ki7T0YCm/3/8G8jAgemhLRm7H2ycaOsTjfV9VidjuYUkoM6EQXR3QPw/EAINEO0h+YFeXQfXySOOS3PIizsMM7xI+2HaeQJ6EM4q8SgTiJXUuKOAGNoykYXi82qaAPCdtHynSipsFvNxBFE93royldaFeMH/E/38NZZAzSRzLEthxfIYsin5WKqGr004i/Q+PCIO6VSS5H68J3h1+YlLJY2doVjhUsM/QUHWSk/Gm+VsZL5pBoVWY+yDkM=";
    const RSA_PSS_SHA512_END_POINT: &str =
        "flFY5bsfKy08V2/bTvSdWBNQRnFhJtV+gXxZESyZ1E7fNkwTWaVrQYiZuHP8im6AuY/fs+JdwVHaovVLntIyqQ==";

    const RSA_PSS_SHA1_CERTIFICATE: &str = "MIIB9DCCAV2gAwIBAgIUbiK8AEUlAzpj3KnFOmF/h2iJSVowDQYJKoZIhvcNAQEKMAAwDDEKMAgGA1UEAwwBdDAeFw0yNjExMjQxNjU2MjBaFw0zNjExMjExNjU2MjBaMAwxCjAIBgNVBAMMAXQwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMgsr+RaTMCZlExu0wgkGtwo/GJ527W7jvwDGf8NJxh2NiNR7JWiuml1V1bPNzf88rTVZ+aWYRBsEGCtgU/bKYIDFHOEwMOndqBDcIBTA2G7C/7aGkfYwkZu0Mezy97Ug6RIk/kNp3twv369Rfo19RR5sqVckU/tAKFItYICrsoBAgMBAAGjUzBRMB0GA1UdDgQWBBTbHCeB7ass7yu1CT+Q/Ke5eY51ozAfBgNVHSMEGDAWgBTbHCeB7ass7yu1CT+Q/Ke5eY51ozAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCjAAA4GBACtYlCmZCCnhfoFhHVVLgMplVOzt7J9/WmBefaQeuRomZtrBFpmC8r2of4yKZb+3496kLT/4ybzNkECXGiKbznGak5Nz0ZWcsO2Y6j+UAzi+H318UYNbpjR8SkdghYe835/VpRGS4WoVJzoekPZ83ltNPHHi5BYw111N/1vlg/CN";
    const RSA_PSS_SHA1_END_POINT: &str = "rKxqiskED/zEtafwna1Yf6EmvtCCc7A/aNKuJFEiHSc=";

    const RSA_PSS_MIXED_HASH_CERTIFICATE: &str = "MIICXDCCAZGgAwIBAgIUSf0Eqyx4TOCVSmpHdFakmcsXS1owQQYJKoZIhvcNAQEKMDSgDzANBglghkgBZQMEAgEFAKEcMBoGCSqGSIb3DQEBCDANBglghkgBZQMEAgIFAKIDAgEgMAwxCjAIBgNVBAMMAXQwHhcNMjYxMTI0MTY1NjIwWhcNMzYxMTIxMTY1NjIwWjAMMQowCAYDVQQDDAF0MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDILK/kWkzAmZRMbtMIJBrcKPxiedu1u478Axn/DScYdjYjUeyVorppdVdWzzc3/PK01WfmlmEQbBBgrYFP2ymCAxRzhMDDp3agQ3CAUwNhuwv+2hpH2MJGbtDHs8ve1IOkSJP5Dad7cL9+vUX6NfUUebKlXJFP7QChSLWCAq7KAQIDAQABo1MwUTAdBgNVHQ4EFgQU2xwnge2rLO8rtQk/kPynuXmOdaMwHwYDVR0jBBgwFoAU2xwnge2rLO8rtQk/kPynuXmOdaMwDwYDVR0TAQH/BAUwAwEB/zBBBgkqhkiG9w0BAQowNKAPMA0GCWCGSAFlAwQCAQUAoRwwGgYJKoZIhvcNAQEIMA0GCWCGSAFlAwQCAgUAogMCASADgYEAieLp7GQ/Bb4zatBs3K+WQ7KsNZAYCwo10PU4Pm2OkozNwXWvOeTBoGHB/Cj+/yxYqln/H1Q4IboMEob2aufdXy1+44B98hwsnLK55kJjLfwE8U+dtw50kL7ZJr23tQaqLX6UQTUHg92KRUIXvZ9cg5YDAfcTES6dQO6OMvrge8g=";

    pub(crate) const ED25519_CERTIFICATE: &str = "MIIBLDCB36ADAgECAhQP41jlX5clwMzHyiXLxwDG9a7awTAFBgMrZXAwDDEKMAgGA1UEAwwBdDAeFw0yNjExMjQxMjAyMjZaFw0zNjExMjExMjAyMjZaMAwxCjAIBgNVBAMMAXQwKjAFBgMrZXADIQC9PCz1tfRaOXpWBjIcz6s5FGEykzOZGmXWVEMRH5Yza6NTMFEwHQYDVR0OBBYEFJCBKQpCDsK6JlYvrmPllhcep6cHMB8GA1UdIwQYMBaAFJCBKQpCDsK6JlYvrmPllhcep6cHMA8GA1UdEwEB/wQFMAMBAf8wBQYDK2VwA0EAnE9mLmQCfY4BlySSz/MafQ93G1o4VppD360iXX45jdYFjcx+r+PkI/UnFvBs2sZe4+a4McU+ZFzHz8f4D99IBQ==";

    fn decode(encoded: &str) -> Vec<u8> {
        STANDARD.decode(encoded).unwrap()
    }

    fn end_point_of(encoded_certificate: &str) -> Option<Vec<u8>> {
        tls_server_end_point(&CertificateDer::from(decode(encoded_certificate)))
    }

    #[test]
    fn ecdsa_with_sha256_hashes_with_sha256() {
        let end_point = end_point_of(ECDSA_SHA256_CERTIFICATE).unwrap();
        assert_eq!(end_point.len(), 32);
        assert_eq!(end_point, decode(ECDSA_SHA256_END_POINT));
    }

    #[test]
    fn ecdsa_with_sha384_hashes_with_sha384() {
        let end_point = end_point_of(ECDSA_SHA384_CERTIFICATE).unwrap();
        assert_eq!(end_point.len(), 48);
        assert_eq!(end_point, decode(ECDSA_SHA384_END_POINT));
    }

    #[test]
    fn ecdsa_with_sha512_hashes_with_sha512() {
        let end_point = end_point_of(ECDSA_SHA512_CERTIFICATE).unwrap();
        assert_eq!(end_point.len(), 64);
        assert_eq!(end_point, decode(ECDSA_SHA512_END_POINT));
    }

    #[test]
    fn sha256_with_rsa_hashes_with_sha256() {
        let end_point = end_point_of(RSA_SHA256_CERTIFICATE).unwrap();
        assert_eq!(end_point.len(), 32);
        assert_eq!(end_point, decode(RSA_SHA256_END_POINT));
    }

    #[test]
    fn sha1_with_rsa_upgrades_to_sha256() {
        let end_point = end_point_of(RSA_SHA1_CERTIFICATE).unwrap();
        assert_eq!(end_point.len(), 32);
        assert_eq!(end_point, decode(RSA_SHA1_END_POINT));
    }

    #[test]
    fn rsa_pss_sha256_hashes_with_sha256() {
        let end_point = end_point_of(RSA_PSS_SHA256_CERTIFICATE).unwrap();
        assert_eq!(end_point.len(), 32);
        assert_eq!(end_point, decode(RSA_PSS_SHA256_END_POINT));
    }

    #[test]
    fn rsa_pss_sha384_hashes_with_sha384() {
        let end_point = end_point_of(RSA_PSS_SHA384_CERTIFICATE).unwrap();
        assert_eq!(end_point.len(), 48);
        assert_eq!(end_point, decode(RSA_PSS_SHA384_END_POINT));
    }

    #[test]
    fn rsa_pss_sha512_hashes_with_sha512() {
        let end_point = end_point_of(RSA_PSS_SHA512_CERTIFICATE).unwrap();
        assert_eq!(end_point.len(), 64);
        assert_eq!(end_point, decode(RSA_PSS_SHA512_END_POINT));
    }

    #[test]
    fn rsa_pss_default_sha1_upgrades_to_sha256() {
        let end_point = end_point_of(RSA_PSS_SHA1_CERTIFICATE).unwrap();
        assert_eq!(end_point.len(), 32);
        assert_eq!(end_point, decode(RSA_PSS_SHA1_END_POINT));
    }

    #[test]
    fn rsa_pss_mixed_hash_has_no_end_point() {
        assert_eq!(end_point_of(RSA_PSS_MIXED_HASH_CERTIFICATE), None);
    }

    #[test]
    fn ed25519_has_no_end_point() {
        assert_eq!(end_point_of(ED25519_CERTIFICATE), None);
    }

    #[test]
    fn non_certificate_bytes_have_no_end_point() {
        assert_eq!(
            tls_server_end_point(&CertificateDer::from(b"not a certificate".to_vec())),
            None
        );
        assert_eq!(
            tls_server_end_point(&CertificateDer::from(Vec::new())),
            None
        );
    }

    use crate::opts::TlsMode;
    use rustls::internal::msgs::codec::{Codec, Reader};

    fn user_tls_config() -> Arc<ClientConfig> {
        let provider = crypto_provider();
        Arc::new(
            ClientConfig::builder_with_provider(Arc::clone(&provider))
                .with_safe_default_protocol_versions()
                .unwrap()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoCertificateVerification { provider }))
                .with_no_client_auth(),
        )
    }

    fn no_certificate_verification() -> NoCertificateVerification {
        NoCertificateVerification {
            provider: crypto_provider(),
        }
    }

    fn digitally_signed(scheme: u16, signature: &[u8]) -> DigitallySignedStruct {
        let mut encoded = scheme.to_be_bytes().to_vec();
        encoded.extend_from_slice(&(signature.len() as u16).to_be_bytes());
        encoded.extend_from_slice(signature);
        DigitallySignedStruct::read(&mut Reader::init(&encoded)).unwrap()
    }

    #[test]
    fn client_config_returns_user_tls_config_for_every_tls_mode() {
        let config = user_tls_config();
        for tls_mode in TlsMode::ALL {
            let opts = Opts {
                tls_mode,
                tls_config: Some(Arc::clone(&config)),
                ..Opts::default()
            };
            let first = client_config(&opts).unwrap();
            let second = client_config(&opts).unwrap();
            assert!(Arc::ptr_eq(&first, &config), "{tls_mode:?}");
            assert!(Arc::ptr_eq(&second, &config), "{tls_mode:?}");
        }
    }

    #[test]
    fn client_config_shares_unverified_config_without_certificate_verification() {
        let insecure = Opts::default();
        let channel_binding = Opts {
            tls_mode: TlsMode::ChannelBinding,
            ..Opts::default()
        };
        let first = client_config(&insecure).unwrap();
        let second = client_config(&insecure).unwrap();
        let third = client_config(&channel_binding).unwrap();
        assert!(Arc::ptr_eq(&first, &second));
        assert!(Arc::ptr_eq(&first, &third));
        assert!(Arc::ptr_eq(&first, &unverified_client_config().unwrap()));
        assert!(!Arc::ptr_eq(&first, &user_tls_config()));
    }

    #[test]
    fn client_config_shares_platform_config_with_certificate_verification() {
        let pki = Opts {
            tls_mode: TlsMode::Pki,
            ..Opts::default()
        };
        let hardened = Opts {
            tls_mode: TlsMode::Hardened,
            ..Opts::default()
        };
        let first = client_config(&pki).unwrap();
        let second = client_config(&hardened).unwrap();
        assert!(Arc::ptr_eq(&first, &second));
        assert!(!Arc::ptr_eq(&first, &unverified_client_config().unwrap()));
    }

    #[test]
    fn no_certificate_verification_accepts_any_certificate() {
        let verifier = no_certificate_verification();
        let server_name = server_name("db.example.test").unwrap();
        for certificate in [
            decode(ECDSA_SHA256_CERTIFICATE),
            decode(ED25519_CERTIFICATE),
            b"not a certificate".to_vec(),
            Vec::new(),
        ] {
            verifier
                .verify_server_cert(
                    &CertificateDer::from(certificate),
                    &[CertificateDer::from(b"garbage".to_vec())],
                    &server_name,
                    b"ocsp",
                    UnixTime::since_unix_epoch(std::time::Duration::ZERO),
                )
                .unwrap();
        }
    }

    #[test]
    fn no_certificate_verification_still_checks_handshake_signatures() {
        let verifier = no_certificate_verification();
        let certificate = CertificateDer::from(decode(ECDSA_SHA256_CERTIFICATE));
        let dss = digitally_signed(0x0403, &[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01]);
        verifier
            .verify_tls12_signature(b"handshake", &certificate, &dss)
            .unwrap_err();
        verifier
            .verify_tls13_signature(b"handshake", &certificate, &dss)
            .unwrap_err();

        let garbage_certificate = CertificateDer::from(b"not a certificate".to_vec());
        verifier
            .verify_tls13_signature(b"handshake", &garbage_certificate, &dss)
            .unwrap_err();
    }

    #[test]
    fn no_certificate_verification_supports_provider_schemes() {
        let verifier = no_certificate_verification();
        let schemes = verifier.supported_verify_schemes();
        assert!(!schemes.is_empty());
        assert!(schemes.contains(&SignatureScheme::ECDSA_NISTP256_SHA256));
        assert!(schemes.contains(&SignatureScheme::ED25519));
        assert!(schemes.contains(&SignatureScheme::RSA_PSS_SHA256));
    }
}
