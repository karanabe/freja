#[cfg(test)]
use crate::TlsInterceptionConfig;

const ALPN_HTTP_2: &[u8] = b"h2";
const ALPN_HTTP_1_1: &[u8] = b"http/1.1";

mod cache;
mod error;
mod interceptor;
mod material;

pub use error::TlsError;
pub use interceptor::TlsInterceptor;

#[cfg(test)]
mod tests {
    use freja_domain::{HostName, SessionId, TargetHost};
    use freja_policy::HostPattern;
    use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose};
    use rustls::RootCertStore;

    use super::{ALPN_HTTP_1_1, TlsError, TlsInterceptionConfig, TlsInterceptor};

    fn test_interceptor(capacity: usize) -> TlsInterceptor {
        let key = KeyPair::generate().expect("generate CA key");
        let mut parameters = CertificateParams::default();
        parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        parameters.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let certificate = parameters.self_signed(&key).expect("generate CA cert");
        TlsInterceptor::from_material(
            &certificate.pem(),
            &key.serialize_pem(),
            vec![HostPattern::Suffix(
                HostName::new("example.test").expect("valid host"),
            )],
            capacity,
            RootCertStore::empty(),
        )
        .expect("build interceptor")
    }

    #[test]
    fn allowlist_is_label_bounded_and_excludes_ip_literals() {
        let interceptor = test_interceptor(2);
        assert!(
            interceptor
                .should_intercept(&TargetHost::parse("api.example.test").expect("valid target"))
        );
        assert!(
            !interceptor
                .should_intercept(&TargetHost::parse("badexample.test").expect("valid target"))
        );
        assert!(
            !interceptor.should_intercept(&TargetHost::parse("127.0.0.1").expect("valid target"))
        );
    }

    #[test]
    fn leaf_cache_is_bounded_and_reports_hits() {
        let interceptor = test_interceptor(1);
        let first = TargetHost::parse("one.example.test").expect("valid target");
        let second = TargetHost::parse("two.example.test").expect("valid target");
        assert!(
            !interceptor
                .downstream_acceptor(&first, Some(ALPN_HTTP_1_1))
                .expect("generate first")
                .1
        );
        assert!(
            interceptor
                .downstream_acceptor(&first, Some(ALPN_HTTP_1_1))
                .expect("reuse first")
                .1
        );
        assert!(
            !interceptor
                .downstream_acceptor(&second, Some(ALPN_HTTP_1_1))
                .expect("generate second")
                .1
        );
        assert!(
            !interceptor
                .downstream_acceptor(&first, Some(ALPN_HTTP_1_1))
                .expect("first was evicted")
                .1
        );
    }

    #[cfg(unix)]
    #[test]
    fn group_readable_ca_private_key_is_rejected_before_parsing() {
        use std::{fs, os::unix::fs::PermissionsExt};

        let directory =
            std::env::temp_dir().join(format!("freja-insecure-ca-test-{}", SessionId::new()));
        fs::create_dir(&directory).expect("create test directory");
        let private_key = directory.join("ca-key.pem");
        fs::write(&private_key, "not-secret-test-material").expect("write test key");
        fs::set_permissions(&private_key, fs::Permissions::from_mode(0o640))
            .expect("set insecure permissions");
        let config = TlsInterceptionConfig::new(
            directory.join("missing-ca.pem"),
            private_key,
            vec![HostPattern::Exact(
                HostName::new("example.test").expect("valid host"),
            )],
            1,
        )
        .expect("valid interception settings");

        let error = TlsInterceptor::from_config(&config).expect_err("permissions must fail");
        assert!(matches!(
            error,
            TlsError::InsecurePrivateKeyPermissions { mode: 0o640, .. }
        ));
        fs::remove_dir_all(directory).expect("remove test directory");
    }
}
