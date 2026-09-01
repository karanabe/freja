use super::error::TlsInput;
use std::{fs, path::Path};

use super::TlsError;

pub(super) fn read_text(path: &Path, input: TlsInput) -> Result<String, TlsError> {
    fs::read_to_string(path).map_err(|source| TlsError::ReadInput {
        input: match input {
            TlsInput::Certificate => "CA certificate",
            TlsInput::PrivateKey => "CA private key",
        },
        path: path.to_path_buf(),
        source,
    })
}

#[cfg(unix)]
pub(super) fn validate_private_key_permissions(path: &Path) -> Result<(), TlsError> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = fs::metadata(path).map_err(|source| TlsError::ReadInput {
        input: "CA private key metadata",
        path: path.to_path_buf(),
        source,
    })?;
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(TlsError::InsecurePrivateKeyPermissions {
            path: path.to_path_buf(),
            mode,
        });
    }
    Ok(())
}

#[cfg(not(unix))]
pub(super) fn validate_private_key_permissions(_path: &Path) -> Result<(), TlsError> {
    Ok(())
}
