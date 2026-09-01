use std::{
    fs::{File, OpenOptions},
    io::{BufWriter, ErrorKind},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use freja::{AppError, AppResult, ResultExt};
use freja_audit::{
    AuditEnvelope, AuditError, CheckpointSchedule, CheckpointSigner, Redactor,
    drain_jsonl_with_checkpoints,
};
use freja_config::CompiledConfig;
use tokio::{sync::mpsc, task::JoinHandle};
use tracing::info;

pub(super) fn spawn_audit_writer(
    compiled: &CompiledConfig,
    audit_receiver: mpsc::Receiver<AuditEnvelope>,
) -> AppResult<JoinHandle<Result<(), AuditError>>> {
    let (audit_file, audit_path) = create_audit_segment(&compiled.audit().path)?;
    info!(path = %audit_path.display(), "audit segment created");
    let redactor = Redactor::new(compiled.audit().redact_query_parameters.clone());
    let checkpoint = match &compiled.audit().checkpoint_signing_key {
        Some(path) => {
            let signer = CheckpointSigner::load_hex_seed(path).with_context(|| {
                format!("could not load audit checkpoint key {}", path.display())
            })?;
            Some(
                CheckpointSchedule::new(signer, compiled.audit().checkpoint_interval)
                    .context("could not configure audit checkpoints")?,
            )
        }
        None => None,
    };
    Ok(tokio::task::spawn_blocking(move || {
        drain_jsonl_with_checkpoints(
            audit_receiver,
            BufWriter::new(audit_file),
            redactor,
            checkpoint.as_ref(),
        )
    }))
}

pub(super) fn create_audit_segment(configured_path: &Path) -> AppResult<(File, PathBuf)> {
    if !configured_path.is_dir() {
        let file = open_new_audit_segment(configured_path).with_context(|| {
            format!(
                "could not create new audit segment {}",
                configured_path.display()
            )
        })?;
        return Ok((file, configured_path.to_owned()));
    }

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_millis();
    for collision in 0_u8..100 {
        let name = format!(
            "freja-{timestamp}-{}-{collision:02}.jsonl",
            std::process::id()
        );
        let path = configured_path.join(name);
        match open_new_audit_segment(&path) {
            Ok(file) => return Ok((file, path)),
            Err(source) if source.kind() == ErrorKind::AlreadyExists => {}
            Err(source) => {
                return Err(AppError::new(source).context(format!(
                    "could not create an audit segment in {}",
                    configured_path.display()
                )));
            }
        }
    }
    Err(AppError::msg(format!(
        "could not allocate a unique audit segment name in {}",
        configured_path.display()
    )))
}

fn open_new_audit_segment(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    options.open(path)
}
