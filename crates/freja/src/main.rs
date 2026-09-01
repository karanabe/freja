#![forbid(unsafe_code)]

mod ui_adapter;

use std::{path::PathBuf, process::ExitCode};

use clap::{Parser, Subcommand};
use freja::{AppResult, ResultExt};

const MAXIMUM_REPLAY_LINE_BYTES: usize = 16 * 1024 * 1024;
const MAXIMUM_TUI_LOG_LINE_BYTES: usize = 16 * 1024;

mod audit_writer;
mod check;
mod proxy;
mod replay;
mod tracing_setup;

use check::check_config;
use proxy::run_proxy_command;
use replay::replay_audit;
use tracing_setup::{initialize_tracing, print_error};

#[cfg(test)]
use audit_writer::create_audit_segment;
#[cfg(test)]
use replay::{read_bounded_replay_line, validate_replay_schema};
#[cfg(test)]
use tracing_setup::TuiTracingRouter;

#[derive(Debug, Parser)]
#[command(
    name = "freja",
    version,
    about = "Local-first explainable inspection proxy"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Parse, validate, and compile a configuration without opening listeners.
    CheckConfig {
        #[arg(short, long)]
        config: PathBuf,
    },
    /// Run configured proxy listeners.
    Run {
        #[arg(short, long)]
        config: PathBuf,
    },
    /// Verify and evaluate recorded facts/captured prefixes with a candidate configuration.
    Replay {
        #[arg(short, long)]
        audit: PathBuf,
        #[arg(short, long)]
        config: PathBuf,
        /// Require signed checkpoints from this 32-byte Ed25519 public key (hex).
        #[arg(long)]
        checkpoint_public_key: Option<String>,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            print_error(&error);
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> AppResult<()> {
    match cli.command {
        Command::CheckConfig { config } => {
            initialize_tracing().context("failed to initialize tracing")?;
            check_config(&config)
        }
        Command::Run { config } => run_proxy_command(&config).await,
        Command::Replay {
            audit,
            config,
            checkpoint_public_key,
        } => {
            initialize_tracing().context("failed to initialize tracing")?;
            replay_audit(&audit, &config, checkpoint_public_key.as_deref())
        }
    }
}
#[cfg(test)]
mod tests {
    use std::{fs, io::Cursor, io::Write as _};

    use freja_domain::SessionId;
    use freja_ui::{UiEvent, UiPublisher};
    use tracing_subscriber::fmt::MakeWriter as _;

    use super::{
        TuiTracingRouter, create_audit_segment, read_bounded_replay_line, validate_replay_schema,
    };

    #[test]
    fn replay_line_reader_rejects_oversized_input_before_json_parsing() {
        let mut input = Cursor::new(b"12345\n".as_slice());

        let error = read_bounded_replay_line(&mut input, 4).unwrap_err();

        assert!(error.to_string().contains("4-byte replay limit"));
    }

    #[test]
    fn replay_line_reader_excludes_line_endings_from_the_limit() {
        for ending in ["\n", "\r\n"] {
            let mut input = Cursor::new(format!("1234{ending}"));
            assert_eq!(
                read_bounded_replay_line(&mut input, 4).unwrap().as_deref(),
                Some("1234")
            );
        }
    }

    #[test]
    fn replay_rejects_unknown_schema_versions_explicitly() {
        let error = validate_replay_schema(2, 7).unwrap_err();

        assert_eq!(
            error.to_string(),
            "unsupported audit schema version 2 at line 7"
        );
    }

    #[test]
    fn audit_directory_allocates_a_fresh_segment_for_each_start() {
        let directory =
            std::env::temp_dir().join(format!("freja-audit-segment-test-{}", SessionId::new()));
        fs::create_dir(&directory).unwrap();

        let (first, first_path) = create_audit_segment(&directory).unwrap();
        drop(first);
        let (second, second_path) = create_audit_segment(&directory).unwrap();
        drop(second);

        assert_ne!(first_path, second_path);
        assert!(first_path.exists());
        assert!(second_path.exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            let mode = fs::metadata(&first_path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn exact_audit_path_is_never_overwritten() {
        let directory =
            std::env::temp_dir().join(format!("freja-audit-file-test-{}", SessionId::new()));
        fs::create_dir(&directory).unwrap();
        let path = directory.join("audit.jsonl");
        fs::write(&path, "retained").unwrap();

        assert!(create_audit_segment(&path).is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), "retained");
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn tui_tracing_routes_one_normalized_line_and_disconnects() {
        let (publisher, mut receiver) = UiPublisher::channel(1).unwrap();
        let router = TuiTracingRouter::new(publisher);
        {
            let mut writer = router.make_writer();
            writer.write_all(b"listener bound\nnext field\r\n").unwrap();
        }

        let event = receiver.try_recv().unwrap();
        assert!(matches!(
            event,
            UiEvent::OperationalLog { message }
                if message == "listener bound next field"
        ));

        router.disconnect();
        assert!(matches!(
            receiver.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected)
        ));
    }
}
