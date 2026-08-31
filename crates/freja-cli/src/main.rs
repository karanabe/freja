#![forbid(unsafe_code)]

use std::{
    collections::HashMap,
    error::Error,
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, BufWriter, ErrorKind, Read, Write},
    path::{Path, PathBuf},
    process::ExitCode,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use clap::{Parser, Subcommand};
use freja_audit::{
    AuditEvent, AuditPublisher, AuditRecord, CheckpointSchedule, CheckpointSigner, RecordHash,
    Redactor, drain_jsonl_with_checkpoints,
};
use freja_cli::{AppError, AppResult, ResultExt};
use freja_config::{AuditConfig, CapturePolicy, CompiledConfig, Limits, TlsConfig};
use freja_domain::{
    Decision, Direction, HookMode, ListenerSpec, Protocol, ReplayFacts, SessionId, TransactionId,
    UiMode,
};
use freja_policy::hook::{
    HookFailurePolicy, HookRegistry, HookRunner, InteractiveBroker, InterceptTimeoutPolicy,
};
use freja_policy::{PolicyFacts, StreamScanner};
use freja_proxy::{
    DataPlaneServices, HttpForwardServer, Socks5Server, StaticTcpServer, TlsInterceptor,
    shutdown_channel,
};
use freja_ui::{UiEvent, UiPublisher, tui::spawn_tui};
use tokio::task::JoinSet;
use tracing::{info, warn};
use tracing_subscriber::{EnvFilter, fmt::MakeWriter};

const MAXIMUM_REPLAY_LINE_BYTES: usize = 16 * 1024 * 1024;
const MAXIMUM_TUI_LOG_LINE_BYTES: usize = 16 * 1024;

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

async fn run_proxy_command(path: &Path) -> AppResult<()> {
    let compiled = CompiledConfig::load(path)
        .with_context(|| format!("could not compile configuration {}", path.display()))?;
    if compiled.runtime().ui == UiMode::Tui {
        let (ui, receiver) = UiPublisher::channel(compiled.limits().ui_event_capacity)
            .context("could not create bounded UI event channel")?;
        let tracing_router =
            initialize_tui_tracing(ui.clone()).context("failed to initialize TUI tracing")?;
        return run_proxy(
            path,
            compiled,
            Some(PreparedTui { ui, receiver }),
            Some(tracing_router),
        )
        .await;
    }

    initialize_tracing().context("failed to initialize tracing")?;
    run_proxy(path, compiled, None, None).await
}

struct PreparedTui {
    ui: UiPublisher,
    receiver: tokio::sync::mpsc::Receiver<UiEvent>,
}

fn replay_audit(
    audit_path: &PathBuf,
    config_path: &PathBuf,
    checkpoint_public_key: Option<&str>,
) -> AppResult<()> {
    let compiled = CompiledConfig::load(config_path).with_context(|| {
        format!(
            "could not compile replay configuration {}",
            config_path.display()
        )
    })?;
    let file = File::open(audit_path)
        .with_context(|| format!("could not open audit segment {}", audit_path.display()))?;
    let mut expected_sequence = 1_u64;
    let mut previous_hash: Option<RecordHash> = None;
    let mut decisions = 0_u64;
    let expected_checkpoint_key = checkpoint_public_key
        .map(parse_checkpoint_public_key)
        .transpose()?;
    let mut verified_checkpoints = 0_u64;
    let mut scanners = HashMap::<ReplayStreamKey, StreamScanner>::new();
    let mut reader = BufReader::new(file);
    let mut line_number = 0_usize;
    while let Some(line) = read_bounded_replay_line(&mut reader, MAXIMUM_REPLAY_LINE_BYTES)? {
        line_number = line_number.saturating_add(1);
        let record = serde_json::from_str::<AuditRecord>(&line)
            .with_context(|| format!("invalid audit JSON at line {line_number}"))?;
        validate_replay_schema(record.schema_version, line_number)?;
        if record.sequence.get() != expected_sequence
            || record.previous_hash != previous_hash
            || !record.verifies_hash()
        {
            return Err(AppError::msg(format!(
                "audit integrity verification failed at line {line_number}"
            )));
        }
        if let AuditEvent::SignedCheckpoint { checkpoint } = &record.event {
            let key_matches = expected_checkpoint_key.is_none_or(|expected| {
                hex::decode(&checkpoint.public_key_hex)
                    .is_ok_and(|actual| actual.as_slice() == expected.as_slice())
            });
            let covers_chain = previous_hash.is_some_and(|hash| {
                checkpoint.covers_sequence.get() == expected_sequence.saturating_sub(1)
                    && checkpoint.record_hash == hash
            });
            if !checkpoint.verifies() || !key_matches || !covers_chain {
                return Err(AppError::msg(format!(
                    "audit checkpoint verification failed at line {line_number}"
                )));
            }
            verified_checkpoints = verified_checkpoints.saturating_add(1);
        }
        decisions = decisions.saturating_add(replay_record(&compiled, &record, &mut scanners)?);
        previous_hash = Some(record.record_hash);
        expected_sequence = expected_sequence.saturating_add(1);
    }
    if expected_checkpoint_key.is_some() && verified_checkpoints == 0 {
        return Err(AppError::msg(
            "audit segment contains no checkpoint from the required public key",
        ));
    }
    info!(
        records = expected_sequence.saturating_sub(1),
        decisions, "offline replay completed"
    );
    Ok(())
}

fn validate_replay_schema(schema_version: u16, line_number: usize) -> AppResult<()> {
    if schema_version != 1 {
        return Err(AppError::msg(format!(
            "unsupported audit schema version {schema_version} at line {line_number}"
        )));
    }
    Ok(())
}

fn read_bounded_replay_line(
    reader: &mut impl BufRead,
    maximum_bytes: usize,
) -> AppResult<Option<String>> {
    let maximum_with_line_ending = maximum_bytes.saturating_add(2);
    let mut bytes = Vec::new();
    let mut limited = reader.take(u64::try_from(maximum_with_line_ending).unwrap_or(u64::MAX));
    let count = limited
        .read_until(b'\n', &mut bytes)
        .context("could not read audit input")?;
    if count == 0 {
        return Ok(None);
    }
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
    }
    if bytes.len() > maximum_bytes {
        return Err(AppError::msg(format!(
            "audit line exceeds the {maximum_bytes}-byte replay limit"
        )));
    }
    String::from_utf8(bytes)
        .context("audit input is not UTF-8")
        .map(Some)
}

fn parse_checkpoint_public_key(value: &str) -> AppResult<[u8; 32]> {
    let decoded = hex::decode(value).context("checkpoint public key is not hexadecimal")?;
    decoded
        .try_into()
        .map_err(|_| AppError::msg("checkpoint public key must contain exactly 32 bytes"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct ReplayStreamKey {
    session_id: SessionId,
    transaction_id: Option<TransactionId>,
    direction: Direction,
    protocol: Protocol,
}

fn replay_record(
    compiled: &CompiledConfig,
    record: &AuditRecord,
    scanners: &mut HashMap<ReplayStreamKey, StreamScanner>,
) -> AppResult<u64> {
    match &record.event {
        AuditEvent::ReplayFactsObserved { facts } => replay_facts(compiled, record, facts),
        AuditEvent::PayloadPrefixCaptured {
            direction,
            protocol,
            bytes_hex,
        } => {
            let bytes = hex::decode(bytes_hex).with_context(|| {
                format!(
                    "invalid captured bytes at sequence {}",
                    record.sequence.get()
                )
            })?;
            if bytes.len() > compiled.limits().body_prefix_bytes {
                return Err(AppError::msg(format!(
                    "captured bytes at sequence {} exceed the configured replay body-prefix limit",
                    record.sequence.get()
                )));
            }
            let key = ReplayStreamKey {
                session_id: record.session_id,
                transaction_id: record.transaction_id,
                direction: *direction,
                protocol: *protocol,
            };
            let scanner = scanners
                .entry(key)
                .or_insert_with(|| compiled.inspection().scanner(*direction));
            let mut count = 0_u64;
            for finding in scanner.inspect(&bytes) {
                let decision = compiled.inspection().evaluate(&finding, *protocol);
                emit_replay_decision(record, "captured-prefix", &decision)?;
                count = count.saturating_add(1);
            }
            Ok(count)
        }
        AuditEvent::ConnectionAccepted { .. }
        | AuditEvent::TargetResolved { .. }
        | AuditEvent::AclEvaluated { .. }
        | AuditEvent::HttpRequestObserved { .. }
        | AuditEvent::HttpResponseObserved { .. }
        | AuditEvent::ProxyAuthentication { .. }
        | AuditEvent::FindingDetected { .. }
        | AuditEvent::InspectionEvaluated { .. }
        | AuditEvent::HookExecuted { .. }
        | AuditEvent::ManualModification { .. }
        | AuditEvent::TlsCertificateGenerated { .. }
        | AuditEvent::TlsInterceptionEstablished { .. }
        | AuditEvent::ActionExecuted { .. }
        | AuditEvent::TunnelClosed { .. }
        | AuditEvent::FlowClosed { .. }
        | AuditEvent::SignedCheckpoint { .. } => Ok(0),
    }
}

fn replay_facts(
    compiled: &CompiledConfig,
    record: &AuditRecord,
    facts: &ReplayFacts,
) -> AppResult<u64> {
    let decisions = match facts {
        ReplayFacts::Requested(facts) => {
            vec![compiled.policy().evaluate(PolicyFacts::Requested(facts))]
        }
        ReplayFacts::Resolved(facts) => {
            let mut decisions = Vec::with_capacity(2);
            if let Some(decision) = compiled
                .destination_guard()
                .evaluate(compiled.policy().generation(), facts)
            {
                decisions.push(decision);
            }
            decisions.push(compiled.policy().evaluate(PolicyFacts::Resolved(facts)));
            decisions
        }
        ReplayFacts::HttpRequest(facts) => {
            vec![compiled.policy().evaluate(PolicyFacts::HttpRequest(facts))]
        }
        ReplayFacts::HttpResponse(facts) => {
            vec![compiled.policy().evaluate(PolicyFacts::HttpResponse(facts))]
        }
        ReplayFacts::Finding { finding, protocol } => {
            vec![compiled.inspection().evaluate(finding, *protocol)]
        }
    };
    for decision in &decisions {
        emit_replay_decision(record, "recorded-facts", decision)?;
    }
    Ok(u64::try_from(decisions.len()).unwrap_or(u64::MAX))
}

fn emit_replay_decision(
    record: &AuditRecord,
    source: &'static str,
    decision: &Decision,
) -> AppResult<()> {
    let output = serde_json::json!({
        "source_sequence": record.sequence,
        "session_id": record.session_id,
        "transaction_id": record.transaction_id,
        "source": source,
        "decision": decision,
    });
    let output = serde_json::to_string(&output).context("could not serialize replay decision")?;
    println!("{output}");
    Ok(())
}

fn check_config(path: &PathBuf) -> AppResult<()> {
    let compiled = CompiledConfig::load(path)
        .with_context(|| format!("could not compile configuration {}", path.display()))?;
    info!(
        listeners = compiled.listeners().len(),
        policy_generation = compiled.policy().generation().get(),
        "configuration is valid"
    );
    println!(
        "configuration valid: {} listener(s), policy generation {}",
        compiled.listeners().len(),
        compiled.policy().generation()
    );
    Ok(())
}

async fn run_proxy(
    path: &Path,
    compiled: CompiledConfig,
    tui: Option<PreparedTui>,
    tracing_router: Option<TuiTracingRouter>,
) -> AppResult<()> {
    let (audit_publisher, audit_receiver) = AuditPublisher::channel(
        compiled.audit().channel_capacity,
        compiled.audit().failure_policy,
    )
    .context("could not create bounded audit channel")?;
    let mut services = DataPlaneServices::new(
        compiled.policy().clone(),
        compiled.destination_guard().clone(),
        compiled.runtime().enforcement,
        audit_publisher,
    )
    .with_capture(compiled.capture())
    .with_inspection(compiled.inspection().clone(), compiled.inspection_mode())
    .with_hooks(HookRunner::new(
        compiled.runtime().hooks,
        HookRegistry::default(),
        compiled.limits().interception_timeout,
        HookFailurePolicy::FailClosed,
    ));
    if let Some(interceptor) = TlsInterceptor::from_config(compiled.tls())
        .context("could not initialize TLS interception")?
    {
        services = services.with_tls_interceptor(interceptor);
    }
    let mut intercept_receiver = None;
    if compiled.runtime().hooks == freja_domain::HookMode::Interactive {
        let (broker, receiver) = InteractiveBroker::channel(
            compiled.limits().ui_event_capacity,
            compiled.limits().paused_flows,
            compiled.limits().interception_timeout,
            InterceptTimeoutPolicy::FailClosed,
        )
        .context("could not create bounded interactive interception channel")?;
        services = services.with_interactive_broker(broker);
        intercept_receiver = Some(receiver);
    }
    if let Some(prepared) = tui.as_ref() {
        services = services.with_ui(prepared.ui.clone());
    }
    let servers = bind_configured_servers(&compiled, &services).await?;
    if servers.is_empty() {
        return Err(AppError::msg(
            "configuration contains no runnable listeners",
        ));
    }

    let mut audit_task = spawn_audit_writer(&compiled, audit_receiver)?;

    let (shutdown, signal) = shutdown_channel();
    let reload_task = spawn_reload_task(path.to_path_buf(), &compiled, services.clone())?;
    let (mut tui_exit, tui_thread) = if let Some(prepared) = tui {
        let metrics = prepared.ui.metrics();
        let task = spawn_tui(prepared.receiver, metrics, intercept_receiver.take())
            .context("could not start terminal UI")?;
        let (exit, thread) = task.into_parts();
        (Some(exit), Some(thread))
    } else {
        (None, None)
    };
    let mut listeners = JoinSet::new();
    for server in servers {
        listeners.spawn(server.run(signal.clone()));
    }
    let (mut first_failure, audit_completed_early) =
        wait_for_shutdown_trigger(&mut listeners, &mut tui_exit, &mut audit_task).await?;
    shutdown.shutdown();
    while let Some(joined) = listeners.join_next().await {
        if first_failure.is_none() {
            first_failure = drained_listener_failure(joined);
        }
    }
    if let Some(task) = reload_task {
        task.abort();
        let _join_result = task.await;
    }
    if let Some(router) = tracing_router.as_ref() {
        router.disconnect();
    }
    drop(services);

    if !audit_completed_early {
        let audit_result = audit_task
            .await
            .context("audit writer task failed to join")?;
        audit_result.context("audit writer failed")?;
    }
    if let Some(thread) = tui_thread {
        let result = thread
            .join()
            .map_err(|_| AppError::msg("terminal UI thread panicked"))?;
        result.context("terminal UI failed")?;
    }
    if let Some(error) = first_failure {
        return Err(error);
    }
    Ok(())
}

fn spawn_audit_writer(
    compiled: &CompiledConfig,
    audit_receiver: tokio::sync::mpsc::Receiver<freja_audit::AuditEnvelope>,
) -> AppResult<tokio::task::JoinHandle<Result<(), freja_audit::AuditError>>> {
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

fn create_audit_segment(configured_path: &Path) -> AppResult<(File, PathBuf)> {
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

#[cfg(unix)]
async fn wait_for_shutdown_signal() -> AppResult<()> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut terminate =
        signal(SignalKind::terminate()).context("failed to install SIGTERM handler")?;
    tokio::select! {
        result = tokio::signal::ctrl_c() => {
            result.context("failed to install or receive interrupt signal")
        }
        received = terminate.recv() => {
            received.ok_or_else(|| AppError::msg("SIGTERM handler closed unexpectedly"))
        }
    }
}

#[cfg(not(unix))]
async fn wait_for_shutdown_signal() -> AppResult<()> {
    tokio::signal::ctrl_c()
        .await
        .context("failed to install or receive interrupt signal")
}

#[derive(Clone)]
struct ReloadFingerprint {
    listeners: Vec<ListenerSpec>,
    limits: Limits,
    tls: TlsConfig,
    ui: UiMode,
    hooks: HookMode,
    audit: AuditConfig,
    capture: CapturePolicy,
}

impl ReloadFingerprint {
    fn from_config(config: &CompiledConfig) -> Self {
        Self {
            listeners: config.listeners().to_vec(),
            limits: config.limits(),
            tls: config.tls().clone(),
            ui: config.runtime().ui,
            hooks: config.runtime().hooks,
            audit: config.audit().clone(),
            capture: config.capture(),
        }
    }

    fn incompatibility(&self, candidate: &CompiledConfig) -> Option<&'static str> {
        if self.listeners != candidate.listeners() {
            return Some("listener topology or authentication changed");
        }
        if self.limits != candidate.limits() {
            return Some("resource limits changed");
        }
        if self.tls != *candidate.tls() {
            return Some("TLS configuration changed");
        }
        if self.ui != candidate.runtime().ui || self.hooks != candidate.runtime().hooks {
            return Some("UI or hook mode changed");
        }
        if self.audit != *candidate.audit() {
            return Some("audit sink configuration changed");
        }
        if self.capture != candidate.capture() {
            return Some("capture configuration changed");
        }
        None
    }
}

#[cfg(unix)]
fn spawn_reload_task(
    path: PathBuf,
    baseline: &CompiledConfig,
    services: DataPlaneServices,
) -> AppResult<Option<tokio::task::JoinHandle<()>>> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut hangup = signal(SignalKind::hangup()).context("failed to install SIGHUP handler")?;
    let fingerprint = ReloadFingerprint::from_config(baseline);
    Ok(Some(tokio::spawn(async move {
        while hangup.recv().await.is_some() {
            let candidate = match CompiledConfig::load(&path) {
                Ok(candidate) => candidate,
                Err(error) => {
                    warn!(error = %error, "configuration reload rejected");
                    continue;
                }
            };
            if let Some(reason) = fingerprint.incompatibility(&candidate) {
                warn!(reason, "configuration reload requires a process restart");
                continue;
            }
            let generation = candidate.policy().generation();
            services.reload(
                candidate.policy().clone(),
                candidate.destination_guard().clone(),
                candidate.runtime().enforcement,
                candidate.inspection().clone(),
                candidate.inspection_mode(),
            );
            info!(policy_generation = %generation, "configuration snapshot reloaded atomically");
        }
    })))
}

#[cfg(not(unix))]
fn spawn_reload_task(
    _path: PathBuf,
    _baseline: &CompiledConfig,
    _services: DataPlaneServices,
) -> AppResult<Option<tokio::task::JoinHandle<()>>> {
    Ok(None)
}

async fn wait_for_tui_exit(exit: &mut Option<tokio::sync::oneshot::Receiver<()>>) {
    match exit {
        Some(exit) => {
            let _exit_result = exit.await;
        }
        None => std::future::pending::<()>().await,
    }
}

async fn wait_for_shutdown_trigger(
    listeners: &mut JoinSet<Result<(), freja_proxy::ProxyError>>,
    tui_exit: &mut Option<tokio::sync::oneshot::Receiver<()>>,
    audit_task: &mut tokio::task::JoinHandle<Result<(), freja_audit::AuditError>>,
) -> AppResult<(Option<AppError>, bool)> {
    let mut audit_completed_early = false;
    let failure = tokio::select! {
        signal_result = wait_for_shutdown_signal() => {
            signal_result?;
            None
        }
        joined = listeners.join_next() => Some(early_listener_failure(joined)),
        () = wait_for_tui_exit(tui_exit) => None,
        joined = audit_task => {
            audit_completed_early = true;
            Some(early_audit_writer_failure(joined))
        }
    };
    Ok((failure, audit_completed_early))
}

async fn bind_configured_servers(
    compiled: &CompiledConfig,
    services: &DataPlaneServices,
) -> AppResult<Vec<BoundServer>> {
    let mut servers = Vec::new();
    for listener in compiled.listeners() {
        match listener {
            ListenerSpec::TcpStatic(specification) => {
                let server = StaticTcpServer::bind(
                    specification.clone(),
                    services.clone(),
                    compiled.limits(),
                )
                .await
                .with_context(|| {
                    format!(
                        "could not bind static TCP listener {}",
                        specification.bind()
                    )
                })?;
                info!(
                    bind = %server.local_address(),
                    upstream = %specification.upstream(),
                    "static TCP listener bound"
                );
                servers.push(BoundServer::Tcp(server));
            }
            ListenerSpec::HttpForward(specification) => {
                let server = HttpForwardServer::bind(
                    specification.clone(),
                    services.clone(),
                    compiled.limits(),
                )
                .await
                .with_context(|| {
                    format!(
                        "could not bind HTTP forward listener {}",
                        specification.bind()
                    )
                })?;
                info!(
                    bind = %server.local_address(),
                    "HTTP/1 explicit forward listener bound"
                );
                servers.push(BoundServer::Http(server));
            }
            ListenerSpec::Socks5(specification) => {
                let server =
                    Socks5Server::bind(specification.clone(), services.clone(), compiled.limits())
                        .await
                        .with_context(|| {
                            format!("could not bind SOCKS5 listener {}", specification.bind())
                        })?;
                info!(bind = %server.local_address(), "SOCKS5 listener bound");
                servers.push(BoundServer::Socks5(server));
            }
        }
    }
    Ok(servers)
}

fn early_listener_failure(
    joined: Option<Result<Result<(), freja_proxy::ProxyError>, tokio::task::JoinError>>,
) -> AppError {
    match joined {
        Some(Ok(Ok(()))) => AppError::msg("listener exited before shutdown was requested"),
        Some(Ok(Err(error))) => AppError::new(error).context("listener failed"),
        Some(Err(error)) => AppError::new(error).context("listener task failed to join"),
        None => AppError::msg("all listener tasks stopped unexpectedly"),
    }
}

fn early_audit_writer_failure(
    joined: Result<Result<(), freja_audit::AuditError>, tokio::task::JoinError>,
) -> AppError {
    match joined {
        Ok(Ok(())) => AppError::msg("audit writer exited unexpectedly"),
        Ok(Err(error)) => AppError::new(error).context("audit writer failed"),
        Err(error) => AppError::new(error).context("audit writer task failed to join"),
    }
}

fn drained_listener_failure(
    joined: Result<Result<(), freja_proxy::ProxyError>, tokio::task::JoinError>,
) -> Option<AppError> {
    match joined {
        Ok(Ok(())) => None,
        Ok(Err(error)) => Some(AppError::new(error).context("listener failed during shutdown")),
        Err(error) => Some(AppError::new(error).context("listener task failed to join")),
    }
}

#[derive(Clone)]
struct TuiTracingRouter {
    publisher: Arc<Mutex<Option<UiPublisher>>>,
}

impl TuiTracingRouter {
    fn new(publisher: UiPublisher) -> Self {
        Self {
            publisher: Arc::new(Mutex::new(Some(publisher))),
        }
    }

    fn publish(&self, message: String) {
        let Ok(publisher) = self.publisher.lock() else {
            return;
        };
        let Some(publisher) = publisher.as_ref() else {
            return;
        };
        let _outcome = publisher.try_publish(UiEvent::OperationalLog { message });
    }

    fn disconnect(&self) {
        if let Ok(mut publisher) = self.publisher.lock() {
            publisher.take();
        }
    }
}

impl<'writer> MakeWriter<'writer> for TuiTracingRouter {
    type Writer = TuiTracingWriter;

    fn make_writer(&'writer self) -> Self::Writer {
        TuiTracingWriter {
            router: self.clone(),
            bytes: Vec::new(),
            truncated: false,
        }
    }
}

struct TuiTracingWriter {
    router: TuiTracingRouter,
    bytes: Vec<u8>,
    truncated: bool,
}

#[derive(Debug)]
struct TracingInitializationError {
    source: Box<dyn Error + Send + Sync + 'static>,
}

impl std::fmt::Display for TracingInitializationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("could not install the tracing subscriber")
    }
}

impl Error for TracingInitializationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.source.as_ref())
    }
}

impl Write for TuiTracingWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let available = MAXIMUM_TUI_LOG_LINE_BYTES.saturating_sub(self.bytes.len());
        let copied = available.min(bytes.len());
        self.bytes.extend_from_slice(&bytes[..copied]);
        self.truncated |= copied < bytes.len();
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Drop for TuiTracingWriter {
    fn drop(&mut self) {
        let raw = String::from_utf8_lossy(&self.bytes);
        let mut message = raw
            .trim()
            .chars()
            .map(|character| match character {
                '\r' | '\n' => ' ',
                character => character,
            })
            .collect::<String>();
        if self.truncated {
            message.push('…');
        }
        if !message.is_empty() {
            self.router.publish(message);
        }
    }
}

fn tracing_filter() -> EnvFilter {
    match EnvFilter::try_from_default_env() {
        Ok(filter) => filter,
        Err(_) => EnvFilter::new("info"),
    }
}

fn initialize_tui_tracing(
    publisher: UiPublisher,
) -> Result<TuiTracingRouter, TracingInitializationError> {
    let router = TuiTracingRouter::new(publisher);
    tracing_subscriber::fmt()
        .with_ansi(false)
        .with_env_filter(tracing_filter())
        .with_writer(router.clone())
        .try_init()
        .map_err(|source| TracingInitializationError { source })?;
    Ok(router)
}

fn initialize_tracing() -> Result<(), TracingInitializationError> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_filter())
        .try_init()
        .map_err(|source| TracingInitializationError { source })?;
    Ok(())
}

fn print_error(error: &AppError) {
    eprintln!("error: {error}");
    let mut source = error.source();
    while let Some(cause) = source {
        eprintln!("  caused by: {cause}");
        source = cause.source();
    }
}

enum BoundServer {
    Tcp(StaticTcpServer),
    Http(HttpForwardServer),
    Socks5(Socks5Server),
}

impl BoundServer {
    async fn run(
        self,
        shutdown: freja_proxy::ShutdownSignal,
    ) -> Result<(), freja_proxy::ProxyError> {
        match self {
            Self::Tcp(server) => server.run(shutdown).await,
            Self::Http(server) => server.run(shutdown).await,
            Self::Socks5(server) => server.run(shutdown).await,
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
