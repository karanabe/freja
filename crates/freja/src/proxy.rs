use std::path::{Path, PathBuf};

use freja::{AppError, AppResult, ResultExt};
use freja_audit::AuditPublisher;
use freja_config::{AuditConfig, CapturePolicy, CompiledConfig, Limits, TlsConfig};
use freja_domain::{HookMode, ListenerSpec, UiMode};
use freja_policy::hook::{
    HookFailurePolicy, HookRegistry, HookRunner, InteractiveBroker, InterceptTimeoutPolicy,
};
use freja_proxy::{
    CaptureSettings, DataPlaneServices, HttpForwardServer, HttpRepeatExecutor, ProxyLimits,
    Socks5Server, StaticTcpServer, TlsInterceptionConfig, TlsInterceptor, UiCaptureSettings,
    shutdown_channel,
};
use freja_ui::{UiEvent, UiPublisher, tui::spawn_tui};
use tokio::task::JoinSet;
use tracing::{info, warn};

use crate::ui_adapter::UiDataPlaneEventSink;

use super::{
    audit_writer::spawn_audit_writer,
    configuration::{compile_configuration, configuration_description},
    tracing_setup::{TuiTracingRouter, initialize_tracing, initialize_tui_tracing},
};

pub(super) async fn run_proxy_command(path: Option<&Path>) -> AppResult<()> {
    let compiled = compile_configuration(path)
        .with_context(|| format!("could not compile {}", configuration_description(path)))?;
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

#[allow(clippy::too_many_lines)]
async fn run_proxy(
    path: Option<&Path>,
    compiled: CompiledConfig,
    tui: Option<PreparedTui>,
    tracing_router: Option<TuiTracingRouter>,
) -> AppResult<()> {
    info!(source = %configuration_description(path), "runtime configuration selected");
    let proxy_limits = proxy_limits(compiled.limits())?;
    let capture = capture_settings(compiled.capture())?;
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
    .with_capture(capture)
    .with_inspection(compiled.inspection().clone(), compiled.inspection_mode())
    .with_hooks(HookRunner::new(
        compiled.runtime().hooks,
        HookRegistry::default(),
        compiled.limits().interception_timeout,
        HookFailurePolicy::FailClosed,
    ));
    if let Some(interceptor) = tls_interceptor(compiled.tls())? {
        services = services.with_tls_interceptor(interceptor);
    }
    let mut intercept_receiver = None;
    if compiled.runtime().hooks == HookMode::Interactive {
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
    services = attach_tui_services(services, &compiled, tui.as_ref())?;
    let (repeat_executor, repeat_sender, repeat_result_receiver) =
        prepare_repeat_services(&compiled, &services, proxy_limits);
    let servers = bind_configured_servers(&compiled, &services, proxy_limits).await?;
    if servers.is_empty() {
        return Err(AppError::msg(
            "configuration contains no runnable listeners",
        ));
    }

    let mut audit_task = spawn_audit_writer(&compiled, audit_receiver)?;

    let (shutdown, signal) = shutdown_channel();
    let reload_task = spawn_reload_task(path.map(Path::to_path_buf), &compiled, services.clone())?;
    let (mut tui_exit, tui_thread) = if let Some(prepared) = tui {
        let metrics = prepared.ui.metrics();
        let task = spawn_tui(
            prepared.receiver,
            metrics,
            intercept_receiver.take(),
            repeat_sender,
            repeat_result_receiver,
            compiled.limits().ui_retained_rows,
        )
        .context("could not start terminal UI")?;
        let (exit, thread) = task.into_parts();
        (Some(exit), Some(thread))
    } else {
        (None, None)
    };
    let mut listeners = JoinSet::new();
    if let Some(executor) = repeat_executor {
        listeners.spawn(executor.run(signal.clone()));
    }
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

type PreparedRepeat = (
    Option<HttpRepeatExecutor>,
    Option<tokio::sync::mpsc::Sender<freja_policy::hook::RepeatRequest>>,
    Option<tokio::sync::mpsc::Receiver<freja_policy::hook::RepeatResult>>,
);

fn prepare_repeat_services(
    compiled: &CompiledConfig,
    services: &DataPlaneServices,
    limits: ProxyLimits,
) -> PreparedRepeat {
    if compiled.runtime().hooks != HookMode::Interactive {
        return (None, None, None);
    }
    let capacity = compiled.limits().ui_retained_rows;
    let (request_sender, request_receiver) = tokio::sync::mpsc::channel(capacity);
    let (result_sender, result_receiver) = tokio::sync::mpsc::channel(capacity);
    (
        Some(HttpRepeatExecutor::new(
            request_receiver,
            result_sender,
            services.clone(),
            limits,
        )),
        Some(request_sender),
        Some(result_receiver),
    )
}

fn attach_tui_services(
    services: DataPlaneServices,
    compiled: &CompiledConfig,
    tui: Option<&PreparedTui>,
) -> AppResult<DataPlaneServices> {
    let Some(prepared) = tui else {
        return Ok(services);
    };
    let ui_capture = UiCaptureSettings::new(
        compiled.limits().ui_content_bytes,
        compiled.limits().ui_retained_rows,
    )
    .context("compiled configuration contains invalid TUI capture limits")?;
    Ok(services
        .with_ui_capture(ui_capture)
        .with_event_sink(UiDataPlaneEventSink::new(prepared.ui.clone())))
}

fn proxy_limits(limits: Limits) -> AppResult<ProxyLimits> {
    ProxyLimits::new(
        limits.connections,
        limits.header_bytes,
        limits.body_prefix_bytes,
        limits.connect_timeout,
        limits.read_timeout,
        limits.idle_timeout,
    )
    .context("compiled configuration contains invalid proxy limits")
}

fn capture_settings(capture: CapturePolicy) -> AppResult<CaptureSettings> {
    match capture {
        CapturePolicy::MetadataOnly => Ok(CaptureSettings::metadata_only()),
        CapturePolicy::Prefix { max_bytes } => CaptureSettings::prefix(max_bytes)
            .context("compiled configuration contains an invalid capture bound"),
    }
}

fn tls_interceptor(config: &TlsConfig) -> AppResult<Option<TlsInterceptor>> {
    let TlsConfig::Intercept {
        ca_certificate,
        ca_private_key,
        intercept_hosts,
        leaf_cache_entries,
    } = config
    else {
        return Ok(None);
    };
    let settings = TlsInterceptionConfig::new(
        ca_certificate.clone(),
        ca_private_key.clone(),
        intercept_hosts.clone(),
        *leaf_cache_entries,
    )
    .context("compiled configuration contains invalid TLS interception settings")?;
    TlsInterceptor::from_config(&settings)
        .map(Some)
        .context("could not initialize TLS interception")
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
    path: Option<PathBuf>,
    baseline: &CompiledConfig,
    services: DataPlaneServices,
) -> AppResult<Option<tokio::task::JoinHandle<()>>> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut hangup = signal(SignalKind::hangup()).context("failed to install SIGHUP handler")?;
    let fingerprint = ReloadFingerprint::from_config(baseline);
    Ok(Some(tokio::spawn(async move {
        while hangup.recv().await.is_some() {
            let Some(path) = path.as_ref() else {
                warn!("configuration reload ignored while using built-in defaults");
                continue;
            };
            let candidate = match CompiledConfig::load(path) {
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
    _path: Option<PathBuf>,
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
    limits: ProxyLimits,
) -> AppResult<Vec<BoundServer>> {
    let mut servers = Vec::new();
    for listener in compiled.listeners() {
        match listener {
            ListenerSpec::TcpStatic(specification) => {
                let server = StaticTcpServer::bind(specification.clone(), services.clone(), limits)
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
                let server =
                    HttpForwardServer::bind(specification.clone(), services.clone(), limits)
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
                let server = Socks5Server::bind(specification.clone(), services.clone(), limits)
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
