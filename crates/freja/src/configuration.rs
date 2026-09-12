use std::path::Path;

use freja_config::{CompiledConfig, ConfigError, RawConfig, RawListener};
use freja_domain::Port;

const BUILT_IN_HTTP_BIND: &str = "127.0.0.1:8080";

pub(super) fn compile_configuration(path: Option<&Path>) -> Result<CompiledConfig, ConfigError> {
    if let Some(path) = path {
        return CompiledConfig::load(path);
    }
    let mut raw = RawConfig::default();
    raw.listeners.push(RawListener::HttpForward {
        bind: BUILT_IN_HTTP_BIND.to_owned(),
        connect_ports: vec![Port::HTTPS.get()],
        authentication: None,
    });
    raw.validate()?.compile()
}

pub(super) fn configuration_description(path: Option<&Path>) -> String {
    match path {
        Some(path) => format!("configuration {}", path.display()),
        None => "built-in default configuration".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use freja_config::ListenerExposure;
    use freja_domain::{EnforcementMode, HookMode, ListenerSpec, Port, UiMode};

    use super::{BUILT_IN_HTTP_BIND, compile_configuration};

    #[test]
    fn built_in_configuration_is_loopback_only_and_interactive() {
        let compiled = compile_configuration(None).unwrap();

        assert_eq!(compiled.runtime().ui, UiMode::Tui);
        assert_eq!(compiled.runtime().enforcement, EnforcementMode::Observe);
        assert_eq!(compiled.runtime().hooks, HookMode::Interactive);
        assert_eq!(
            compiled.safety().listener_exposure(),
            ListenerExposure::LoopbackOnly
        );
        let [ListenerSpec::HttpForward(listener)] = compiled.listeners() else {
            panic!("built-in configuration must contain one HTTP listener");
        };
        assert_eq!(listener.bind().to_string(), BUILT_IN_HTTP_BIND);
        assert!(listener.allows_connect_port(Port::HTTPS));
        assert!(listener.authentication().is_none());
    }
}
