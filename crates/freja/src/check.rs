use std::path::Path;

use freja::{AppResult, ResultExt};
use tracing::info;

use super::configuration::{compile_configuration, configuration_description};

pub(super) fn check_config(path: Option<&Path>) -> AppResult<()> {
    let compiled = compile_configuration(path)
        .with_context(|| format!("could not compile {}", configuration_description(path)))?;
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
