use std::path::PathBuf;

use freja::{AppResult, ResultExt};
use freja_config::CompiledConfig;
use tracing::info;

pub(super) fn check_config(path: &PathBuf) -> AppResult<()> {
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
