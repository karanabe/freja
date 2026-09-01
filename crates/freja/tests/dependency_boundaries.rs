use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    process::Command,
};

use serde_json::Value;

#[test]
fn workspace_crates_follow_the_declared_dependency_direction() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../Cargo.toml");
    let output = Command::new(env!("CARGO"))
        .args(["metadata", "--format-version", "1", "--no-deps"])
        .arg("--manifest-path")
        .arg(&manifest)
        .output()
        .expect("run cargo metadata");
    assert!(
        output.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let metadata: Value = serde_json::from_slice(&output.stdout).expect("parse cargo metadata");
    let packages = metadata["packages"]
        .as_array()
        .expect("metadata packages are an array");
    let allowed = allowed_workspace_dependencies();

    for package in packages {
        let name = package["name"].as_str().expect("package has a name");
        let Some(allowed_dependencies) = allowed.get(name) else {
            continue;
        };
        let dependencies = package["dependencies"]
            .as_array()
            .expect("package dependencies are an array");
        let actual_workspace_dependencies = dependencies
            .iter()
            .filter_map(|dependency| dependency["name"].as_str())
            .filter(|dependency| allowed.contains_key(*dependency))
            .collect::<BTreeSet<_>>();

        assert_eq!(
            &actual_workspace_dependencies, allowed_dependencies,
            "workspace dependency boundary changed for {name}"
        );
        if name != "freja-proxy" {
            assert!(
                dependencies.iter().all(|dependency| {
                    !dependency["name"]
                        .as_str()
                        .is_some_and(|dependency| dependency.starts_with("pingora"))
                }),
                "Pingora dependency escaped freja-proxy into {name}"
            );
        }
    }
}

fn allowed_workspace_dependencies() -> BTreeMap<&'static str, BTreeSet<&'static str>> {
    BTreeMap::from([
        ("freja-domain", BTreeSet::from([])),
        ("freja-policy", BTreeSet::from(["freja-domain"])),
        ("freja-audit", BTreeSet::from(["freja-domain"])),
        (
            "freja-config",
            BTreeSet::from(["freja-audit", "freja-domain", "freja-policy"]),
        ),
        ("freja-ui", BTreeSet::from(["freja-domain", "freja-policy"])),
        (
            "freja-proxy",
            BTreeSet::from(["freja-audit", "freja-domain", "freja-policy"]),
        ),
        (
            "freja",
            BTreeSet::from([
                "freja-audit",
                "freja-config",
                "freja-domain",
                "freja-policy",
                "freja-proxy",
                "freja-ui",
            ]),
        ),
    ])
}
