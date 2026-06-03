use raxcell_protocol::{
    BackendFamily, EnforcementSpec, FallbackSpec, PolicyPack, PolicyPreset, PolicyProfile,
    PolicyResolutionReport, PolicyResolutionWarning, ResolveProfileRequest,
    ResolvedProfileResponse,
};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PolicyResolutionError {
    #[error("policy pack path is required")]
    EmptyPackPaths,
    #[error("failed to read policy pack `{path}`: {source}")]
    ReadPack {
        path: String,
        source: std::io::Error,
    },
    #[error("unsupported policy pack format for `{path}`")]
    UnsupportedFormat { path: String },
    #[error("failed to parse policy pack `{path}`: {message}")]
    ParsePack { path: String, message: String },
    #[error("duplicate policy pack name `{name}`")]
    DuplicatePackName { name: String },
    #[error("policy pack `{pack}` extends missing pack `{parent}`")]
    MissingParent { pack: String, parent: String },
    #[error("policy pack inheritance cycle: {cycle}")]
    Cycle { cycle: String },
    #[error("profile `{profile}` was not found")]
    MissingProfile { profile: String },
    #[error("profile `{profile}` cannot be resolved: {message}")]
    ProfileConflict { profile: String, message: String },
    #[error("missing profile variable `{variable}`")]
    MissingVariable { variable: String },
}

pub fn resolve_profile(
    request: ResolveProfileRequest,
) -> Result<ResolvedProfileResponse, PolicyResolutionError> {
    if request.pack_paths.is_empty() {
        return Err(PolicyResolutionError::EmptyPackPaths);
    }
    let packs = load_packs(&request.pack_paths)?;
    let pack_names: Vec<String> = packs.iter().map(|pack| pack.name.clone()).collect();
    let pack_map = build_pack_map(&packs)?;
    let target = packs
        .iter()
        .rev()
        .find(|pack| pack.profiles.contains_key(&request.profile))
        .ok_or_else(|| PolicyResolutionError::MissingProfile {
            profile: request.profile.clone(),
        })?;
    let mut resolver = Resolver {
        pack_map,
        profile: request.profile.clone(),
        variables: request.variables,
        report: PolicyResolutionReport {
            packs: pack_names,
            merge: Vec::new(),
            warnings: Vec::new(),
        },
    };
    let profile = resolver.resolve_profile_in_pack(&target.name, &mut Vec::new())?;
    let normalized = normalize_profile(profile)?;
    let enforcement = resolver.lower_enforcement(&request.profile, &normalized)?;
    Ok(ResolvedProfileResponse {
        kind: "raxcell.resolvedProfile.v1".to_string(),
        profile: request.profile,
        enforcement,
        backend_preference: normalized.backend_preference,
        fallback: normalized.fallback,
        report: resolver.report,
    })
}

fn load_packs(paths: &[String]) -> Result<Vec<PolicyPack>, PolicyResolutionError> {
    paths
        .iter()
        .map(|path| {
            let content = std::fs::read_to_string(path).map_err(|source| {
                PolicyResolutionError::ReadPack {
                    path: path.clone(),
                    source,
                }
            })?;
            parse_pack(path, &content)
        })
        .collect()
}

fn parse_pack(path: &str, content: &str) -> Result<PolicyPack, PolicyResolutionError> {
    let pack: PolicyPack = match Path::new(path)
        .extension()
        .and_then(|extension| extension.to_str())
    {
        Some("json") => {
            serde_json::from_str(content).map_err(|err| PolicyResolutionError::ParsePack {
                path: path.to_string(),
                message: err.to_string(),
            })?
        }
        Some("yaml" | "yml") => {
            yaml_serde::from_str(content).map_err(|err| PolicyResolutionError::ParsePack {
                path: path.to_string(),
                message: err.to_string(),
            })?
        }
        Some("toml") => {
            toml::from_str(content).map_err(|err| PolicyResolutionError::ParsePack {
                path: path.to_string(),
                message: err.to_string(),
            })?
        }
        _ => {
            return Err(PolicyResolutionError::UnsupportedFormat {
                path: path.to_string(),
            });
        }
    };
    if pack.kind != "raxcell.policyPack.v1" {
        return Err(PolicyResolutionError::ParsePack {
            path: path.to_string(),
            message: format!("unsupported policy pack kind `{}`", pack.kind),
        });
    }
    Ok(pack)
}

fn build_pack_map(
    packs: &[PolicyPack],
) -> Result<BTreeMap<String, PolicyPack>, PolicyResolutionError> {
    let mut pack_map = BTreeMap::new();
    for pack in packs {
        if pack_map.insert(pack.name.clone(), pack.clone()).is_some() {
            return Err(PolicyResolutionError::DuplicatePackName {
                name: pack.name.clone(),
            });
        }
    }
    Ok(pack_map)
}

struct Resolver {
    pack_map: BTreeMap<String, PolicyPack>,
    profile: String,
    variables: BTreeMap<String, String>,
    report: PolicyResolutionReport,
}

impl Resolver {
    fn resolve_profile_in_pack(
        &mut self,
        pack_name: &str,
        stack: &mut Vec<String>,
    ) -> Result<PolicyProfile, PolicyResolutionError> {
        if stack.iter().any(|name| name == pack_name) {
            let mut cycle = stack.clone();
            cycle.push(pack_name.to_string());
            return Err(PolicyResolutionError::Cycle {
                cycle: cycle.join(" -> "),
            });
        }
        let pack = self.pack_map.get(pack_name).cloned().ok_or_else(|| {
            PolicyResolutionError::MissingParent {
                pack: stack
                    .last()
                    .cloned()
                    .unwrap_or_else(|| pack_name.to_string()),
                parent: pack_name.to_string(),
            }
        })?;
        stack.push(pack.name.clone());
        let mut resolved = None;
        for parent in &pack.extends {
            if !self.pack_map.contains_key(parent) {
                return Err(PolicyResolutionError::MissingParent {
                    pack: pack.name.clone(),
                    parent: parent.clone(),
                });
            }
            let parent_profile = self.resolve_profile_in_pack(parent, stack)?;
            resolved = Some(match resolved {
                Some(current) => self.merge_profiles(current, parent_profile)?,
                None => parent_profile,
            });
        }
        if let Some(profile) = pack.profiles.get(&self.profile) {
            resolved = Some(match resolved {
                Some(current) => self.merge_profiles(current, profile.clone())?,
                None => profile.clone(),
            });
            self.report.merge.push(format!(
                "merged `{}` from pack `{}`",
                self.profile, pack.name
            ));
        }
        stack.pop();
        resolved.ok_or_else(|| PolicyResolutionError::MissingProfile {
            profile: self.profile.clone(),
        })
    }

    fn merge_profiles(
        &self,
        current: PolicyProfile,
        next: PolicyProfile,
    ) -> Result<PolicyProfile, PolicyResolutionError> {
        let current = normalize_profile(current)?;
        let next = normalize_profile(next)?;
        Ok(PolicyProfile {
            preset: stricter_preset(&current.preset, &next.preset),
            filesystem: merge_filesystem(current.filesystem, next.filesystem),
            network: merge_network(current.network, next.network, &self.profile)?,
            process: merge_process(current.process, next.process, &self.profile)?,
            resources: merge_resources(current.resources, next.resources, &self.profile)?,
            backend_preference: merge_backend_preference(
                current.backend_preference,
                next.backend_preference,
                &self.profile,
            )?,
            fallback: merge_fallback(current.fallback, next.fallback, &self.profile)?,
        })
    }

    fn lower_enforcement(
        &mut self,
        profile_name: &str,
        profile: &PolicyProfile,
    ) -> Result<EnforcementSpec, PolicyResolutionError> {
        let mut filesystem = profile.filesystem.clone();
        for roots in filesystem.values_mut() {
            for root in roots {
                *root = self.expand_variables(root)?;
            }
        }
        Ok(EnforcementSpec {
            profile: profile_name.to_string(),
            filesystem,
            network: profile.network.clone(),
            process: profile.process.clone(),
            resources: profile.resources.clone(),
        })
    }

    fn expand_variables(&mut self, value: &str) -> Result<String, PolicyResolutionError> {
        if !value.starts_with('$') {
            return Ok(value.to_string());
        }
        let (variable, suffix) = value
            .split_once('/')
            .map(|(variable, suffix)| (variable, format!("/{suffix}")))
            .unwrap_or((value, String::new()));
        let variable_name = variable.trim_start_matches('$');
        let Some(root) = self.variables.get(variable_name) else {
            return Err(PolicyResolutionError::MissingVariable {
                variable: variable.to_string(),
            });
        };
        if !matches!(variable_name, "workspace" | "home" | "tmp") {
            self.report.warnings.push(PolicyResolutionWarning {
                code: "NAMED_RUNTIME_ROOT".to_string(),
                message: format!(
                    "variable `{variable}` is treated as a caller-supplied named runtime root"
                ),
            });
        }
        Ok(format!("{root}{suffix}"))
    }
}

fn normalize_profile(mut profile: PolicyProfile) -> Result<PolicyProfile, PolicyResolutionError> {
    apply_preset_defaults(&mut profile);
    if profile.preset == PolicyPreset::NoFilesystemWrite
        && profile
            .filesystem
            .get("write")
            .is_some_and(|roots| !roots.is_empty())
    {
        return Err(PolicyResolutionError::ProfileConflict {
            profile: "no-filesystem-write".to_string(),
            message: "`no-filesystem-write` cannot declare writable roots".to_string(),
        });
    }
    if profile.preset == PolicyPreset::HostObserved && profile.backend_preference.is_empty() {
        profile.backend_preference = vec![BackendFamily::HostObserved];
    }
    Ok(profile)
}

fn apply_preset_defaults(profile: &mut PolicyProfile) {
    match profile.preset {
        PolicyPreset::WorkspaceWrite => {
            default_filesystem_root(&mut profile.filesystem, "read", "$workspace");
            default_filesystem_root(&mut profile.filesystem, "write", "$workspace");
        }
        PolicyPreset::WorkspaceReadonly | PolicyPreset::NoFilesystemWrite => {
            default_filesystem_root(&mut profile.filesystem, "read", "$workspace");
            profile.filesystem.entry("write".to_string()).or_default();
        }
        PolicyPreset::HostObserved => {
            profile.filesystem.entry("read".to_string()).or_default();
            profile.filesystem.entry("write".to_string()).or_default();
        }
    }
}

fn default_filesystem_root(filesystem: &mut BTreeMap<String, Vec<String>>, key: &str, value: &str) {
    filesystem
        .entry(key.to_string())
        .or_insert_with(|| vec![value.to_string()]);
}

fn stricter_preset(current: &PolicyPreset, next: &PolicyPreset) -> PolicyPreset {
    if preset_rank(next) > preset_rank(current) {
        next.clone()
    } else {
        current.clone()
    }
}

fn preset_rank(preset: &PolicyPreset) -> u8 {
    match preset {
        PolicyPreset::WorkspaceWrite => 1,
        PolicyPreset::WorkspaceReadonly => 2,
        PolicyPreset::NoFilesystemWrite => 3,
        PolicyPreset::HostObserved => 4,
    }
}

fn merge_filesystem(
    mut current: BTreeMap<String, Vec<String>>,
    next: BTreeMap<String, Vec<String>>,
) -> BTreeMap<String, Vec<String>> {
    for (key, next_roots) in next {
        current
            .entry(key.clone())
            .and_modify(|current_roots| {
                if key == "denyRead" || key == "denyWrite" {
                    *current_roots = union_roots(current_roots, &next_roots);
                } else {
                    *current_roots = intersect_roots(current_roots, &next_roots);
                }
            })
            .or_insert(next_roots);
    }
    current
}

fn union_roots(left: &[String], right: &[String]) -> Vec<String> {
    left.iter()
        .chain(right.iter())
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn intersect_roots(left: &[String], right: &[String]) -> Vec<String> {
    let right = right.iter().collect::<BTreeSet<_>>();
    left.iter()
        .filter(|root| right.contains(root))
        .cloned()
        .collect()
}

fn merge_network(
    current: Option<String>,
    next: Option<String>,
    profile: &str,
) -> Result<Option<String>, PolicyResolutionError> {
    match (current.as_deref(), next.as_deref()) {
        (Some("deny"), _) | (_, Some("deny")) => Ok(Some("deny".to_string())),
        (Some("allow"), Some("allow")) => Ok(Some("allow".to_string())),
        (Some(value), None) | (None, Some(value)) => Ok(Some(value.to_string())),
        (None, None) => Ok(None),
        (Some(left), Some(right)) => Err(conflict(
            profile,
            format!("network `{left}` and `{right}` are not comparable"),
        )),
    }
}

fn merge_process(
    mut current: BTreeMap<String, serde_json::Value>,
    next: BTreeMap<String, serde_json::Value>,
    profile: &str,
) -> Result<BTreeMap<String, serde_json::Value>, PolicyResolutionError> {
    for (key, value) in next {
        current
            .entry(key.clone())
            .and_modify(|current_value| {
                if key == "spawn" {
                    let current_bool = current_value.as_bool().unwrap_or(true);
                    let next_bool = value.as_bool().unwrap_or(true);
                    *current_value = serde_json::json!(current_bool && next_bool);
                } else if *current_value != value {
                    *current_value = serde_json::Value::Null;
                }
            })
            .or_insert(value);
        if current.get(&key).is_some_and(serde_json::Value::is_null) {
            return Err(conflict(
                profile,
                format!("process field `{key}` is not comparable"),
            ));
        }
    }
    Ok(current)
}

fn merge_resources(
    mut current: BTreeMap<String, serde_json::Value>,
    next: BTreeMap<String, serde_json::Value>,
    profile: &str,
) -> Result<BTreeMap<String, serde_json::Value>, PolicyResolutionError> {
    for (key, value) in next {
        current
            .entry(key.clone())
            .and_modify(|current_value| {
                if key == "timeoutMs" || key == "maxOutputBytes" {
                    let current_number = current_value.as_u64().unwrap_or(u64::MAX);
                    let next_number = value.as_u64().unwrap_or(u64::MAX);
                    *current_value = serde_json::json!(current_number.min(next_number));
                } else if *current_value != value {
                    *current_value = serde_json::Value::Null;
                }
            })
            .or_insert(value);
        if current.get(&key).is_some_and(serde_json::Value::is_null) {
            return Err(conflict(
                profile,
                format!("resource field `{key}` is not comparable"),
            ));
        }
    }
    Ok(current)
}

fn merge_backend_preference(
    current: Vec<BackendFamily>,
    next: Vec<BackendFamily>,
    profile: &str,
) -> Result<Vec<BackendFamily>, PolicyResolutionError> {
    if current.is_empty() {
        return Ok(next);
    }
    if next.is_empty() {
        return Ok(current);
    }
    let next_set = next.iter().collect::<BTreeSet<_>>();
    let intersection: Vec<BackendFamily> = current
        .into_iter()
        .filter(|backend| next_set.contains(backend))
        .collect();
    if intersection.is_empty() {
        Err(conflict(
            profile,
            "backendPreference has no shared backend".to_string(),
        ))
    } else {
        Ok(intersection)
    }
}

fn merge_fallback(
    current: FallbackSpec,
    next: FallbackSpec,
    profile: &str,
) -> Result<FallbackSpec, PolicyResolutionError> {
    match (current.mode.as_str(), next.mode.as_str()) {
        ("none", _) | (_, "none") => Ok(FallbackSpec {
            mode: "none".to_string(),
        }),
        ("workspace-rollback", "workspace-rollback") => Ok(FallbackSpec {
            mode: "workspace-rollback".to_string(),
        }),
        (left, right) if left == right => Ok(FallbackSpec {
            mode: left.to_string(),
        }),
        (left, right) => Err(conflict(
            profile,
            format!("fallback modes `{left}` and `{right}` are not comparable"),
        )),
    }
}

fn conflict(profile: &str, message: String) -> PolicyResolutionError {
    PolicyResolutionError::ProfileConflict {
        profile: profile.to_string(),
        message,
    }
}
