use raxcell_protocol::{
    FileSystemLoweringReport, LoweredRootAccess, PolicyDecisionRequired, RunRequest,
};
use std::path::{Path, PathBuf};

use super::error::{LinuxRunError, environment_gap, sandbox_denied};
use super::filesystem::is_covered;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ShellEffectAccess {
    Read,
    Write,
}

struct ShellEffect {
    path: PathBuf,
    access: ShellEffectAccess,
}

pub(super) fn require_shell_effect_grants(
    request: &RunRequest,
    cwd: &Path,
    filesystem_lowering: &FileSystemLoweringReport,
) -> Result<(), LinuxRunError> {
    for effect in shell_effects(&request.command.argv, cwd)? {
        if shell_effect_is_allowed(&effect, request, filesystem_lowering)? {
            continue;
        }
        let required = match effect.access {
            ShellEffectAccess::Read => "filesystem.read",
            ShellEffectAccess::Write => "filesystem.write",
        };
        return Err(LinuxRunError::PolicyDecisionRequired(
            PolicyDecisionRequired {
                reason: "shell-effect-outside-declared-roots".to_string(),
                path: effect.path.to_string_lossy().into_owned(),
                required: vec![required.to_string()],
                public_safe_message:
                    "command references filesystem paths outside declared roots; upper policy decision required"
                        .to_string(),
            },
        ));
    }
    Ok(())
}

fn shell_effect_is_allowed(
    effect: &ShellEffect,
    request: &RunRequest,
    filesystem_lowering: &FileSystemLoweringReport,
) -> Result<bool, LinuxRunError> {
    let read_roots: Vec<PathBuf> = filesystem_lowering
        .declared_roots
        .iter()
        .filter(|root| root.access == LoweredRootAccess::Read)
        .map(|root| PathBuf::from(&root.path))
        .collect();
    let write_roots: Vec<PathBuf> = filesystem_lowering
        .declared_roots
        .iter()
        .filter(|root| root.access == LoweredRootAccess::Write)
        .map(|root| PathBuf::from(&root.path))
        .collect();
    if is_covered(&effect.path, &write_roots) {
        return Ok(true);
    }
    if effect.access == ShellEffectAccess::Read && is_covered(&effect.path, &read_roots) {
        return Ok(true);
    }
    for grant in &request.policy_grants {
        let grant_path = std::fs::canonicalize(&grant.path).map_err(|err| {
            sandbox_denied(format!(
                "policy grant path `{}` is not available: {err}",
                grant.path
            ))
        })?;
        if !effect.path.starts_with(&grant_path) {
            continue;
        }
        if grant.access.iter().any(|access| access == "write") {
            return Ok(true);
        }
        if effect.access == ShellEffectAccess::Read
            && grant.access.iter().any(|access| access == "read")
        {
            return Ok(true);
        }
    }
    Ok(false)
}

pub(super) fn reject_unresolved_dynamic_redirect_paths(
    argv: &[String],
) -> Result<(), LinuxRunError> {
    let Some(script) = shell_script_from_argv(argv) else {
        return Ok(());
    };
    let tokens = tokenize_shell_script(script);
    for pair in tokens.windows(2) {
        if redirect_access(&pair[0]).is_some()
            && shell_path_has_unresolved_dynamic_segment(&pair[1])
        {
            return Err(environment_gap(
                "dynamic-shell-path-unresolved",
                Some(&pair[1]),
                vec!["command.rewrite.static-path"],
                "shell path contains dynamic expansion that Raxcell cannot lower without an upper rewrite",
            ));
        }
    }
    Ok(())
}

fn shell_effects(argv: &[String], cwd: &Path) -> Result<Vec<ShellEffect>, LinuxRunError> {
    let Some(script) = shell_script_from_argv(argv) else {
        return command_effects(argv, cwd, /*reject_dynamic_paths*/ false);
    };
    command_effects(
        &tokenize_shell_script(script),
        cwd,
        /*reject_dynamic_paths*/ true,
    )
}

fn shell_script_from_argv(argv: &[String]) -> Option<&str> {
    let executable = Path::new(argv.first()?).file_name()?.to_str()?;
    if !matches!(executable, "sh" | "bash" | "dash" | "zsh") {
        return None;
    }
    argv.iter()
        .enumerate()
        .find(|(index, arg)| *index > 0 && matches!(arg.as_str(), "-c" | "-lc" | "-cl"))
        .and_then(|(index, _)| argv.get(index + 1).map(String::as_str))
}

fn tokenize_shell_script(script: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    let mut chars = script.chars().peekable();
    while let Some(ch) = chars.next() {
        if let Some(active_quote) = quote {
            if ch == active_quote {
                quote = None;
            } else {
                current.push(ch);
            }
            continue;
        }
        match ch {
            '\'' | '"' => quote = Some(ch),
            ' ' | '\t' | '\n' => {
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
            }
            '>' | '<' => {
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
                let mut op = ch.to_string();
                if chars.peek() == Some(&ch) {
                    op.push(chars.next().expect("peeked char exists"));
                }
                tokens.push(op);
            }
            ';' | '|' | '&' => {
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
                tokens.push(ch.to_string());
            }
            _ => current.push(ch),
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    split_numbered_redirects(tokens)
}

fn split_numbered_redirects(tokens: Vec<String>) -> Vec<String> {
    let mut split = Vec::new();
    for token in tokens {
        if token.len() > 1
            && token.chars().next().is_some_and(|ch| ch.is_ascii_digit())
            && token[1..].chars().all(|ch| ch == '>' || ch == '<')
        {
            split.push(token[1..].to_string());
        } else {
            split.push(token);
        }
    }
    split
}

fn command_effects(
    argv: &[String],
    cwd: &Path,
    reject_dynamic_paths: bool,
) -> Result<Vec<ShellEffect>, LinuxRunError> {
    let mut effects = Vec::new();
    let mut index = 0;
    while index < argv.len() {
        let token = &argv[index];
        if matches!(token.as_str(), ";" | "|" | "&") {
            index += 1;
            continue;
        }
        if let Some(access) = redirect_access(token) {
            if let Some(target) = argv.get(index + 1) {
                effects.push(ShellEffect {
                    path: normalize_effect_path(target, cwd, reject_dynamic_paths)?,
                    access,
                });
            }
            index += 2;
            continue;
        }
        let command = Path::new(token)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(token);
        if command == "cat" {
            for arg in non_option_args(&argv[index + 1..]) {
                effects.push(ShellEffect {
                    path: normalize_effect_path(arg, cwd, reject_dynamic_paths)?,
                    access: ShellEffectAccess::Read,
                });
            }
        } else if matches!(command, "touch" | "mkdir" | "rm" | "rmdir") {
            for arg in non_option_args(&argv[index + 1..]) {
                effects.push(ShellEffect {
                    path: normalize_effect_path(arg, cwd, reject_dynamic_paths)?,
                    access: ShellEffectAccess::Write,
                });
            }
        }
        index += 1;
    }
    Ok(effects)
}

fn redirect_access(token: &str) -> Option<ShellEffectAccess> {
    match token {
        ">" | ">>" | "<>" => Some(ShellEffectAccess::Write),
        "<" | "<<" => Some(ShellEffectAccess::Read),
        _ => None,
    }
}

fn non_option_args(args: &[String]) -> impl Iterator<Item = &String> {
    args.iter()
        .take_while(|arg| !matches!(arg.as_str(), ";" | "|" | "&"))
        .filter(|arg| !arg.starts_with('-'))
}

fn normalize_effect_path(
    raw: &str,
    cwd: &Path,
    reject_dynamic_paths: bool,
) -> Result<PathBuf, LinuxRunError> {
    if reject_dynamic_paths && shell_path_has_unresolved_dynamic_segment(raw) {
        return Err(environment_gap(
            "dynamic-shell-path-unresolved",
            Some(raw),
            vec!["command.rewrite.static-path"],
            "shell path contains dynamic expansion that Raxcell cannot lower without an upper rewrite",
        ));
    }
    let path = if Path::new(raw).is_absolute() {
        PathBuf::from(raw)
    } else {
        cwd.join(raw)
    };
    if let Ok(canonical) = std::fs::canonicalize(&path) {
        return Ok(canonical);
    }
    let Some(parent) = path.parent() else {
        return Err(sandbox_denied(format!(
            "failed to resolve shell effect path `{raw}`"
        )));
    };
    let parent = std::fs::canonicalize(parent).map_err(|err| {
        sandbox_denied(format!(
            "failed to resolve shell effect parent `{}`: {err}",
            parent.to_string_lossy()
        ))
    })?;
    let Some(file_name) = path.file_name() else {
        return Ok(parent);
    };
    Ok(parent.join(file_name))
}

fn shell_path_has_unresolved_dynamic_segment(raw: &str) -> bool {
    raw.contains('$') || raw.contains('~') || raw.contains('*') || raw.contains('?')
}
