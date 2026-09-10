//! Guest-only shell persistence. All filesystem destinations are explicit so
//! tests never consult or modify the developer's real home/profile.
use anyhow::{Context, Result, bail};
use std::{
    fs,
    path::{Path, PathBuf},
};

const MARKER: &str = "# Friendzone guest environment (managed)";

pub fn persist(
    home: &Path,
    zdotdir: &Path,
    env: &Path,
    previous_bash_env: Option<&str>,
) -> Result<PathBuf> {
    let config = env.parent().context("environment file has no parent")?;
    let activate = config.join("activate.sh");
    let bash_env = config.join("bash-env.sh");
    let saved_previous = config.join("previous-bash-env");
    // The first installation owns the previous hook. Never record our own
    // wrapper on a rerun, or recursively source it.
    let previous = if saved_previous.exists() {
        fs::read_to_string(&saved_previous)?
    } else {
        previous_bash_env
            .filter(|s| Path::new(s) != bash_env)
            .unwrap_or("")
            .to_owned()
    };
    let source = format!(". {}\n", crate::setup::shell_quote(&env.to_string_lossy()));
    let wrapper = format!(
        "# Friendzone non-interactive bash; preserve the pre-existing hook.\n{}{}",
        if previous.is_empty() {
            String::new()
        } else {
            format!(
                "if [ -r {0} ]; then . {0}; fi\n",
                crate::setup::shell_quote(&previous)
            )
        },
        source
    );
    let activation = format!(
        "{source}export BASH_ENV={}\n",
        crate::setup::shell_quote(&bash_env.to_string_lossy())
    );
    let hook = format!(
        "{MARKER}\nif [ -r {0} ]; then . {0}; fi\n",
        crate::setup::shell_quote(&activate.to_string_lossy())
    );
    let mut paths = vec![
        home.join(".profile"),
        home.join(".bashrc"),
        zdotdir.join(".zshenv"),
    ];
    for name in [".bash_profile", ".bash_login"] {
        let path = home.join(name);
        // Creating a new .bash_profile would shadow the user's .profile.
        if path.exists() {
            paths.push(path);
        }
    }
    paths.sort();
    paths.dedup();
    let mut changes = Vec::new();
    for path in paths {
        let old = match fs::read_to_string(&path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(e) => return Err(e).with_context(|| format!("read profile {}", path.display())),
        };
        if old.contains(&hook) {
            continue;
        }
        if old.contains(MARKER) {
            bail!(
                "existing Friendzone hook in {} uses another location; remove that managed hook before changing configuration directories",
                path.display()
            );
        }
        // Upgrade simple manual source lines rather than add a second one.
        // Do not try to rewrite arbitrary shell syntax or compound commands.
        let env_text = env.to_string_lossy();
        let activate_text = activate.to_string_lossy();
        let mut candidates: Vec<_> = [env_text.as_ref(), activate_text.as_ref()]
            .into_iter()
            .flat_map(|target| {
                [
                    format!(". {}", crate::setup::shell_quote(target)),
                    format!("source {}", crate::setup::shell_quote(target)),
                    format!(". {target}"),
                    format!("source {target}"),
                    format!(". \"{target}\""),
                    format!("source \"{target}\""),
                ]
            })
            .collect();
        for file in [env, &activate] {
            if let Ok(relative) = file.strip_prefix(home) {
                let relative = relative.to_string_lossy().replace('\\', "/");
                for command in [".", "source"] {
                    candidates.extend([
                        format!("{command} ~/{relative}"),
                        format!("{command} \"$HOME/{relative}\""),
                        format!("{command} $HOME/{relative}"),
                    ]);
                }
            }
        }
        let lines: Vec<_> = old.lines().collect();
        let matching: Vec<_> = lines
            .iter()
            .enumerate()
            .filter(|(_, line)| candidates.iter().any(|candidate| line.trim() == candidate))
            .map(|(i, _)| i)
            .collect();
        if let Some(first) = matching.first() {
            let mut updated = String::new();
            for (i, line) in lines.iter().enumerate() {
                if i == *first {
                    updated.push_str(&hook);
                }
                if !matching.contains(&i) {
                    updated.push_str(line);
                    updated.push('\n');
                }
            }
            changes.push((path, updated));
        } else {
            // Put the hook before common non-interactive early returns in
            // .bashrc. Existing commands remain in their original order.
            changes.push((path, format!("{hook}\n{old}")));
        }
    }
    fs::create_dir_all(config)?;
    crate::storage::atomic_write(&saved_previous, previous.as_bytes())?;
    crate::storage::atomic_write(&bash_env, wrapper.as_bytes())?;
    crate::storage::atomic_write(&activate, activation.as_bytes())?;
    for (path, contents) in changes {
        fs::create_dir_all(path.parent().context("profile has no parent")?)?;
        // Follow user-owned symlinks, preserving their target and mode.
        let destination = if path.exists() {
            fs::canonicalize(&path)?
        } else {
            path.clone()
        };
        let permissions = fs::metadata(&destination).ok().map(|m| m.permissions());
        let backup = path.with_file_name(format!(
            "{}.friendzone-backup",
            path.file_name().unwrap().to_string_lossy()
        ));
        if path.exists() && !backup.exists() {
            fs::copy(&path, &backup)?;
        }
        crate::storage::atomic_write(&destination, contents.as_bytes())?;
        if let Some(permissions) = permissions {
            fs::set_permissions(&destination, permissions)?;
        }
    }
    Ok(activate)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn profile_hooks_are_idempotent_preserve_login_precedence_and_previous_bash_env() {
        let home = std::env::temp_dir().join(format!("fz-profile-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&home).unwrap();
        fs::write(home.join(".profile"), "# existing profile\n").unwrap();
        fs::write(home.join(".bash_login"), "# existing login\n").unwrap();
        let config = home.join("config");
        let env = config.join("env.sh");
        let zdir = home.join("zsh");
        let activate = persist(&home, &zdir, &env, Some("/previous hook.sh")).unwrap();
        let before = fs::read_to_string(home.join(".profile")).unwrap();
        persist(
            &home,
            &zdir,
            &env,
            Some(config.join("bash-env.sh").to_str().unwrap()),
        )
        .unwrap();
        assert_eq!(fs::read_to_string(home.join(".profile")).unwrap(), before);
        assert_eq!(before.matches(MARKER).count(), 1);
        assert!(!home.join(".bash_profile").exists());
        assert!(
            fs::read_to_string(home.join(".bash_login"))
                .unwrap()
                .contains(MARKER)
        );
        assert!(
            fs::read_to_string(zdir.join(".zshenv"))
                .unwrap()
                .contains(MARKER)
        );
        assert_eq!(
            fs::read_to_string(home.join(".profile.friendzone-backup")).unwrap(),
            "# existing profile\n"
        );
        assert!(
            fs::read_to_string(config.join("bash-env.sh"))
                .unwrap()
                .contains("/previous hook.sh")
        );
        assert!(
            fs::read_to_string(activate)
                .unwrap()
                .contains("export BASH_ENV=")
        );
        fs::remove_dir_all(home).unwrap();
    }

    #[test]
    fn activation_and_noninteractive_bash_use_only_temporary_home() {
        #[cfg(windows)]
        let bash = "C:/Program Files/Git/bin/bash.exe";
        #[cfg(not(windows))]
        let bash = "/bin/bash";
        let home = std::env::temp_dir().join(format!("fz-shell-{}", uuid::Uuid::new_v4()));
        let config = home.join("config");
        fs::create_dir_all(&config).unwrap();
        let env = config.join("env.sh");
        fs::write(&env, "export FZ_PROFILE_PROBE=guest-only\n").unwrap();
        let old = home.join("previous.sh");
        fs::write(&old, "export FZ_PREVIOUS_PROBE=preserved\n").unwrap();
        let activate = persist(&home, &home, &env, Some(old.to_str().unwrap())).unwrap();
        let command = format!(
            "set -eu; . {}; [ \"$FZ_PROFILE_PROBE\" = guest-only ]; bash --noprofile --norc -c '[ \"$FZ_PROFILE_PROBE\" = guest-only ] && [ \"$FZ_PREVIOUS_PROBE\" = preserved ]'; . \"$HOME/.bashrc\"; . \"$HOME/.zshenv\"; printf profile-ok",
            crate::setup::shell_quote(&activate.to_string_lossy())
        );
        let output = std::process::Command::new(bash)
            .args(["--noprofile", "--norc", "-c", &command])
            .env("HOME", &home)
            .env_remove("BASH_ENV")
            .env_remove("ENV")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("profile-ok"));
        fs::remove_dir_all(home).unwrap();
    }

    #[test]
    fn existing_manual_source_line_is_upgraded_without_duplicates() {
        let home =
            std::env::temp_dir().join(format!("fz-profile-existing-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&home).unwrap();
        let env = home.join("env.sh");
        fs::write(
            home.join(".profile"),
            format!(
                "# before\n. {}\n# after\n",
                crate::setup::shell_quote(&env.to_string_lossy())
            ),
        )
        .unwrap();
        persist(&home, &home, &env, None).unwrap();
        let text = fs::read_to_string(home.join(".profile")).unwrap();
        assert_eq!(text.matches(MARKER).count(), 1);
        assert!(!text.contains(&format!(
            ". {}\n",
            crate::setup::shell_quote(&env.to_string_lossy())
        )));
        assert!(text.starts_with("# before\n"));
        assert!(text.ends_with("# after\n"));
        fs::remove_dir_all(home).unwrap();
    }
}
