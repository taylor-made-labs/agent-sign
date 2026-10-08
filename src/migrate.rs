//! Moving an agent-sign home (`~/.agent-sign`) to a agent-commits home (`~/.agent-commits`).
//!
//! `agent-commitsd` calls [`migrate_state_dir`] when it starts, so an existing user
//! needs to do nothing. The whole directory (key, leases, config, socket, and
//! `bin/`) is moved with one `rename`, which is atomic on the same file system
//! and never copies the private key. A symlink is then left at the old path,
//! pointing to the new one, so everything that still names `~/.agent-sign`
//! keeps working unchanged: the `PATH` entry `~/.agent-sign/bin`, the
//! LaunchAgent's `~/.agent-sign/bin/agent-signd`, old binaries' socket path,
//! and any absolute paths in the config file. File contents are not touched,
//! so leases, the key, and the config mean exactly what they meant before.
//!
//! The move is refused, and nothing is changed, when both directories already
//! hold something: picking one silently could replace the agent key that
//! GitHub and `allowed_signers` know with a new one.

use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::paths;

/// What [`migrate_state_dir`] found or did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MigrationOutcome {
    /// There is no `~/.agent-sign`: a fresh install, or a agent-commits-only one.
    NothingToMigrate,
    /// `~/.agent-sign` is already a link to `~/.agent-commits`.
    AlreadyMigrated,
    /// `~/.agent-sign` was moved to `~/.agent-commits` and a link left in its place.
    Migrated { from: PathBuf, to: PathBuf },
    /// `~/.agent-sign` is a link to somewhere other than `~/.agent-commits` (the person
    /// put their state elsewhere on purpose, or the link is broken), and there
    /// is no other `~/.agent-commits` to conflict with. It is left alone; if it leads to
    /// a directory, `paths::state_dir_in` keeps using it.
    LeftLegacyLink { target: PathBuf },
}

impl fmt::Display for MigrationOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MigrationOutcome::NothingToMigrate => write!(f, "no agent-sign state to migrate"),
            MigrationOutcome::AlreadyMigrated => write!(f, "agent-sign state already migrated"),
            MigrationOutcome::Migrated { from, to } => write!(
                f,
                "moved {} to {} and left a link at the old path",
                from.display(),
                to.display()
            ),
            MigrationOutcome::LeftLegacyLink { target } => write!(
                f,
                "left the agent-sign link (to {}) in place and kept using it",
                target.display()
            ),
        }
    }
}

/// Why [`migrate_state_dir`] could not migrate.
#[derive(Debug)]
pub enum MigrationError {
    /// Both `~/.agent-sign` and `~/.agent-commits` hold state (neither is a link to the
    /// other, and `~/.agent-commits` is not empty). Nothing was changed; the person has
    /// to choose.
    Conflict {
        legacy: PathBuf,
        agent_commits_dir: PathBuf,
    },
    /// `~/.agent-sign` exists but is not a directory or a link.
    NotADirectory { legacy: PathBuf },
    /// A file-system step failed. `rolled_back` says whether the directory is
    /// back at its old path (so the old layout is still in use).
    Io {
        step: &'static str,
        source: io::Error,
        rolled_back: bool,
    },
}

impl fmt::Display for MigrationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MigrationError::Conflict {
                legacy,
                agent_commits_dir,
            } => write!(
                f,
                "both {} and {} exist; move one aside so only the one holding the agent key and leases remains, then start agent-commitsd again",
                legacy.display(),
                agent_commits_dir.display()
            ),
            MigrationError::NotADirectory { legacy } => {
                write!(f, "{} exists but is not a directory", legacy.display())
            }
            MigrationError::Io {
                step,
                source,
                rolled_back,
            } => write!(
                f,
                "could not {}: {}{}",
                step,
                source,
                if *rolled_back {
                    " (undone; still using the agent-sign directory)"
                } else {
                    ""
                }
            ),
        }
    }
}

impl std::error::Error for MigrationError {}

/// Moves `<home>/.agent-sign` to `<home>/.agent-commits` and leaves a symlink at the old
/// path. Safe to call on every start: it does nothing once migrated, on a
/// fresh home, or when another `agent-commitsd` finished the move first.
pub fn migrate_state_dir(home: &Path) -> Result<MigrationOutcome, MigrationError> {
    let legacy = paths::legacy_dir_in(home);
    let agent_commits_dir = paths::agent_commits_dir_in(home);

    let legacy_meta = match fs::symlink_metadata(&legacy) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Ok(MigrationOutcome::NothingToMigrate);
        }
        Err(source) => {
            return Err(MigrationError::Io {
                step: "inspect the agent-sign directory",
                source,
                rolled_back: false,
            });
        }
    };

    if legacy_meta.file_type().is_symlink() {
        return classify_legacy_link(legacy, agent_commits_dir);
    }
    if !legacy_meta.is_dir() {
        return Err(MigrationError::NotADirectory { legacy });
    }

    // ~/.agent-sign is a real directory. Make room at ~/.agent-commits if it is empty.
    match fs::symlink_metadata(&agent_commits_dir) {
        Ok(m) if m.is_dir() && is_empty_dir(&agent_commits_dir) => {
            fs::remove_dir(&agent_commits_dir).map_err(|source| MigrationError::Io {
                step: "remove the empty agent-commits directory",
                source,
                rolled_back: false,
            })?;
        }
        Ok(_) => {
            return Err(MigrationError::Conflict {
                legacy,
                agent_commits_dir,
            });
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(MigrationError::Io {
                step: "inspect the agent-commits directory",
                source,
                rolled_back: false,
            });
        }
    }

    if let Err(source) = fs::rename(&legacy, &agent_commits_dir) {
        // Another agent-commitsd may have moved it between our checks and the rename.
        if let Ok(m) = fs::symlink_metadata(&legacy)
            && m.file_type().is_symlink()
        {
            return classify_legacy_link(legacy, agent_commits_dir);
        }
        return Err(MigrationError::Io {
            step: "move the agent-sign directory",
            source,
            rolled_back: true,
        });
    }

    if let Err(source) = std::os::unix::fs::symlink(&agent_commits_dir, &legacy) {
        // Put the directory back so the old paths (PATH, LaunchAgent) keep working.
        let rolled_back = fs::rename(&agent_commits_dir, &legacy).is_ok();
        return Err(MigrationError::Io {
            step: "leave a link at the agent-sign path",
            source,
            rolled_back,
        });
    }

    Ok(MigrationOutcome::Migrated {
        from: legacy,
        to: agent_commits_dir,
    })
}

/// `~/.agent-sign` is a symlink. If it leads to `~/.agent-commits`, the migration is
/// done. If it leads to another directory while `~/.agent-commits` also exists, that is
/// a conflict. Otherwise (it leads elsewhere, or nowhere) it is left alone.
fn classify_legacy_link(
    legacy: PathBuf,
    agent_commits_dir: PathBuf,
) -> Result<MigrationOutcome, MigrationError> {
    let target = fs::read_link(&legacy).unwrap_or_default();
    let resolved_legacy = fs::canonicalize(&legacy).ok();
    let resolved_agent_commits = fs::canonicalize(&agent_commits_dir).ok();
    match (resolved_legacy, resolved_agent_commits) {
        (Some(a), Some(b)) if a == b => Ok(MigrationOutcome::AlreadyMigrated),
        (Some(a), Some(_)) if a.is_dir() => Err(MigrationError::Conflict {
            legacy,
            agent_commits_dir,
        }),
        _ => Ok(MigrationOutcome::LeftLegacyLink { target }),
    }
}

fn is_empty_dir(dir: &Path) -> bool {
    fs::read_dir(dir)
        .map(|mut entries| entries.next().is_none())
        .unwrap_or(false)
}
