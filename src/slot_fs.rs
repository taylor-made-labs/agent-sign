//! The launcher's file moves in slot folders, made so that a hostile
//! session can't redirect them (docs/system-mode.md, "D6" and its step 4;
//! build step 3). Linux only.
//!
//! **The threat.** A session runs as its slot's account and can write
//! anything inside its own `current/` folder: links (symbolic or hard),
//! FIFOs, files of any size, folders where files are expected, and it can
//! race the launcher while it runs. The launcher (`agent-launch`) reads
//! what the end step leaves in `current/out/`, writes the input bundles to
//! `current/in/`, and renames `current/` into the slot's Trash. Done with
//! plain paths, a session could point those at the launcher's own files
//! (its state, other sessions' returned bundles) and have them sent to the
//! caller, or overwritten.
//!
//! **How each move is made safe.**
//! - Every operation starts from a descriptor of a folder the launcher
//!   opened itself, never from a path string under a slot's control:
//!   `openat`, `mkdirat`, `renameat2` relative to that descriptor.
//! - The slot's own folder (`<root>/<n>/`) belongs to the launcher, mode
//!   0750, so the slot can enter it but not change its entries: `current`
//!   and `trash` in it can't be swapped for links. It is opened with
//!   `O_NOFOLLOW` and checked (a folder, owned by the launcher, no write or
//!   access for others) before anything is made in it.
//! - A file the launcher reads from a session's folder is opened with
//!   `openat2` and `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS |
//!   RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV` ([`read_beneath`]): no link
//!   anywhere on the way is followed and nothing outside `current/` is
//!   reached. Where the kernel has no `openat2` (before Linux 5.6), each
//!   component is opened in turn with `O_NOFOLLOW`, which refuses the same
//!   links. The file is opened `O_NONBLOCK` (a FIFO can't stall the
//!   launcher) and read only if it is a regular file, with one link (a hard
//!   link to someone else's file is refused), owned by the slot's account,
//!   and no bigger than the caller's limit.
//! - New folders and files are made with `mkdirat` and `O_CREAT | O_EXCL |
//!   O_NOFOLLOW`: if anything is already at the name (a session's planted
//!   link), the call fails rather than follow or reuse it.
//! - The Trash move is `renameat2` with `RENAME_NOREPLACE`: it never
//!   replaces an earlier Trash entry, and it moves the folder itself, so the
//!   links inside it are carried along, never followed.
//!
//! - A file that must already be there, in a folder only root can change
//!   (the launcher's I/O folder, [`open_existing_file_at`]), is opened
//!   `O_NOFOLLOW` and never `O_CREAT`, then checked on the open descriptor
//!   (a regular file, the launcher's own, one name): a missing or planted
//!   entry is refused, and nothing is made in its place.
//!
//! Nothing here deletes anything.

use std::ffi::CString;
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::Path;

fn cstr(name: &str) -> io::Result<CString> {
    CString::new(name).map_err(|_| io::Error::other(format!("{name:?} has a NUL in it")))
}

/// Whether `name` is one plain folder entry: not empty, not `.` or `..`, no
/// `/` and no NUL.
pub fn is_plain_name(name: &str) -> bool {
    !name.is_empty() && name != "." && name != ".." && !name.contains('/') && !name.contains('\0')
}

fn plain(name: &str) -> io::Result<CString> {
    if !is_plain_name(name) {
        return Err(io::Error::other(format!("{name:?} isn't one plain name")));
    }
    cstr(name)
}

fn check(rc: libc::c_int) -> io::Result<libc::c_int> {
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(rc)
    }
}

/// Opens the folder at `path` (a path from root-owned settings, so links
/// in it are followed).
pub fn open_dir_path(path: &Path) -> io::Result<OwnedFd> {
    let c = CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|_| io::Error::other("the path has a NUL in it"))?;
    // SAFETY: a valid C string and flags; the result is checked.
    let fd = check(unsafe {
        libc::open(
            c.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    })?;
    // SAFETY: the kernel just made this descriptor for us.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Opens the folder `name` in `dir`, refusing a link at `name`.
pub fn open_dir_at(dir: &OwnedFd, name: &str) -> io::Result<OwnedFd> {
    let c = plain(name)?;
    // SAFETY: a valid descriptor and C string; the result is checked.
    let fd = check(unsafe {
        libc::openat(
            dir.as_raw_fd(),
            c.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    })?;
    // SAFETY: the kernel just made this descriptor for us.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// The status of an open descriptor.
pub fn stat_fd(fd: &OwnedFd) -> io::Result<libc::stat> {
    // SAFETY: an all-zero stat is a valid buffer for fstat to fill.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: a valid descriptor and buffer.
    check(unsafe { libc::fstat(fd.as_raw_fd(), &mut st) })?;
    Ok(st)
}

/// The status of `name` in `dir`, not following a link; `None` if nothing
/// is there.
pub fn stat_at(dir: &OwnedFd, name: &str) -> io::Result<Option<libc::stat>> {
    let c = plain(name)?;
    // SAFETY: an all-zero stat is a valid buffer for fstatat to fill.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: a valid descriptor, C string and buffer.
    let rc = unsafe {
        libc::fstatat(
            dir.as_raw_fd(),
            c.as_ptr(),
            &mut st,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if rc < 0 {
        let e = io::Error::last_os_error();
        return if e.raw_os_error() == Some(libc::ENOENT) {
            Ok(None)
        } else {
            Err(e)
        };
    }
    Ok(Some(st))
}

/// Whether `st` is a folder.
pub fn is_dir(st: &libc::stat) -> bool {
    st.st_mode & libc::S_IFMT == libc::S_IFDIR
}

/// Makes the folder `name` in `dir` with `mode` exactly (not narrowed by the
/// umask: it is set again on the open folder), refusing anything already
/// there, and returns it open.
pub fn make_dir_at(dir: &OwnedFd, name: &str, mode: u32) -> io::Result<OwnedFd> {
    let c = plain(name)?;
    // SAFETY: a valid descriptor and C string; the result is checked.
    check(unsafe { libc::mkdirat(dir.as_raw_fd(), c.as_ptr(), 0o700) })?;
    let fd = open_dir_at(dir, name)?;
    set_mode(&fd, mode)?;
    Ok(fd)
}

/// Sets the mode of an open file or folder.
pub fn set_mode(fd: &OwnedFd, mode: u32) -> io::Result<()> {
    // SAFETY: a valid descriptor.
    check(unsafe { libc::fchmod(fd.as_raw_fd(), mode as libc::mode_t) }).map(|_| ())
}

/// Gives an open file or folder the group `gid`, keeping its owner.
pub fn set_group(fd: &OwnedFd, gid: u32) -> io::Result<()> {
    // SAFETY: a valid descriptor; -1 keeps the owner.
    check(unsafe { libc::fchown(fd.as_raw_fd(), u32::MAX, gid) }).map(|_| ())
}

/// Writes a new file `name` in `dir` (refusing anything already there, a
/// link included) with `mode` and group `gid`, holding `bytes`, synced.
pub fn create_file_at(
    dir: &OwnedFd,
    name: &str,
    mode: u32,
    gid: u32,
    bytes: &[u8],
) -> io::Result<()> {
    use std::io::Write;
    let c = plain(name)?;
    // SAFETY: a valid descriptor and C string; the result is checked.
    let fd = check(unsafe {
        libc::openat(
            dir.as_raw_fd(),
            c.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600 as libc::c_uint,
        )
    })?;
    // SAFETY: the kernel just made this descriptor for us.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    set_group(&fd, gid)?;
    set_mode(&fd, mode)?;
    let mut file = std::fs::File::from(fd);
    file.write_all(bytes)?;
    file.sync_all()
}

/// Opens the file `name` in `dir` for reading and writing, only if it is
/// already there as it must be, and never makes anything (A-2, the launcher's
/// I/O folder): `O_NOFOLLOW` (a link at `name` is refused, dangling or not,
/// and nothing is made at its target), no `O_CREAT`, `O_NONBLOCK | O_NOCTTY`
/// (a FIFO or a terminal can't stall the launcher), then `fstat` of the open
/// descriptor: a regular file, owned by `owner`, with one name (a second hard
/// link would let a write reach a file somewhere else). The error says in
/// plain words what is wrong with the entry, naming `name`. The check is on
/// the descriptor, so what was checked is what is written.
pub fn open_existing_file_at(
    dir: &OwnedFd,
    name: &str,
    owner: u32,
) -> Result<std::fs::File, String> {
    let c = plain(name).map_err(|e| e.to_string())?;
    // SAFETY: a valid descriptor and C string; the result is checked.
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            c.as_ptr(),
            libc::O_RDWR | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        let e = io::Error::last_os_error();
        return Err(match e.raw_os_error() {
            Some(libc::ENOENT) => format!("{name} is missing (the sitting makes it)"),
            Some(libc::ELOOP) => format!("{name} is a link: not followed"),
            Some(libc::EISDIR) | Some(libc::ENXIO) | Some(libc::ENODEV) => {
                format!("{name} isn't a regular file")
            }
            _ => format!("{name} can't be opened ({e})"),
        });
    }
    // SAFETY: the kernel just made this descriptor for us.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let st = stat_fd(&fd).map_err(|e| format!("{name}: {e}"))?;
    if st.st_mode & libc::S_IFMT != libc::S_IFREG {
        return Err(format!("{name} isn't a regular file"));
    }
    if st.st_nlink != 1 {
        return Err(format!(
            "{name} has more than one name (a hard link): not written"
        ));
    }
    if st.st_uid != owner {
        return Err(format!(
            "{name} belongs to uid {}, not the launcher's (uid {owner})",
            st.st_uid
        ));
    }
    Ok(std::fs::File::from(fd))
}

/// Renames `from` in `from_dir` to `to` in `to_dir`, never replacing
/// anything at `to` (`RENAME_NOREPLACE`).
pub fn rename_noreplace(
    from_dir: &OwnedFd,
    from: &str,
    to_dir: &OwnedFd,
    to: &str,
) -> io::Result<()> {
    let (a, b) = (plain(from)?, plain(to)?);
    // SAFETY: valid descriptors and C strings.
    check(unsafe {
        libc::renameat2(
            from_dir.as_raw_fd(),
            a.as_ptr(),
            to_dir.as_raw_fd(),
            b.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    })
    .map(|_| ())
}

/// Syncs an open folder, so a rename or a new entry in it lasts a crash.
pub fn sync_dir(fd: &OwnedFd) -> io::Result<()> {
    // SAFETY: a valid descriptor.
    check(unsafe { libc::fsync(fd.as_raw_fd()) }).map(|_| ())
}

/// The flags every link-refusing open uses.
const READ_FLAGS: libc::c_int =
    libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC | libc::O_NOCTTY;

/// `openat2` with the resolve rules of the module documentation, or `None`
/// when this kernel has no `openat2`.
fn openat2_beneath(dir: RawFd, rel: &CString) -> Option<io::Result<OwnedFd>> {
    // SAFETY: an all-zero open_how is valid (it is a plain struct of u64s,
    // non-exhaustive only for Rust's sake).
    let mut how: libc::open_how = unsafe { std::mem::zeroed() };
    how.flags = READ_FLAGS as u64;
    how.mode = 0;
    how.resolve = libc::RESOLVE_BENEATH
        | libc::RESOLVE_NO_SYMLINKS
        | libc::RESOLVE_NO_MAGICLINKS
        | libc::RESOLVE_NO_XDEV;
    // SAFETY: valid pointers for the sizes given.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            dir,
            rel.as_ptr(),
            &how as *const libc::open_how,
            std::mem::size_of::<libc::open_how>(),
        )
    };
    if rc < 0 {
        let e = io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::ENOSYS) {
            return None;
        }
        return Some(Err(e));
    }
    // SAFETY: the kernel just made this descriptor for us.
    Some(Ok(unsafe { OwnedFd::from_raw_fd(rc as RawFd) }))
}

/// The same rules without `openat2`: each folder on the way opened with
/// `O_NOFOLLOW | O_DIRECTORY`, the file with `O_NOFOLLOW`.
fn walk_beneath(dir: &OwnedFd, parts: &[&str]) -> io::Result<OwnedFd> {
    let (last, folders) = parts
        .split_last()
        .ok_or_else(|| io::Error::other("empty path"))?;
    let mut owned: Option<OwnedFd> = None;
    for part in folders {
        let next = open_dir_at(owned.as_ref().unwrap_or(dir), part)?;
        owned = Some(next);
    }
    let c = plain(last)?;
    let at = owned.as_ref().unwrap_or(dir).as_raw_fd();
    // SAFETY: a valid descriptor and C string; the result is checked.
    let fd = check(unsafe { libc::openat(at, c.as_ptr(), READ_FLAGS) })?;
    // SAFETY: the kernel just made this descriptor for us.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Reads the file at `rel` (plain names joined by `/`, such as
/// `out/status.json`) beneath `dir`, following no link and leaving no
/// folder, and only if it is a regular file with one link, owned by
/// `owner`, of at most `max` bytes (see the module documentation). `None`
/// when nothing is there; an error, saying why, when something is there
/// that isn't such a file.
pub fn read_beneath(
    dir: &OwnedFd,
    rel: &str,
    owner: u32,
    max: u64,
) -> Result<Option<Vec<u8>>, String> {
    let parts: Vec<&str> = rel.split('/').collect();
    if parts.iter().any(|p| !is_plain_name(p)) {
        return Err(format!("{rel:?} isn't a plain relative path"));
    }
    let c = cstr(rel).map_err(|e| e.to_string())?;
    let opened = match openat2_beneath(dir.as_raw_fd(), &c) {
        Some(r) => r,
        None => walk_beneath(dir, &parts),
    };
    let fd = match opened {
        Ok(fd) => fd,
        Err(e) if e.raw_os_error() == Some(libc::ENOENT) => return Ok(None),
        Err(e)
            if matches!(
                e.raw_os_error(),
                Some(libc::ELOOP) | Some(libc::EXDEV) | Some(libc::ENOTDIR)
            ) =>
        {
            return Err(format!(
                "{rel} is, or goes through, a link or another folder: not read"
            ));
        }
        Err(e) => return Err(format!("{rel} couldn't be opened ({e})")),
    };
    let st = stat_fd(&fd).map_err(|e| format!("{rel}: {e}"))?;
    if st.st_mode & libc::S_IFMT != libc::S_IFREG {
        return Err(format!("{rel} isn't a regular file: not read"));
    }
    if st.st_nlink != 1 {
        return Err(format!(
            "{rel} has more than one name (a hard link): not read"
        ));
    }
    if st.st_uid != owner {
        return Err(format!(
            "{rel} belongs to uid {}, not the slot's account (uid {owner}): not read",
            st.st_uid
        ));
    }
    if st.st_size as u64 > max {
        return Err(format!("{rel} is bigger than {max} bytes: not read"));
    }
    let mut file = std::fs::File::from(fd);
    // A regular file opened O_NONBLOCK reads normally.
    let mut out = Vec::new();
    (&mut file)
        .take(max + 1)
        .read_to_end(&mut out)
        .map_err(|e| format!("{rel} couldn't be read ({e})"))?;
    if out.len() as u64 > max {
        return Err(format!(
            "{rel} grew past {max} bytes while it was read: not read"
        ));
    }
    Ok(Some(out))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn me() -> u32 {
        // SAFETY: geteuid takes no arguments and can't fail.
        unsafe { libc::geteuid() }
    }

    #[test]
    fn reads_refuse_links_fifos_hard_links_and_strangers() {
        let t = tempfile::tempdir().unwrap();
        let root = t.path();
        std::fs::create_dir_all(root.join("cur/out")).unwrap();
        std::fs::create_dir_all(root.join("elsewhere")).unwrap();
        std::fs::write(root.join("elsewhere/secret"), "SECRET").unwrap();
        std::fs::write(root.join("cur/out/good"), "GOOD").unwrap();
        symlink(root.join("elsewhere/secret"), root.join("cur/out/link")).unwrap();
        symlink(root.join("elsewhere"), root.join("cur/linked")).unwrap();
        std::fs::hard_link(root.join("elsewhere/secret"), root.join("cur/out/hard")).unwrap();
        let fifo = CString::new(root.join("cur/out/fifo").as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: a valid C string.
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        let cur = open_dir_path(&root.join("cur")).unwrap();
        let read = |rel: &str| read_beneath(&cur, rel, me(), 1024);
        assert_eq!(read("out/good").unwrap().unwrap(), b"GOOD");
        assert_eq!(read("out/none").unwrap(), None);
        for bad in [
            "out/link",
            "linked/secret",
            "out/hard",
            "out/fifo",
            "../elsewhere/secret",
        ] {
            let r = read(bad);
            assert!(!matches!(r, Ok(Some(_))), "{bad}: {r:?}");
        }
        assert!(read_beneath(&cur, "out/good", me() + 1, 1024).is_err());
        assert!(read_beneath(&cur, "out/good", me(), 2).is_err());
    }

    #[test]
    fn existing_files_are_opened_only_if_exactly_right_and_nothing_is_made() {
        use std::os::unix::net::UnixListener;
        let t = tempfile::tempdir().unwrap();
        let p = t.path();
        std::fs::write(p.join("good"), "GOOD").unwrap();
        std::fs::write(p.join("target"), "TARGET").unwrap();
        symlink(p.join("target"), p.join("link")).unwrap();
        symlink(p.join("nothing"), p.join("dangling")).unwrap();
        std::fs::hard_link(p.join("target"), p.join("twin")).unwrap();
        std::fs::create_dir(p.join("folder")).unwrap();
        drop(UnixListener::bind(p.join("socket")).unwrap());
        let fifo = CString::new(p.join("fifo").as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: a valid C string.
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        let dir = open_dir_path(p).unwrap();
        let mut f = open_existing_file_at(&dir, "good", me()).unwrap();
        // It is the file itself, writable in place (the launcher truncates and writes).
        f.set_len(0).unwrap();
        std::io::Write::write_all(&mut f, b"NEW").unwrap();
        assert_eq!(std::fs::read_to_string(p.join("good")).unwrap(), "NEW");
        for bad in [
            "missing", "link", "dangling", "twin", "target", "folder", "socket", "fifo",
        ] {
            let r = open_existing_file_at(&dir, bad, me());
            assert!(r.is_err(), "{bad} was opened");
            assert!(r.unwrap_err().contains(bad));
        }
        assert!(open_existing_file_at(&dir, "good", me() + 1).is_err());
        assert!(open_existing_file_at(&dir, "../good", me()).is_err());
        // Nothing was made or changed.
        assert!(!p.join("missing").exists() && !p.join("nothing").exists());
        assert_eq!(std::fs::read_to_string(p.join("target")).unwrap(), "TARGET");
    }

    #[test]
    fn new_entries_never_reuse_or_follow_what_is_there() {
        let t = tempfile::tempdir().unwrap();
        let root = open_dir_path(t.path()).unwrap();
        symlink(t.path().join("target"), t.path().join("planted")).unwrap();
        assert!(make_dir_at(&root, "planted", 0o700).is_err());
        assert!(create_file_at(&root, "planted", 0o600, u32::MAX, b"x").is_err());
        assert!(!t.path().join("target").exists());
        let d = make_dir_at(&root, "made", 0o750).unwrap();
        assert_eq!(stat_fd(&d).unwrap().st_mode & 0o7777, 0o750);
        std::fs::create_dir(t.path().join("trash")).unwrap();
        std::fs::create_dir(t.path().join("trash/x")).unwrap();
        let trash = open_dir_at(&root, "trash").unwrap();
        assert!(rename_noreplace(&root, "made", &trash, "x").is_err());
        rename_noreplace(&root, "made", &trash, "y").unwrap();
        assert!(t.path().join("trash/y").is_dir());
        assert!(!is_plain_name("..") && !is_plain_name("a/b") && is_plain_name("a.b"));
    }
}
