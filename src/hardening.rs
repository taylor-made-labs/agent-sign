//! Ordinary process dumps are disabled before any private signing key exists.
//! This does not prevent swap, debuggers, privileged memory access or host dump
//! handlers which ignore RLIMIT_CORE; those remain host trust assumptions.

pub fn disable_core_dumps() -> std::io::Result<()> {
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: setrlimit reads a correctly initialized rlimit for this process.
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}
