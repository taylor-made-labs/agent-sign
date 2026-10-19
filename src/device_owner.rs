//! macOS: proof that the device's owner is present, through the system's
//! LocalAuthentication framework (`LAContext`).
//!
//! The policy is "device owner authentication": Touch ID where the Mac has
//! it, otherwise (or when the person chooses) the login password. Both are
//! checked by the system's own secure prompt, outside this process, so a
//! program that can click, type or script the screen can't answer for the
//! owner (it would need a fingerprint, or the password).
//!
//! The reason text passed in is what the prompt says is being approved (see
//! [`crate::approval::auth_reason`]). macOS builds the prompt from it as
//! "<name> is trying to <reason>.", where the name is that of the program
//! that asked: the installer runs the service from a small app bundle so
//! that name is "agent-sign" and not "agent-signd" (see
//! `scripts/agent-sign.Info.plist`). Nothing in this file can set the name.
//!
//! Anything but a success reply is a denial: wrong or cancelled
//! authentication, a lockout, no password set, no usable session, the wait
//! running out, or the request being withdrawn.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use block2::RcBlock;
use objc2::runtime::Bool;
use objc2_foundation::{NSError, NSString};
use objc2_local_authentication::{LAContext, LAPolicy};

use crate::approval::{AuthOutcome, Authenticator};

/// The macOS authenticator: Touch ID or the login password.
pub struct DeviceOwner {
    timeout: Duration,
}

impl DeviceOwner {
    /// One that gives up (and denies) after `timeout`.
    pub fn new(timeout: Duration) -> Self {
        DeviceOwner { timeout }
    }

    /// Whether this Mac can authenticate its owner in this session, without
    /// showing anything. For checks and tests.
    pub fn is_available() -> Result<(), String> {
        // SAFETY: a fresh context used on this thread only.
        unsafe {
            let ctx = LAContext::new();
            ctx.canEvaluatePolicy_error(LAPolicy::DeviceOwnerAuthentication)
                .map_err(|e| e.localizedDescription().to_string())
        }
    }
}

impl Authenticator for DeviceOwner {
    fn authenticate(&self, reason: &str, cancel: &AtomicBool) -> AuthOutcome {
        // SAFETY: the context is created here and used from this thread; the
        // reply block only sends on a channel (`Sender` is `Send`), which
        // meets evaluatePolicy's requirement that the block be sendable.
        unsafe {
            let ctx = LAContext::new();
            if let Err(e) = ctx.canEvaluatePolicy_error(LAPolicy::DeviceOwnerAuthentication) {
                let why = e.localizedDescription().to_string();
                // The agent is told only that nobody could be asked; the
                // service's log says why.
                eprintln!("[agent-signd] Can't ask the device owner to authenticate: {why}");
                return AuthOutcome::Unavailable(why);
            }
            let (tx, rx) = mpsc::channel::<Result<(), String>>();
            let reply = RcBlock::new(move |ok: Bool, error: *mut NSError| {
                let result = if ok.as_bool() {
                    Ok(())
                } else {
                    Err(match error.as_ref() {
                        Some(e) => e.localizedDescription().to_string(),
                        None => "the system gave no reason".to_string(),
                    })
                };
                let _ = tx.send(result);
            });
            ctx.evaluatePolicy_localizedReason_reply(
                LAPolicy::DeviceOwnerAuthentication,
                &NSString::from_str(reason),
                &reply,
            );
            let deadline = Instant::now() + self.timeout;
            loop {
                match rx.recv_timeout(Duration::from_millis(100)) {
                    Ok(Ok(())) => return AuthOutcome::Authenticated,
                    Ok(Err(why)) => return AuthOutcome::Failed(why),
                    Err(mpsc::RecvTimeoutError::Disconnected) => {
                        return AuthOutcome::Failed("the system did not answer".to_string());
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                }
                if cancel.load(Ordering::SeqCst) {
                    ctx.invalidate();
                    return AuthOutcome::Withdrawn;
                }
                if Instant::now() >= deadline {
                    ctx.invalidate();
                    return AuthOutcome::TimedOut;
                }
            }
        }
    }
}
