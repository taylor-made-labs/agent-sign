# Agent-Sign: Software Engineering Best Practices & Guidelines

- **Version**: 1.0.0
- **Scope**: Architectural standards, security patterns, code quality, and testing practices for `agent-sign`.

---

## 1. Architectural Principles

### 1.1. Clean Architecture & Separation of Concerns
1. **Core Domain (`crypto`, `lease`, `attribution`)**:
   - Must have **zero I/O dependencies** or environment side effects.
   - Pure, deterministic, easily testable logic.
   - Independent of Git CLI, OS sockets, or file systems.
2. **Services & Multiplexer (`multiplexer`, `interceptor`, `protocol`)**:
   - Manages routing, command inspection, and IPC message schemas.
   - Decoupled from transport specifics (can be tested in memory).
3. **Adapters & Binaries (`agent-sign`, `agent-git`, `agent-signd`)**:
   - Outer shell responsible for parsing CLI arguments, reading OS environment, connecting to Unix domain sockets, and spawning child processes.
   - Thin translation layers between OS interfaces and the Core Domain.

### 1.2. The Fail-Closed Security Doctrine
* Any failure in cryptographic signature creation, lease validation, or socket communication **must terminate execution with a non-zero exit code and an informative stderr message**.
* **Never** fall back to signing with an unverified key or bypassing verification on error.
* **Never** print private key material, tokens, or secret hashes to stdout, stderr, or logs.

### 1.3. Sub-Millisecond Latency Budget
* Git signing shims execute on every commit and Git operation.
* Every millisecond of latency is felt by developers and agents:
  * Static dispatch and minimal heap allocations.
  * Unix Domain Sockets (`AF_UNIX`) over localhost TCP.
  * Fast JSON framing with newline delimiters (`\n`).
  * Process startup overhead target: `< 5ms`.

---

## 2. Security & File System Permissions

1. **Restricted Runtime Directories**:
   * All runtime sockets, keys, and session states must live in `~/.agent-sign/`.
   * Directory permissions: strictly `0700` (`rwx------`).
   * Private key file permissions: strictly `0600` (`rw-------`).
   * Sockets: strictly `0600` (`rw-------`) accessible only by the current user.
2. **Ephemeral Event Tokens**:
   * Tokens must be single-use (consumed immediately upon signature).
   * Unused tokens expire automatically after 60 seconds.
   * Cryptographically random using OsRng / CSPRNG.

---

## 3. Error Handling & Robustness

* **No Unhandled Panics**: Never call `.unwrap()` or `.expect()` in runtime daemon or shim paths where user input, socket drops, or malformed Git buffers can occur.
* Use explicit `Result<T, AgentSignError>` types with clear context.
* Always clean up stale socket files (`unlink`) before binding the Unix listener.
* Handle `SIGINT` and `SIGTERM` gracefully in the daemon.

---

## 4. Testing & Verification Hierarchy

* **Unit Tests**: Test core domain logic (crypto, lease state transitions, attribution string templates) in memory.
* **Integration Tests**: Test Unix socket communication and multiplexer decisions.
* **End-to-End (E2E) Tests**: Spin up a real temporary Git repository using system `git`, execute actual commits, and verify signature validity via `/usr/bin/ssh-keygen -Y verify`.
