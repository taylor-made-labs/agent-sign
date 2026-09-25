# Agent-Sign: Value Proposition & Product Commitments

- **Status**: Living Contract / Ground Truth
- **Version**: 1.0.0
- **Purpose**: Tracks the explicit promises made to developers and teams, and the measurable acceptance criteria required to claim success.

---

## 1. Executive Mission

`Agent-Sign` resolves the fundamental collision between **interactive human security** and **autonomous AI coding agent execution** in Git workflows.

We promise that developers can enable strict, cryptographic commit verification across all repositories without suffering repetitive biometric or hardware interrupts, without exposing their master credentials, and without misattributing human actions.

---

## 2. The 5 Target Workflows & Our Commitments

### Workflow 1: 1Password & Biometric Touch ID Users
* **The Reality Today**: Every time an autonomous agent creates an incremental commit, a macOS modal or 1Password window demands a fingerprint, halting execution and destroying developer focus.
* **Our Commitment**:
  * **One-Touch Session Leasing**: Prompt for Touch ID **once** at the start of a session/task, granting a cryptographically bound lease (e.g., 2 hours).
  * **Headless Subsequent Commits**: All subsequent commits during the lease sign silently in milliseconds.
  * **100% Human Isolation**: Any commit initiated directly by the human (via terminal shell or IDE GUI button) bypasses the agent lease and routes to 1Password with Touch ID as normal.

### Workflow 2: YubiKey & Physical Hardware Security Token Users
* **The Reality Today**: Security-conscious developers using FIDO2/PIV hardware tokens (`sk-ssh-ed25519` or OpenPGP smartcards) must physically reach over and touch the metal contact on their USB port for *every single commit*.
* **Our Commitment**:
  * **Delegated Sub-Key Delegation**: The physical token is touched once to authorize the local agent session; the agent operates with a sandboxed sub-key that cannot access authentication or SSH server access.

### Workflow 3: Traditional GPG & Pinentry Users
* **The Reality Today**: Subshell and tool-sandbox agent executions cannot handle interactive `pinentry` dialogs. The agent either crashes, hangs in an infinite wait loop, or silently passes `--no-gpg-sign`, creating untrusted commits.
* **Our Commitment**:
  * **Deterministic Non-Blocking Signing**: Replaces brittle `pinentry` terminal hooks with an asynchronous local daemon that speaks Git's standard `gpg.ssh.program` interface directly.

### Workflow 4: Enterprise & Regulated Teams (SOC2 / ISO 27001)
* **The Reality Today**: Organizations enforce GitHub branch protection (`Require signed commits`). When developers try to use AI agents, they are blocked, prompting engineering managers to either weaken repository rules or ban autonomous agent commits.
* **Our Commitment**:
  * **Unbroken Branch Protection**: All agent commits satisfy GitHub's cryptographic signature requirements, displaying the green "Verified" badge.
  * **Cryptographic Provenance**: Every commit provides tamper-evident audit trailers documenting agent model, session lease ID, and human supervisor.
  * **Policy Enforcement**: Built-in guardrails block direct commits to `main`/`master` and rate-limit runaway commit loops.
  * **Corporate Compliance Flexibility**: Configurable attribution modes (`trailers` mode for strict employee LDAP/SSO compliance; `split` mode for open-source transparency).

### Workflow 5: DevContainers, Docker & Remote SSH
* **The Reality Today**: Forwarding your master private key or full SSH agent socket into a container where an untrusted AI agent runs creates severe host blast-radius risk.
* **Our Commitment**:
  * **Zero Blast-Radius Signing**: The agent key is restricted strictly to signing Git objects. It cannot clone private repos, push to remotes, or open SSH shell sessions on servers.

---

## 3. Measurable Acceptance Criteria (How We Prove It)

To claim that `Agent-Sign` delivers on its value proposition, the system must continually satisfy the following measurable benchmarks:

| Benchmark | Target Metric | How It Is Verified |
| :--- | :--- | :--- |
| **Signing Latency** | < 10 milliseconds overhead per commit | End-to-end benchmark test comparing raw `git commit` to `agent-sign commit`. |
| **Prompt Frequency** | Exactly 1 prompt per lease duration (e.g. 2 hours) | Automated session test running 20 commits in succession with 0 intermediate interrupts. |
| **Human False-Positive Rate** | 0.00% | Automated test simulating human terminal and IDE GUI commits, ensuring 0% are intercepted by the agent key. |
| **GitHub Verification Rate** | 100% "Verified" badge compatibility | Cryptographic test validating output with `/usr/bin/ssh-keygen -Y verify` against allowed signers. |
| **Fail-Closed Security** | 100% fail-closed on invalid token / expired lease | Test suites verifying that corrupted, forged, or expired tokens reject signing without fallback. |

---

## 4. Explicit Anti-Goals (What We Will Never Do)

1. **Never weaken human security**: We will never recommend or automate disabling biometric prompts for the human's personal keys.
2. **Never store unencrypted master credentials**: The human's master SSH/GPG keys will remain solely inside their secure hardware vault (1Password / YubiKey / Secure Enclave).
3. **Never rely on the LLM's memory**: All interception and policy enforcement must be deterministic in the software runtime, never dependent on prompting the AI model to pass flags.
4. **Never create opaque lock-in**: Keys, signatures, and configs follow OpenSSH and Git native standards with zero proprietary lock-in.
