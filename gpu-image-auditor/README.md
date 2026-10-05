# GPU Image Security Auditor

A lightweight Linux security auditor and remediation engine for **GPU / AI infrastructure**.

The project inspects a GPU-enabled Linux host, identifies security-relevant configuration and exposure, produces a security score and remediation plan, and can safely apply selected remediations with validation and rollback.

The goal is not to build another generic vulnerability scanner. The goal is to understand and secure the **Linux host underneath AI/GPU workloads**.

---

## Why This Project?

GPU infrastructure is increasingly used for AI training, inference, research, and distributed workloads.

A GPU server is still a Linux server — which means the security of the underlying host matters just as much as the security of the ML software running on it.

A typical stack looks like:

```text
┌──────────────────────────────────────┐
│        AI / ML Workloads             │
│  PyTorch · CUDA · Containers · etc. │
├──────────────────────────────────────┤
│       NVIDIA Driver / Runtime        │
├──────────────────────────────────────┤
│             Linux                    │
│  SSH · Services · Users · Network   │
├──────────────────────────────────────┤
│        GPU / Hardware                │
└──────────────────────────────────────┘
```

This project focuses primarily on the Linux security layer.

It answers questions such as:

* Is SSH configured securely?
* Is root SSH login permitted?
* Is password authentication enabled?
* Which services are listening on network interfaces?
* Is RPCbind unnecessarily exposed?
* Is Jupyter exposed outside localhost?
* Is SSH exposed outside the host?
* Are NVIDIA device nodes accessible to everyone?
* Are suspicious or unexpected network listeners present?
* What should be changed to improve the security posture?
* Can a remediation be applied without accidentally locking out the administrator?

---

# Features

## Security Auditing

The auditor collects system state and evaluates it against security policies.

### Host information

Currently reports:

* Operating system
* Linux kernel
* NVIDIA GPU
* NVIDIA driver
* CUDA version

Example:

```text
SYSTEM
----------------------------------------
OS:     Ubuntu 22.04.5 LTS
Kernel: 6.8.0-1046-nvidia
GPU:    NVIDIA A10
Driver: 580.105.08
CUDA:   13.0
```

---

## SSH Security

The auditor examines the **effective SSH configuration**, rather than relying only on raw configuration files.

For example:

```bash
sudo sshd -T
```

This is important because OpenSSH configuration can be affected by:

* `sshd_config`
* configuration drop-ins
* configuration ordering
* cloud-init/provider configuration

Current checks include:

* Root SSH login
* SSH password authentication
* SSH network exposure
* Current SSH sessions
* Login history
* Failed login attempts

Example:

```text
[PASS] SSH-001 SSH root login disabled
    permitrootlogin no

[PASS] SSH-002 SSH password authentication disabled
    passwordauthentication no
```

---

# Network Exposure Detection

The auditor uses Linux's socket information to discover listening TCP and UDP services.

Internally it uses:

```bash
ss -lntup
```

The output is normalized into C++ structures such as:

```cpp
struct Listener {
    std::string protocol;
    std::string address;
    int port;
    std::string process;
    bool externallyBound;
};
```

The auditor distinguishes between:

```text
127.0.0.1:7000
```

and:

```text
0.0.0.0:7000
```

The first is loopback-only.

The second is bound to non-loopback interfaces.

### Important distinction

`externallyBound` means the service is **not restricted to loopback at the host socket level**.

It does **not** necessarily mean the service is reachable from the public Internet.

Cloud/provider firewalls, security groups, routing, and other network controls may still prevent external access.

---

# Security Checks

Current checks include:

| ID        | Check                       | Severity           |
| --------- | --------------------------- | ------------------ |
| `SSH-001` | SSH root login              | PASS / WARN / HIGH |
| `SSH-002` | SSH password authentication | PASS / WARN        |
| `NET-001` | Host firewall status        | PASS / WARN        |
| `NET-002` | RPCbind exposure            | PASS / HIGH        |
| `NET-003` | Jupyter exposure            | PASS / HIGH        |
| `NET-004` | SSH network exposure        | PASS / WARN        |
| `NET-005` | Unknown external listeners  | PASS / WARN        |
| `NET-006` | No external listeners       | PASS               |
| `GPU-001` | NVIDIA GPU availability     | PASS / INFO        |
| `GPU-002` | NVIDIA device permissions   | PASS / WARN        |
| `SVC-001` | Docker accessibility        | INFO               |

---

# Security Scoring

The auditor starts from a score of:

```text
100
```

Findings can subtract points depending on severity and risk.

For example:

```text
HIGH    → significant deduction
WARN    → moderate deduction
INFO    → informational only
PASS    → no deduction
```

The scoring system is intentionally simple.

The important part is that **multiple pieces of evidence representing the same underlying problem are aggregated into one finding**.

For example, RPCbind may appear as:

```text
0.0.0.0:111
[::]:111
```

over multiple protocols.

These are not four independent vulnerabilities.

They are evidence of one underlying issue:

```text
RPCbind is externally exposed
```

Therefore the auditor creates one finding:

```text
[HIGH] NET-002 RPCbind exposed on wildcard interface
```

This prevents the security score from being artificially distorted by the number of sockets associated with the same service.

---

# SSH Activity Monitoring

The auditor also collects Linux authentication activity.

### Current sessions

Uses:

```bash
who
```

### Login history

Uses:

```bash
last
```

### Failed login attempts

Uses:

```bash
lastb
```

This allows the auditor to report information such as:

```text
SSH SECURITY SUMMARY
----------------------------------------
Current SSH sessions: 1
Successful logins:    3
Failed attempts:      17
```

The failed-login data is useful for detecting brute-force activity and suspicious authentication patterns.

---

# Remediation Engine

The project is evolving from a passive auditor into a security enforcement system.

The key design principle is:

> **Audit first. Plan second. Apply carefully. Verify afterward.**

The architecture is:

```text
                 ┌─────────────────┐
                 │     Linux Host   │
                 └────────┬────────┘
                          │
                          ▼
                 ┌─────────────────┐
                 │    Collector    │
                 │                 │
                 │ SSH · Network   │
                 │ GPU · Services  │
                 └────────┬────────┘
                          │
                          ▼
                 ┌─────────────────┐
                 │  Policy Engine  │
                 └────────┬────────┘
                          │
                          ▼
                     Findings
                          │
                          ▼
                 ┌─────────────────┐
                 │   Remediation   │
                 │     Engine      │
                 └────────┬────────┘
                          │
                ┌─────────┴─────────┐
                ▼                   ▼
             Apply                Verify
                │                   │
                └─────────┬─────────┘
                          ▼
                       Re-audit
```

---

# Remediation Plans

The auditor can translate findings into remediation actions.

Example:

```text
REMEDIATION PLAN
========================================

[REM-001] Disable SSH root login
Finding: SSH-001
Risk: HIGH
Requires sudo: yes
Requires reboot: no

Action:
  Set PermitRootLogin to 'no' in the SSH configuration,
  validate the configuration, then reload SSH.

[REM-003] Disable externally exposed rpcbind
Finding: NET-002
Risk: HIGH
Requires sudo: yes
Requires reboot: no

Action:
  Stop and disable rpcbind/rpcbind.socket if RPC services
  are not required.
```

The plan provides a human-readable bridge between:

```text
Security finding
       ↓
Recommended action
```

before any system modification occurs.

---

# Safe SSH Enforcement

One of the first implemented remediations is:

```text
REM-001
Disable SSH root login
```

This is deliberately implemented with several safety checks.

The workflow is:

```text
        Backup existing configuration
                    │
                    ▼
             Write policy
                    │
                    ▼
          Validate sshd syntax
                    │
                    ▼
       Verify effective SSH policy
                    │
                    ▼
             Reload SSH
                    │
                    ▼
      Verify effective policy again
                    │
                    ▼
               SUCCESS
```

If any validation step fails:

```text
              Apply
                │
                ▼
            Validation
                │
          ┌─────┴─────┐
          │           │
        PASS        FAIL
          │           │
          ▼           ▼
       Reload      Rollback
                      │
                      ▼
                   Verify
```

This is particularly important because the project is designed to run on **remote GPU machines**.

A careless SSH configuration change can lock the administrator out of the machine.

---

# Why Not Just Edit `/etc/ssh/sshd_config`?

The implementation intentionally creates a dedicated configuration drop-in:

```text
/etc/ssh/sshd_config.d/99-gpu-auditor.conf
```

For example:

```text
# Managed by GPU Image Security Auditor
# Remediation: REM-001
PermitRootLogin no
```

The enforcer then checks:

```bash
sudo sshd -t
```

before reloading SSH.

It also checks the **effective configuration**:

```bash
sudo sshd -T
```

rather than assuming that writing the configuration file was sufficient.

This matters because Linux services can have configuration layering and provider-managed configuration.

---

# Rollback

Before modifying an existing remediation file, the enforcer creates a backup:

```text
99-gpu-auditor.conf.gpu-auditor-backup
```

If validation fails, the enforcer attempts to restore the previous state.

This gives remediation a transaction-like structure:

```text
        Backup
           ↓
         Apply
           ↓
       Validate
           ↓
        Verify
           ↓
         Commit
```

rather than simply:

```text
write file → hope it works
```

---

# CLI

The current interface is intentionally small.

## Run an audit

```bash
./gpu-image-auditor audit
```

or simply:

```bash
./gpu-image-auditor
```

---

## Generate a remediation plan

```bash
./gpu-image-auditor plan
```

This does **not** modify the machine.

---

## Apply supported remediations

```bash
./gpu-image-auditor enforce
```

The program displays the proposed changes and asks for confirmation before making modifications.

Example:

```text
WARNING: This will modify the system.
Supported remediation(s) may change SSH configuration.
A backup will be created before modification.

Continue? [y/N]:
```

After enforcement, the auditor performs another security audit.

This allows the user to see whether the security score actually improved.

---

# Example Workflow

A typical workflow is:

```bash
# 1. Inspect the machine
./gpu-image-auditor audit

# 2. Review recommended changes
./gpu-image-auditor plan

# 3. Apply supported changes
./gpu-image-auditor enforce

# 4. Verify the resulting security posture
./gpu-image-auditor audit
```

Conceptually:

```text
BEFORE

Security Score: 52/100

[HIGH] SSH root login
[WARN] Firewall inactive
[HIGH] RPCbind exposed
[WARN] NVIDIA device permissions


             │
             │ remediation
             ▼


AFTER

Security Score: 82/100

[PASS] SSH root login disabled
[WARN] Firewall inactive
[WARN] NVIDIA device permissions
```

The score is only a summary. The individual findings remain the important security information.

---

# Architecture

The project is written in **C++17**.

The code is intentionally split into collection, policy, remediation, and orchestration responsibilities.

```text
main.cpp
   │
   ├── CLI
   ├── Audit orchestration
   ├── Remediation orchestration
   └── Reporting
          │
          ▼
checks.cpp
   │
   ├── Linux system collectors
   ├── Network listener collection
   ├── SSH activity collection
   ├── Security policy checks
   ├── Security scoring
   └── Remediation engine
          │
          ▼
checks.h
   │
   ├── SystemInfo
   ├── Listener
   ├── Finding
   ├── SSHSession
   ├── SSHLogin
   ├── SSHFailedAttempt
   ├── Remediation
   └── RemediationResult
```

---

# Linux Integration

Rather than attempting to abstract Linux away, the project intentionally interacts with the operating system.

Examples include:

```text
uname
/etc/os-release
nvidia-smi
ss
who
last
lastb
sshd -T
sshd -t
systemctl
ufw
stat
```

This makes the project useful as a practical exercise in understanding how Linux exposes system state to applications.

---

# GPU-Specific Security

GPU infrastructure introduces additional security considerations beyond a normal Linux server.

The auditor currently checks:

```text
NVIDIA GPU availability
        │
        ▼
NVIDIA device nodes
        │
        ▼
File permissions
```

For example:

```bash
ls -l /dev/nvidia*
```

can expose permissions such as:

```text
crw-rw-rw- root root /dev/nvidia0
```

A world-accessible NVIDIA device node is reported as a warning because it may allow broader-than-intended access to GPU resources.

However, the project deliberately does **not** simply execute:

```bash
chmod 660 /dev/nvidia0
```

as a permanent solution.

NVIDIA device nodes can be created dynamically, so persistent enforcement needs to consider:

* udev rules
* device groups
* NVIDIA services
* container runtimes
* NVIDIA Container Toolkit
* device creation lifecycle

This is an area planned for future versions.

---

# Current Limitations

This is an actively evolving project.

### Firewall

The auditor can detect that UFW is inactive, but it does not automatically enable or reconfigure the firewall.

This is intentional.

On a remote GPU machine, blindly enabling a firewall can:

* terminate connectivity
* block SSH
* conflict with provider-level firewall rules
* create an inconsistent security policy

---

### Docker

Docker is detected, but container-level security inspection is not yet implemented.

Future checks will include:

```text
Privileged containers
Root containers
Linux capabilities
Host networking
Host PID namespace
Host filesystem mounts
Docker socket exposure
GPU device exposure
```

---

### NVIDIA Device Permissions

GPU device permission remediation is currently planned but not automatically enforced.

Persistent device permission management requires understanding how the NVIDIA driver and udev create the device nodes.

---

### Internet Reachability

The auditor currently detects whether a service is bound to a non-loopback interface.

It does not claim to determine whether the service is reachable from the public Internet.

That requires additional information such as:

```text
Cloud firewall
Security groups
Routing
NAT
Provider networking
```

---

# Roadmap

## v0.1 — Host Security Audit

* [x] Linux system information
* [x] NVIDIA GPU detection
* [x] NVIDIA driver/CUDA detection
* [x] Listening socket discovery
* [x] SSH configuration checks
* [x] Firewall detection
* [x] GPU device permission checks
* [x] Security scoring

## v0.2 — Security Intelligence

* [x] Current SSH sessions
* [x] Login history
* [x] Failed authentication attempts
* [x] Network listener normalization
* [x] Finding aggregation
* [x] Remediation plan generation

## v0.3 — Remediation Engine

* [x] Remediation model
* [x] `plan` command
* [x] `enforce` command
* [x] Backup before modification
* [x] Configuration validation
* [x] Effective-state verification
* [x] SSH root-login remediation
* [x] Post-enforcement audit

## v0.4 — Host Hardening

* [ ] SSH password authentication remediation
* [ ] RPCbind remediation
* [ ] Safer SSH network policy
* [ ] Firewall policy generation
* [ ] Firewall apply/verify/rollback
* [ ] Improved rollback management

## v0.5 — GPU Security

* [ ] Persistent NVIDIA device permissions
* [ ] udev policy inspection
* [ ] GPU access groups
* [ ] NVIDIA service security
* [ ] GPU/container boundary checks

## v0.6 — Container Security

* [ ] Privileged container detection
* [ ] Root container detection
* [ ] Linux capability analysis
* [ ] Host namespace checks
* [ ] Host mount checks
* [ ] Docker socket exposure
* [ ] NVIDIA Container Toolkit checks

## v1.0 — AI Infrastructure Security Platform

* [ ] JSON output
* [ ] Machine-readable findings
* [ ] CI/CD security gate
* [ ] Image provenance
* [ ] Package inventory
* [ ] CVE integration
* [ ] Security policy configuration
* [ ] Automated remediation workflows

---

# Future: Image Provenance

The next major direction is moving beyond host configuration.

A GPU/AI environment is composed of multiple software layers:

```text
Ubuntu
   ↓
Linux Kernel
   ↓
NVIDIA Driver
   ↓
CUDA
   ↓
cuDNN / NCCL
   ↓
PyTorch / TensorFlow
   ↓
Python dependencies
   ↓
Container Image
   ↓
AI Workload
```

A future version will generate an infrastructure/software provenance record containing information such as:

```text
OS
Kernel
GPU
NVIDIA Driver
CUDA
ML Framework
Package Versions
Container Image
Image Digest
```

This can then feed into vulnerability scanning and CI/CD policy enforcement.

---

# Design Principles

The project follows several principles.

### 1. Evidence before policy

The collector gathers raw Linux state first.

```text
Linux state
    ↓
Structured facts
    ↓
Policy evaluation
    ↓
Finding
```

This keeps data collection separate from security decisions.

---

### 2. A finding represents a security issue

A socket is evidence.

A finding represents the underlying security problem.

For example:

```text
4 sockets
   ↓
1 rpcbind service
   ↓
1 security finding
```

This avoids double-counting.

---

### 3. Effective configuration matters

For configuration-driven services, the auditor tries to inspect the state the service actually uses.

For SSH:

```bash
sshd -T
```

is more meaningful than simply searching for a line in a configuration file.

---

### 4. Remediation must be safer than the vulnerability

Security automation can create a worse problem if it locks administrators out.

Therefore the enforcer follows:

```text
Backup
   ↓
Apply
   ↓
Validate
   ↓
Verify
   ↓
Reload
   ↓
Verify again
   ↓
Re-audit
```

---

### 5. Don't pretend provider security doesn't exist

A host-level auditor cannot see every layer of a cloud GPU environment.

The project explicitly distinguishes:

```text
Host security
        +
Cloud/provider security
        +
Container security
        +
Application security
```

rather than incorrectly treating host configuration as the complete security posture.

---

# Building

Requirements:

* Ubuntu/Linux
* C++17 compiler
* NVIDIA GPU is optional for development
* `ss`
* `openssh-server` for SSH checks
* `nvidia-smi` for GPU checks
* `sudo` for privileged inspection/remediation

Build with:

```bash
g++ -std=c++17 -Wall -Wextra -O2 \
    main.cpp checks.cpp \
    -o gpu-image-auditor
```

Run:

```bash
./gpu-image-auditor audit
```

---

# Example Environment

The project was developed and tested against a Linux GPU host running:

```text
Ubuntu:       22.04.5 LTS
Kernel:       6.8.x NVIDIA kernel
GPU:          NVIDIA A10
Driver:       580.x
CUDA:         13.0
```

The implementation is intended to remain useful across Linux GPU environments rather than being tightly coupled to one provider.

---

# What I Learned Building This

This project started as a simple question:

> "How do I make a GPU server more secure?"

It evolved into a practical exploration of how Linux actually exposes and manages infrastructure state.

The project touches:

* Linux process/service management
* TCP/UDP sockets
* IPv4/IPv6 address parsing
* SSH configuration
* Linux authentication logs
* Unix permissions
* NVIDIA device nodes
* systemd
* privilege boundaries
* C++ systems programming
* security policy design
* remediation safety
* rollback strategies
* cloud infrastructure considerations

One of the most important lessons was that **security automation is not simply about changing configuration**.

A useful security tool must also understand:

```text
What is the current state?
        ↓
What is the desired state?
        ↓
What change is required?
        ↓
Can the change be applied safely?
        ↓
Did the system actually reach the desired state?
        ↓
What happens if it didn't?
```

That is the direction this project is continuing toward.

---

# Project Status

**Current status: Early prototype / active development**

The auditor is functional for host-level security inspection and has a working remediation framework with a safely implemented SSH hardening action.

The next focus is expanding the remediation engine while maintaining the same safety model:

```text
Discover → Evaluate → Plan → Backup → Apply → Verify → Re-audit
```

---

# License

MIT License
