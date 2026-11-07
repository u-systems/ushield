# µShield (ushield)

> *Status: Work In Progress (WIP) — Active Pre-v0.1 Development*

**µShield** is an ultra-lightweight, high-performance **Synthetic Kernel Emulation & Hot-Patchable Sandbox Engine** written in pure C (C11). Designed to completely bypass heavy container runtime stacks (Docker, containerd) and high-overhead VM emulators (gVisor, QEMU), µShield operates via direct cooperation between a privilege-separated user-space daemon (`ushieldd`) and a custom Ring 0 Linux Kernel Module (`ushield.ko`) powered by eBPF LSM hooks.

By collapsing every system boundary—syscalls, file descriptors, filesystem paths, registers, environment variables, and kernel interfaces—into a universal policy matrix, µShield provides gVisor-like virtualization control and Frida-like live dynamic hooking at native Ring 0 execution speed.

---

## Architecture Overview

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│ USERSPACE (ushieldd - Privilege-Separated Control & API Engine)             │
│                                                                             │
│  ┌─────────────────────────────┐         ┌──────────────────────────────┐   │
│  │ ushieldd-http (API/Web UI)  │         │ ushieldd-core (Master)       │   │
│  │ • Unprivileged (UID 1000)   │  socket │ • Master Supervisor (UID 0)  │   │
│  │ • Self-Sealed (No /dev)     │◄─pair──►│ • Handles /dev/ushield       │   │
│  │ • Serves REST API / Web UI  │   IPC   │ • Executes Ring 3 Hooks  ────┼   │
│  └─────────────────────────────┘         └──────────────┬───────────────┘   │
└─────────────────────────────────────────────────────────┼───────────────────┼
                                                          │ /dev/ushield      │
                                                          │ (IOCTL / mmap)    │ Ring 3 Upcall
┌─────────────────────────────────────────────────────────┴───────────────────┼┐ Loop
│ KERNELSPACE (ushield.ko - Ring 0 Control & Emulation Plane)                 ││ (Hook Execution)
│                                                                             ││
│  ┌───────────────────────────────────────────────────────────────────────┐  ││
│  │ LAYERED ENVIRONMENT DEFINITION ENGINE (Base + Stackable Deltas)       │  ││
│  │   [ Base Template ] ──► [ Delta 1: Mounts ] ──► [ Delta 2: Syscalls ] │  ││
│  └──────────────────────────────────┬────────────────────────────────────┘  ││
│                                     │ Evaluates Policy                      ││
│  ┌──────────────────────────────────▼────────────────────────────────────┐  ││
│  │ UNIVERSAL ENFORCEMENT & EMULATION MATRIX                              │  ││
│  │   Primitives: (ALLOW | DENY | HOOK) | LOG                             │  ││
│  │   Targets:    Syscalls, File Descriptors, Files, Memory (mmap), Regs  │  ││
│  └──────────────────────────────────┬────────────────────────────────────┘  ││
│                                     │ Intercepts & Dispatches Upcall        ││
│  ┌──────────────────────────────────▼────────────────────────────────────┐  ││
│  │ • Intercepts Syscall / Resource Access ───────────────────────────────┼──┘│
│  │ • Packs Execution Context (ushield_hook_ctx: Syscall NR, Args, Regs)  │   │
│  │ • Suspends Target Thread ──► Dispatches Upcall to Ring 3 Handler      │   │
│  │ • Applies Synthetic Return / Fault Injection ──► Resumes Target       │   │
│  │ • Pre-Exec Target Child Sealing (Zero-Instruction Window Lock)        │   │
│  │ • Lockless Nanosecond Telemetry Streaming (mmap Ring Buffer)          │   │
│  └───────────────────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## Key Technical Specifications

### 1. Privilege-Separated User-Space Controller (`ushieldd`)

- **Zero External Dependencies:** Statically linked C11 binary.
- **Privilege Separation (PrivSep):** The daemon splits into two isolated execution contexts upon launch:
    1. **`ushieldd-core` (Master Supervisor):** Runs as `root` (UID 0), registers with `ushield.ko`, retains exclusive administrative access to `/dev/ushield`, acts as an internal RPC router, and executes Ring 3 upcall hook handlers.
    2. **`ushieldd-http` (API Worker):** Spawns via `fork()`, drops privileges to an unprivileged user (`nobody`/`uid 1000`), closes `/dev/ushield` descriptors, and self-seals via `USHIELD_IOC_SEAL_SELF`.
- **Isolated Control IPC:** `ushieldd-http` communicates with `ushieldd-core` strictly across an anonymous `AF_UNIX` `socketpair` IPC bridge. An RCE in the Web stack cannot issue `ioctl` commands or tamper with Ring 0.
- **Embedded Control Plane:** Embedded Single-Page Web UI served directly from C bytecode. Simple file-based configuration via `ushield.conf`.

### 2. Layered Environment Engine (Base Templates + Delta Layers)

- **Base Layers:** Environments are constructed starting from a fundamental host visibility profile:
  - `USHIELD_BASE_BARE`: Empty root filesystem with minimal standard dev stubs.
  - `USHIELD_BASE_MINIMAL`: Stripped distribution base containing essential runtime libraries (`glibc`).
  - `USHIELD_BASE_HOST_REFLECT`: Full host system reflection with read-only copy-on-write (COW) file semantics.
- **Stackable Delta Layers:** Sequential, non-destructive modifications stacked on top of the base layer:
  - Dynamic mount additions/masking (e.g. mask `/etc/shadow`, isolate `/tmp` as `tmpfs`).
  - Environment variable filter/injection lists.
  - Asymmetric namespace isolation (`CLONE_NEWPID`, `CLONE_NEWNET`, `CLONE_NEWNS`).

### 3. Universal Policy Matrix: `(ALLOW | DENY | HOOK) | LOG`

Every monitored resource (Syscalls, File Descriptors, Filesystem Paths, Registers, Kernel Interfaces) is governed by an orthogonal 2-bit action tuple:
- **`ALLOW`**: Permit operation to pass down to the host Linux kernel.
- **`DENY`**: Intercept and block operation (default action: send `SIGKILL` or return custom `override_errno` such as `-EPERM`, `-EACCES`, or `-ENOENT`).
- **`HOOK`**: Bypass host kernel implementation entirely and dispatch execution to registered user-space (Ring 3) handlers, synthesizing responses or injecting emulated state.
- **`LOG`** (Bitwise Flag): Stream zero-copy nanosecond telemetry events to user space regardless of the action taken.

### 4. Ring 3 Programmable Upcall Hooking & Hot-Patching Engine

- **Zero-Kernel-Recompile Hot-Patching:** Modify binary execution behavior live from Ring 3 without unloading `ushield.ko` or writing kernel code. Write standard C functions in user space to hot-patch kernel responses dynamically.
- **Standardized Execution Frame (`ushield_hook_ctx`):** When an operation is set to `HOOK`, Ring 0 traps the target thread and packs its exact execution context into an ABI-aligned frame:
  ```c
  struct ushield_hook_ctx {
      uint32_t target_pid;
      uint32_t syscall_nr;
      uint64_t args[6];         /* Register arguments (rdi, rsi, rdx, r10, r8, r9) */
      uint64_t instruction_ptr; /* Target RIP */
      uint32_t resource_type;   /* SYSCALL, FD, FILE, NET, REG */
  };
  ```
- **Synchronous Upcall Execution Loop:**
  $$\text{Target Binary (Ring 3)} \xrightarrow{\text{Syscall}} \text{Ring 0 Trap} \xrightarrow{\text{Fast IPC Upcall}} \text{Ring 3 Hook Handler} \xrightarrow{\text{Synthetic Result}} \text{Ring 0} \xrightarrow{\text{Resume/Return}} \text{Target Binary}$$
  1. Target binary triggers a hooked resource/syscall.
  2. Ring 0 freezes the target thread and dispatches the packed `ushield_hook_ctx` frame to the registered Ring 3 handler via fast IPC.
  3. Ring 3 handler evaluates inputs in standard user-space C logic and returns synthetic output data (e.g., custom return value, fake buffer, or fault code).
  4. Ring 0 patches the target's return registers and unblocks target thread execution instantly.

### 5. Synthetic Kernel Emulation & Inline Fault Injection

- **Host Kernel Exploit Mitigation:** Mitigates kernel-sharing vulnerabilities inherent to Docker/containerd. Untrusted binaries calling risky or un-vetted kernel subsystems (e.g., `io_uring`, `bpf`) are trapped in Ring 0 and answered by synthetic emulation handlers without ever executing host kernel code paths.
- **Programmable Fault Injection & Software Fuzzing:** Stress-test binary error-handling paths by dynamically forcing syscall failure states, injecting custom return codes, or simulating hardware I/O failures.

### 6. Ring 0 Introspection & Event-Driven Hot-Patching

- **Live Execution Control:** Atomic `USHIELD_IOC_PAUSE_TARGET` and `USHIELD_IOC_RESUME_TARGET` control allows supervisors to freeze target binaries mid-execution (`SIGSTOP`/LSM hold) for deep inspection.
- **Deep Memory & FD Visibility:** Full visibility into target process memory structures (`task_struct->mm->mmap`) and file descriptor tables (`files_struct`), enabling live memory dumps and transparent I/O tapping across `stdin`, `stdout`, `stderr`, and network sockets.
- **Stateful Hot-Patching:** Dynamic policy updates in Ring 0 based on runtime telemetry triggers (e.g., automatically transition a syscall rule from `ALLOW` to `HOOK` after $N$ calls).

---

## API & Control Capabilities

The REST API (and matching Web UI) exposes complete control over the sandbox engine:

| Endpoint Group | Description |
| --- | --- |
| **`POST /api/auth/login`** | Authenticates against `ushield.conf` creds; returns session token. |
| **`POST /api/binary/upload`** | Uploads target ELF binaries for sandboxed execution. |
| **`GET /api/binary/download`** | Retrieves stored binaries or execution artifacts. |
| **`POST /api/sandbox/create`** | Configures base templates, stackable delta layers, and universal policy matrices. |
| **`POST /api/sandbox/execute`** | Spawns sandboxed execution with pre-exec sealing and real-time telemetry streaming. |
| **`POST /api/sandbox/pause`** | Freezes a target process mid-execution (`SIGSTOP`) for live memory inspection. |
| **`POST /api/sandbox/resume`** | Resumes execution of a paused target process (`SIGCONT`). |
| **`POST /api/sandbox/hotpatch`** | Dynamically updates target rule matrices and Ring 3 hooks in Ring 0 while process is running. |
| **`GET /api/telemetry/stats`** | Fetches low-latency ring buffer metrics and intercepted syscall/emulation logs. |
| **`WS /api/sandbox/attach`** | Interactive real-time stream directly into running sandboxes. |

---

## Development Roadmap

- [x] **Phase 0:** Project layout, Makefile build system, and isolated QEMU/KVM dev VM setup.
- [x] **Phase 1:** Core LKM skeleton (`ushield.ko`) & character device registration (`/dev/ushield`).
- [ ] **Phase 2:** Bare-metal C daemon (`ushieldd`), `ushield.conf` parser, and embedded Web UI.
- [x] **Phase 3:** Zero-copy `mmap` ring buffer telemetry transport.
- [x] **Phase 4:** PrivSep daemon split, process hierarchy identity registry, and path-based target registration (`USHIELD_IOC_REGISTER_TARGET`).
- [ ] **Phase 5:** Universal Policy Matrix `(ALLOW | DENY | HOOK) | LOG` & eBPF LSM syscall interception with Ring 3 Upcall Hook Dispatcher (`USHIELD_IOC_REGISTER_HOOK` + `ushield_hook_ctx` loop).
- [x] **Phase 6:** Layered Environment Engine (Base Templates + Delta Layer Mount/Env stacker).
- [ ] **Phase 7:** Synthetic Kernel Emulation & Inline Fault Injection Engine (`DENY_ERRNO`, `EMULATE`).
- [ ] **Phase 8:** Ring 0 Target Introspection (VMA mmap dumping, FD tapping, atomic Pause/Resume).
- [ ] **Phase 9 (Future):** *Behavioral Sequence State Machines* — Ring 0 workflow triggers (e.g. stateful hot-patching when Syscall A is followed by Syscall B).
- [ ] **Phase 10 (Future):** HTTP library replaced by [`uhttp`](https://github.com/u-systems/uhttp) when production-ready.

---

## License & Authorship

Developed independently by [tralsesec](https://github.com/tralsesec) under [µSystems](https://github.com/u-systems). 

* **Kernel Module (`ushield.ko`):** Licensed under the GNU General Public License v2.0 (GPL-2.0).
* **User-Space Daemon (`ushieldd`):** Licensed under the MIT License.
