<div align="center">
  <img src="logo/logo.png" alt="SentryAVTT Logo" width="120"/>
  <h1>SentryAVTT</h1>
  <p><strong>Real-time antivirus and threat detection engine for Windows</strong></p>
  <p>
    <img src="https://img.shields.io/badge/Rust-1.80%2B-orange?logo=rust" alt="Rust"/>
    <img src="https://img.shields.io/badge/.NET-9.0-512BD4?logo=dotnet" alt=".NET 9"/>
    <img src="https://img.shields.io/badge/Status-Alpha-yellow" alt="Status Alpha"/>
    <img src="https://img.shields.io/badge/Platform-Windows-blue?logo=windows" alt="Windows"/>
  </p>
</div>

---

SentryAVTT is a Windows-native antivirus suite built with a **Rust core agent** background service and a **C# WPF desktop UI**. The two processes communicate over **Windows Named Pipes** using **Protocol Buffers** for structured, low-latency IPC. Threat signatures are stored in a local **SQLite** database that can be updated from MalwareBazaar and other threat feeds.

## Architecture

```
┌─────────────────────┐         ┌───────────────────────────────────┐
│  C# WPF UI          │         │  Rust Core Agent                 │
│  (user process)     │         │  (Windows Service / LocalSystem)  │
│                     │  Named  │                                   │
│  PipeClient.cs ─────┼─────────┼──▶ Named Pipe Server (tokio)     │
│                     │  Pipe   │       │                           │
│  Protobuf-net       │ \\.\    │       ├─ Session Manager          │
│  Bi-directional     │ pipe\   │       ├─ Request Router           │
│  streaming          │ Sentry  │       ├─ Event Broadcaster        │
│                     │ AVTT\   │       │                           │
│                     │ main    │       ├─ Scanner Engine           │
│                     │         │       │   ├─ SHA-256 Hashing      │
│                     │         │       │   ├─ YARA-ready (future)  │
│                     │         │       │   └─ Recursive Walker     │
│                     │         │       │                           │
│                     │         │       ├─ File Monitor (notify)    │
│                     │         │       ├─ Process Scanner (sysinfo)│
│                     │         │       ├─ Quarantine Manager       │
│                     │         │       └─ SQLite Database          │
└─────────────────────┘         └───────────────────────────────────┘
```

### Key Decisions

| Area | Choice | Rationale |
|------|--------|-----------|
| **IPC Transport** | Windows Named Pipes | Native ACL security, no firewall prompts, low latency |
| **Serialization** | Protocol Buffers | Cross-language, compact wire format, version-tolerant |
| **Async Runtime** | tokio | Mature Windows I/O support (named pipes, overlapped I/O) |
| **Database** | SQLite | Zero-install, single-file, ACID transactions |
| **Scan Engine** | SHA-256 hash lookup | Simple, effective; YARA integration ready for future |
| **File Monitoring** | `notify` crate | User-mode, no kernel driver needed |
| **Process Monitoring** | `sysinfo` crate | Cross-platform process enumeration |

## Project Structure

```
SentryAVTT/
├── Cargo.toml                  # Rust workspace root
├── README.md
├── logo/                       # Application branding
│   └── logo.png
├── proto/
│   └── sentryavtt.proto        # Canonical protobuf schema for IPC
├── core/                       # Rust core agent (sentryavtt-core)
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs             # Entry point, service lifecycle
│       ├── config.rs           # JSON config loader
│       ├── scanner/            # Threat detection engine
│       │   ├── mod.rs          # Scan orchestration
│       │   ├── hasher.rs       # SHA-256 hashing with retry logic
│       │   └── walker.rs       # Recursive directory scanner
│       ├── monitor/            # Real-time system monitoring
│       │   ├── filesystem.rs   # File creation/modification watcher
│       │   └── process.rs      # Process creation scanner
│       ├── db/                 # SQLite database layer
│       │   ├── mod.rs          # Connection management
│       │   ├── schema.rs       # Schema migrations & seed data
│       │   ├── threats.rs      # Threat hash lookup & recording
│       │   ├── scan_history.rs # Scan audit trail
│       │   └── updater.rs      # Signature DB updates (JSON/CSV)
│       ├── ipc/                # Named Pipe IPC server
│       │   ├── pipe_server.rs  # Listener & client handler
│       │   ├── message.rs      # Protobuf codec & envelope builders
│       │   ├── proto.rs        # Import for generated types
│       │   └── gen.rs          # Manual prost! message types
│       └── quarantine/         # Safe file isolation
│           └── mod.rs          # Quarantine/restore/delete operations
└── ui/
    └── SentryAVTT.UI/          # C# WPF desktop application
        ├── SentryAVTT.UI.csproj
        ├── App.xaml / .cs      # Application lifecycle
        ├── MainWindow.xaml / .cs  # Primary window with navigation
        ├── Pages/
        │   ├── AboutPage.xaml / .cs
        │   └── QuarantinePage.xaml / .cs
        ├── Services/
        │   ├── PipeClient.cs   # Low-level Named Pipe client
        │   ├── IpcService.cs   # High-level IPC event bridge
        │   └── ScanService.cs  # Scan orchestration (simulation)
        ├── ViewModels/
        │   ├── DashboardViewModel.cs
        │   ├── AdminConsoleViewModel.cs
        │   └── QuarantineViewModel.cs
        ├── Models/
        │   └── ScanResult.cs   # ScanStatus, ProcessEntry, DashboardStats
        ├── Ipc/
        │   └── Proto.cs        # C# protobuf message definitions
        ├── Converters/
        │   └── StatusConverters.cs
        └── Styles/
            └── ModernStyles.xaml
```

## Features

### Core Agent (Rust)
- **On-demand scanning** — Recursive directory walk with SHA-256 hash verification against a threat database
- **Real-time file monitoring** — Watches configured directories for new/modified files using the `notify` crate
- **Process monitoring** — Periodically scans active processes, comparing hashes and checking against a denylist
- **Quarantine** — Isolates threats by moving them to `C:\ProgramData\SentryAVTT\Quarantine\` with deny-ACL via `icacls`
- **SQLite threat database** — Persistent storage for signatures, scan history, and quarantine records
- **Threat feed updates** — Import signatures from JSON or MalwareBazaar CSV format
- **Windows Service support** — Register/unregister as a system service via `--install`/`--uninstall`

### Desktop UI (C# WPF)
- **Modern dark-themed dashboard** — Custom window chrome, Segoe MDL2 icons, responsive layout
- **Real-time status shield** — Color-coded status (green = protected, red = threat, yellow = scanning)
- **Stat cards** — Files scanned, threats blocked, processes monitored, quarantine count
- **Admin Console** — Toggleable live process scan log with data grid
- **Quarantine management** — Browse, restore, and delete quarantined items
- **Offline simulation mode** — UI works without the core agent for development/testing

### IPC Protocol
- **Named Pipe**: `\\.\pipe\SentryAVTT\main`
- **Framing**: 4-byte little-endian length prefix + protobuf-encoded envelope
- **Message types**: Requests (UI→Core), Responses (Core→UI), Events (Core→UI, unsolicited)
- **Bi-directional streaming**: Scan progress and threat events pushed in real-time

## Getting Started

### Prerequisites

- [Rust](https://www.rust-lang.org/) 1.80+ (install via [rustup](https://rustup.rs/))
- [.NET 9 SDK](https://dotnet.microsoft.com/download/dotnet/9.0)
- Windows 10/11 (the IPC server uses Windows-specific named pipe APIs)

### Build & Run

```powershell
# Build the Rust core agent
cd core
cargo build --release

# Run the core agent (as a standalone process)
..\target\release\sentryavtt-core.exe

# Run the WPF UI (in a separate terminal)
cd ..\ui\SentryAVTT.UI
dotnet run
```

### CLI Usage

```
sentryavtt-core                              Run the core agent
sentryavtt-core --install                    Register as Windows service
sentryavtt-core --uninstall                  Unregister Windows service
sentryavtt-core --update-db [url]            Update threat DB from JSON feed
sentryavtt-core --update-db-from-csv [url]   Update from MalwareBazaar CSV
sentryavtt-core --help                       Show help
```

### Updating Threat Signatures

```powershell
# From the default MalwareBazaar CSV feed
sentryavtt-core --update-db-from-csv

# From a custom JSON feed
sentryavtt-core --update-db https://example.com/threats.json
```

**JSON format**:
```json
[
  {"hash": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "threat_name": "EICAR-Test-File", "severity": 2}
]
```

**CSV format**: MalwareBazaar export format (`sha256_hash,file_name,signature,...`)

### Configuration

Default configuration is loaded from `C:\ProgramData\SentryAVTT\config.json`:

```json
{
  "watch_paths": ["C:\\SentryWatch"],
  "scan_interval_secs": 5,
  "process_denylist": ["malware.exe", "keylogger.exe", "coinminer.exe"],
  "max_file_size_bytes": 104857600,
  "quarantine_dir": "C:\\ProgramData\\SentryAVTT\\Quarantine"
}
```

## Database

The SQLite database is located at `C:\ProgramData\SentryAVTT\Data\sentryavtt.db` with the following tables:

| Table | Purpose |
|-------|---------|
| `threats` | Known threat signatures (hash, name, severity) |
| `scan_history` | Audit trail of scan operations |
| `quarantine` | Quarantined file records |
| `config` | Key-value settings persistence |

### Seeded Test Threats

The database comes pre-seeded with test signatures, including the **EICAR test file** hash — a standard anti-virus test string that is safe to use for verification.

## Safety & Risk Mitigation

This project operates **entirely in user space** — no kernel drivers, no BSOD risk. Key safety measures:

- **File scanning**: Opens with `FILE_SHARE_READ`, 30-second timeout, 64 KB chunked reads
- **File size limit**: 100 MB max per file (configurable)
- **Concurrent scans**: Throttled to prevent resource exhaustion
- **Quarantine**: Copy-then-delete strategy with ACL-based isolation
- **Path filtering**: Skips system directories, temporary files, and swap files
- **Process monitoring**: Read-only enumeration, no process termination without user action

## Technology Stack

| Component | Technology |
|-----------|------------|
| **Core Agent** | Rust, tokio, prost, rusqlite, notify, sha2, sysinfo |
| **Desktop UI** | C#, .NET 9, WPF, protobuf-net |
| **IPC** | Windows Named Pipes, Protocol Buffers |
| **Database** | SQLite (WAL mode) |
| **Serialization** | Protocol Buffers (prost Rust / protobuf-net C#) |

## Roadmap

- [x] Rust core agent skeleton with IPC server
- [x] SQLite schema, migrations, and threat DB
- [x] C# WPF dashboard with dark theme
- [x] SHA-256 signature scanning with recursive walker
- [x] Quarantine with file isolation and ACL locking
- [x] File system watcher for real-time monitoring
- [x] Process scanner with denylist and hash checking
- [x] Signature updater (JSON + MalwareBazaar CSV)
- [ ] YARA rule integration
- [ ] AMSI provider registration
- [ ] Windows Service integration (SCM)
- [ ] Cross-platform core (macOS/Linux)
- [ ] NSIS installer and code signing
- [ ] Scheduled scans and silent mode

## License

This project is for educational and security research purposes.
