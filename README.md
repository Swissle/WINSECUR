# WINSECUR
all in one windows defensive security tool. 

# MADE FOR WINDOWS ONLY
functionality:
Collect detailed system information (OS, version, architecture, hostname, user)

Capture full systeminfo output

Enumerate installed programs from registry (32-bit and 64-bit)

List all Windows services with state, start mode, and executable path

List loaded drivers

Check digital signatures of critical binaries

Enumerate scheduled tasks

Enumerate autorun registry keys (Run and RunOnce)

Capture running processes and parent-child relationships

Capture network connections and map ports to PIDs

Flag unusual network activity (e.g., many listening ports)

Capture System, Application, and Security event logs

Capture Microsoft Defender status (Antivirus enabled, real-time protection, last scan, versions)

Compute SHA-256 hashes for critical system binaries

Create and compare baselines of critical binaries

Detect missing or altered critical binaries

Flag suspicious strings in autoruns (e.g., cheat tools, debugging tools)

Apply custom regex-based rules to autoruns, services, netstat, and event logs

Save all collected information in timestamped folders

Generate JSON summary of audit

Generate HMAC signature for audit integrity

Optionally zip audit results

Launch local web preview of audit results

Command-line options for full audit, baseline creation/comparison, zipping, and web preview
