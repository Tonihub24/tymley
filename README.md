# Tymley

Tymley is a lightweight host-based behavioral detection and response platform written in Go. It provides timely visibility into file changes, process activity, and network exposure to help identify suspicious behavior before it becomes a security incident.

## Features

✅ File integrity monitoring using SHA256 baseline validation

✅ Behavioral process monitoring for unusual or unauthorized activity

✅ Network port monitoring and exposure detection

✅ Real-time event logging and alert generation

✅ MITRE ATT&CK–mapped telemetry and detections

✅ Baseline creation and system verification

✅ Terminal-based dashboard and monitoring interface

✅ Linux-first design with minimal resource usage

## Requirements

- Linux (tested on Kali Linux)
- Go 1.24+ (for building from source)
- sudo privileges for system-level monitoring features

## Installation

Clone the repository:

```bash
git clone https://github.com/Tonihub24/tymley.git
cd tymley
