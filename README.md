# RuntimeGuard CLI

**RuntimeGuard** is a lightweight host-based security monitoring tool written in Go. It monitors critical system files, running processes, and network ports to detect tampering or unauthorized activity in real time.  

---

## Features

- ✅ File integrity monitoring with SHA256 baseline comparison  
- ✅ Process monitoring for critical system processes  
- ✅ Port monitoring to check open/listening ports  
- ✅ Systemd service integration for automatic background monitoring  
- ✅ Logs changes, warnings, and status information  

---

## Requirements

- Linux (tested on Kali Linux)  
- Go 1.20+ (for building from source)  
- sudo privileges for system-wide monitoring  

---

## Installation

Clone the repository:

```bash
git clone https://github.com/Tonihub24/runxguardstucli.git
cd runxguardstucli
