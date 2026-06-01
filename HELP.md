package main

import "fmt"

func ShowHelpScreen() {
    fmt.Println("Help menu")
}
---

## 📊 1. Control Panel (Left Side)

This is the command menu.

### Options

- **(1) Watch Mode**
  - Starts real-time filesystem monitoring
  - Detects file creation, modification, deletion

- **(2) Check Baseline**
  - Compares current system state with saved baseline
  - Detects file integrity changes

- **(3) Training Mode**
  - Simulated security events for testing
  - Used for learning detection behavior

- **(q) Exit**
  - Stops RuntimeGuard

---

## 📡 2. Live Events Panel (Center)

Displays real-time system activity.

### Example Events

- Watch mode active
- Filesystem event detected
- File modified: /path/to/file

### Event Types

- File created
- File modified
- File deleted
- Watch started/stopped

---

## 🧠 3. Learning / Analysis Panel (Right Side)

Explains detected activity.

### MITRE ATT&CK
- Maps behavior to known attack techniques
- If no match:
  - `[N/A] Unmapped Activity`

### WHAT HAPPENED
- Raw system event description

### WHY IT MATTERS
- Explains if activity is normal or suspicious

### CONCEPT
- Security concept being triggered
- Example: File Integrity Monitoring (FIM)

---

## 🔄 Data Flow

Filesystem Event
→ Watcher (fsnotify)
→ Event Pipeline
→ Detector / Analyzer
→ MITRE Mapping
→ Risk Scoring
→ UI Display

---

## 🧱 System Summary

RuntimeGuard is a lightweight EDR system that:

- Monitors filesystem changes
- Builds and checks baselines
- Detects suspicious behavior
- Maps events to MITRE ATT&CK (when possible)
- Displays everything in a real-time terminal UI

---

## 🛡 Key Idea

| Component | Purpose |
|----------|--------|
| Watcher | Captures raw system events |
| Pipeline | Processes events |
| Detector | Analyzes behavior |
| MITRE Engine | Maps attack patterns |
| UI | Displays security insights |

---

## ⚠️ Note
This UI simulates real SOC/EDR dashboards used in cybersecurity operations centers.
