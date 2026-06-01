package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"github.com/Tonihub24/RunxGuard/detector"
	"github.com/fsnotify/fsnotify"
	"github.com/shirou/gopsutil/v3/net"
	"github.com/shirou/gopsutil/v3/process"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

/* ================= VERSION ================= */

const Version = "1.0.0"

/* ================= GLOBALS ================= */
var (
	watchRunning    bool
	baselineRunning bool
	trainingRunning bool
)
var globalConfig Config

var baseDir string
var baselineFile string
var configFile string

var riskScore int
var webhookURL = ""
var lastAlert time.Time
var lastEvent = make(map[string]time.Time)
var watchedDirs = make(map[string]bool)
var httpClient = &http.Client{
	Timeout: 5 * time.Second,
}

/* ================= STRUCTS ================= */

/* ================= BANNER ================= */

func printHelp() {
	PrintBanner()
	fmt.Println("Usage: runtimeguard <command>")
	fmt.Println("")
	fmt.Println("init        - create baseline")
	fmt.Println("check       - verify system")
	fmt.Println("watch       - monitor directories")
	fmt.Println("processes   - list running processes")
	fmt.Println("ports       - show listening ports")
	fmt.Println("help        - show menu")
	fmt.Println("version     - show version")
}

func printVersion() {
	PrintBanner()
	fmt.Println("Version:", Version)
}

/* ================= MAIN ================= */

func main() {

	if len(os.Args) < 2 {
		printHelp()
		return
	}

	cmd := os.Args[1]

	switch cmd {
	case "monitor":
		setup()
		InitLogger()
		InitBus()

		PrintBanner()
		time.Sleep(2 * time.Second)

		StartPipeline()
		RunUI()

		select {} // keep alive

	case "init":
		setup()
		InitLogger()
		InitBus()

		initBaseline()

	case "check":
		setup()
		InitLogger()
		InitBus()

		checkBaseline()

	case "watch":
		setup()
		InitLogger()
		InitBus()

		go watchDirs()
		RunUI()

		select {} // keep alive

	case "daemon":
		setup()
		InitLogger()
		InitBus()

		runDaemon()

	case "ports":
		setup()
		InitLogger()

		listPorts()

	case "processes":
		setup()
		InitLogger()

		listProcesses()

	case "version":
		printVersion()

	case "help":
		printHelp()

	default:
		fmt.Println("Unknown command:", cmd)
		printHelp()
	}
}

/* ================= SETUP ================= */

func setup() {
	home, _ := os.UserHomeDir()

	baseDir = filepath.Join(home, ".runtimeguard")
	os.MkdirAll(baseDir, 0755)

	baselineFile = filepath.Join(baseDir, "baseline.json")
	configFile = filepath.Join(baseDir, "runtimeguard.json")

	// load config
	data, err := os.ReadFile(configFile)
	if err != nil {

		defaultConfig := `{
  "watch_dirs": [
    "/tmp",
    "/home"
  ],

  "suspicious_extensions": [
    ".sh",
    ".py",
    ".elf",
    ".bin",
    ".ps1"
  ],

  "suspicious_processes": [
    "nc",
    "netcat",
    "ncat",
    "hydra"
  ],

  "ignored_paths": [
    "/proc",
    "/sys",
    "/dev"
  ]
}`

		helpDoc := `# RuntimeGuard Configuration Guide

## watch_dirs
Directories monitored for filesystem activity.

Example:
"watch_dirs": ["/tmp", "/home"]

---

## suspicious_extensions
Extensions commonly associated with malware or scripts.

Recommended:
.sh  -> shell scripts
.elf -> Linux binaries
.ps1 -> PowerShell malware
.bin -> packed payloads

---

## suspicious_processes
Potentially dangerous processes/tools.

Examples:
nc
netcat
ncat
hydra

---

## ignored_paths
Paths ignored to reduce system noise.

Examples:
/proc
/sys
/dev
`

		os.WriteFile(configFile, []byte(defaultConfig), 0644)

		helpPath := filepath.Join(baseDir, "HELP.md")
		os.WriteFile(helpPath, []byte(helpDoc), 0644)

		logMsg("INFO", "Created default config and HELP.md")

		data = []byte(defaultConfig)
	}
	json.Unmarshal(data, &globalConfig)

	// 🔥 THIS LINE IS CRITICAL
}

/* ================= LOGGING ================= */

func logMsg(level, msg string) {

	Emit(Event{
		Type:      "log",
		Severity:  level,
		Message:   msg,
		Timestamp: time.Now(),
	})
}
func runDaemon() {
	setup()
	InitLogger()

	go watchDirs()

	logMsg("INFO", "RuntimeGuard daemon started")
	select {} // block forever
}

/* ================= BASELINE ================= */

func checkBaseline() {

	data, err := os.ReadFile(baselineFile)
	if err != nil {
		logMsg("ERROR", "No baseline found")
		return
	}

	var base Baseline
	json.Unmarshal(data, &base)

	logMsg("INFO", "---- FILE CHECK PIPELINE ----")

	for _, f := range base.Files {

		if _, err := os.Stat(f.Path); err != nil {

			missingMsg := "🚨 Missing file: " + f.Path

			logMsg("WARN", missingMsg)
			sendAlert(missingMsg)

			continue
		}

		h, _ := hashFile(f.Path)

		if h != f.Hash {

			changedMsg := fmt.Sprintf(
				"⚠ File changed since baseline → %s",
				f.Path,
			)

			logMsg("WARN", changedMsg)

		} else {

			logMsg(
				"INFO",
				"Verified: "+f.Path,
			)
		}
	}
}
func sendAlert(message string) {

	if webhookURL == "" {
		return
	}
	payload := map[string]string{
		"content": message,
	}

	data, err := json.Marshal(payload)
	if err != nil {
		logMsg("ERROR", "Failed to marshal webhook payload")
		return
	}

	req, err := http.NewRequest("POST", webhookURL, bytes.NewBuffer(data))
	if err != nil {
		logMsg("ERROR", "Failed to create request")
		return
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		logMsg("ERROR", "Webhook request failed: "+err.Error())
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 204 {

		Emit(Event{
			Type:      "discord",
			Path:      "-",
			Severity:  "HIGH",
			Message:   fmt.Sprintf("Discord failed: %d %s", resp.StatusCode, string(body)),
			Timestamp: time.Now(),
		})

		return
	}

	Emit(Event{
		Type:      "discord",
		Path:      "-",
		Severity:  "INFO",
		Message:   "Discord alert sent",
		Timestamp: time.Now(),
	})
}

/* ================= HASH ================= */

func hashFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}

	sum := sha256.Sum256(data)
	return fmt.Sprintf("%x", sum), nil
}

/* ================= EVENT FILTER ================= */

func shouldProcess(path string) bool {
	now := time.Now()

	if t, ok := lastEvent[path]; ok {
		if now.Sub(t) < 2*time.Second {
			return false
		}
	}

	lastEvent[path] = now
	return true
}

/* ================= RISK ================= */

func applyRisk(level string) {

	switch level {
	case "CRITICAL":
		riskScore += 40
	case "ALERT":
		riskScore += 25
	case "WARN":
		riskScore += 10
	case "INFO":
		riskScore += 1
	}

	if riskScore > 100 {
		riskScore = 100
	}
}

/* ================= PROCESS LIST ================= */

func listProcesses() {
	procs, _ := process.Processes()

	for _, p := range procs {
		name, _ := p.Name()
		fmt.Printf("%d %s\n", p.Pid, name)
	}
}

/* ================= PORTS ================= */

func listPorts() {
	conns, err := net.Connections("inet")
	if err != nil {
		logMsg("ERROR", err.Error())
		return
	}

	logMsg("INFO", "LISTENING PORTS")

	for _, c := range conns {
		if c.Status == "LISTEN" {
			logMsg("INFO", fmt.Sprintf("Port: %d", c.Laddr.Port))
		}
	}
}

/* ================= WATCH ================= */

func watchDirs() {

	cfg := loadConfig()

	watcher, err := fsnotify.NewWatcher()
	if err != nil {

		Emit(Event{
			Type:      "system",
			Path:      "-",
			Severity:  "HIGH",
			Message:   err.Error(),
			Timestamp: time.Now(),
		})

		return
	}

	defer watcher.Close()

	// ============================================
	// REGISTER WATCH DIRECTORIES
	// ============================================
	for _, dir := range cfg.WatchDirs {

		err := watcher.Add(dir)
		if err != nil {

			Emit(Event{
				Type:      "system",
				Path:      dir,
				Severity:  "HIGH",
				Message:   "Failed to watch directory",
				Timestamp: time.Now(),
			})

			continue
		}

		Emit(Event{
			Type:      "system",
			Path:      dir,
			Severity:  "INFO",
			Message:   "Watching directory",
			Timestamp: time.Now(),
		})
	}

	Emit(Event{
		Type:      "system",
		Path:      "-",
		Severity:  "INFO",
		Message:   "Filesystem watch active",
		Timestamp: time.Now(),
	})

	// ============================================
	// EVENT LOOP
	// ============================================
	for {

		select {

		// ========================================
		// FILESYSTEM EVENTS
		// ========================================
		case e, ok := <-watcher.Events:

			if !ok {
				return
			}

			path := e.Name

			// dedupe
			if t, ok := lastEvent[path]; ok {
				if time.Since(t) < 300*time.Millisecond {
					continue
				}
			}

			lastEvent[path] = time.Now()

			eventType := "unknown"

			switch {

			case e.Op&fsnotify.Create != 0:
				eventType = "create"

			case e.Op&fsnotify.Write != 0:
				eventType = "write"

			case e.Op&fsnotify.Remove != 0:
				eventType = "delete"

			case e.Op&fsnotify.Rename != 0:
				eventType = "rename"

			case e.Op&fsnotify.Chmod != 0:
				eventType = "chmod"
			}

			// ====================================
			// PIPELINE EVENT
			// ====================================
			ProcessEvent(Event{
				Type:      "filesystem",
				Path:      e.Name,
				Severity:  "INFO",
				Message:   fmt.Sprintf("Filesystem event: %s", eventType),
				Timestamp: time.Now(),
			})

			// ====================================
			// DETECTOR EVENT
			// ====================================
			detectorEvent := detector.Event{
				Type: eventType,
				Name: filepath.Base(e.Name),
				Path: e.Name,
				User: "system",
			}

			alert := detector.Analyze(detectorEvent)

			// ====================================
			// ALERT EVENT
			// ====================================
			if alert != nil {

				ProcessEvent(Event{
					Type:      "alert",
					Path:      e.Name,
					Severity:  alert.Severity,
					Message:   alert.Reason,
					Timestamp: time.Now(),
				})
			}

		// ========================================
		// WATCHER ERRORS
		// ========================================
		case err, ok := <-watcher.Errors:

			if !ok {
				return
			}

			ProcessEvent(Event{
				Type:      "system",
				Path:      "-",
				Severity:  "HIGH",
				Message:   err.Error(),
				Timestamp: time.Now(),
			})
		}
	}
}

/* ================= CONFIG ================= */

func loadConfig() Config {
	data, err := os.ReadFile(configFile)
	if err != nil {
		logMsg("ERROR", "Missing config")
		os.Exit(1)
	}

	var cfg Config
	json.Unmarshal(data, &cfg)
	return cfg
}

/* ================= STRUCTS ================= */
type Config struct {
	Files      []string `json:"files"`
	Processes  []string `json:"processes"`
	WatchDirs  []string `json:"watch_dirs"`
	Interval   int      `json:"interval"`
	WebhookURL string   `json:"webhook_url"`
}

// malware change
