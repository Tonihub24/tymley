package main

import (
	"encoding/json"
	"os"
	"path/filepath"
)

type FileCheck struct {
	Path string
	Hash string
}

type Baseline struct {
	Files     []FileCheck
	Processes []string
}

func initBaseline() {

	cfg := loadConfig()

	base := Baseline{
		Files:     []FileCheck{},
		Processes: []string{},
	}

	// =========================================
	// FILE SNAPSHOT
	// =========================================
	for _, dir := range cfg.WatchDirs {

		filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {

			if err != nil || info.IsDir() {
				return nil
			}

			hash, err := hashFile(path)
			if err != nil {
				return nil
			}

			base.Files = append(base.Files, FileCheck{
				Path: path,
				Hash: hash,
			})

			return nil
		})
	}

	// =========================================
	// SAVE BASELINE
	// =========================================
	data, err := json.MarshalIndent(base, "", "  ")
	if err != nil {

		Emit(Event{
			Type:      "error",
			Path:      baselineFile,
			Severity:  "HIGH",
			Message:   "Failed to encode baseline",
			MITREID:   "N/A",
			MITREName: "Baseline Error",
		})

		return
	}

	err = os.WriteFile(baselineFile, data, 0644)
	if err != nil {

		Emit(Event{
			Type:      "error",
			Path:      baselineFile,
			Severity:  "HIGH",
			Message:   "Failed to write baseline file",
			MITREID:   "N/A",
			MITREName: "Baseline Error",
		})

		return
	}

	// =========================================
	// SUCCESS
	// =========================================
	Emit(Event{
		Type:      "baseline",
		Path:      baselineFile,
		Severity:  "INFO",
		Message:   "Baseline initialized successfully",
		MITREID:   "N/A",
		MITREName: "System Baseline",
	})
}
