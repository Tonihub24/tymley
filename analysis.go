package main

import (
	"strings"
)

type AnalysisPanel struct {
	EventType string
	Path      string
	Time      string

	Severity string

	WhatHappened string
	Why          string
	Concept      string
	Takeaway     string
	Detection    string

	MITREID   string
	MITREName string

	ReferenceURL string
}

func ConvertToAnalysis(event Event) AnalysisPanel {

	analysis := AnalysisPanel{
		EventType: event.Type,
		Path:      event.Path,
		Time:      event.Timestamp.Format("15:04:05"),

		Severity: event.Severity,

		MITREID:   event.MITREID,
		MITREName: event.MITREName,

		WhatHappened: event.Description,

		Why:       "Attackers may use this behavior for execution, persistence, or defense evasion.",
		Concept:   "MITRE ATT&CK Detection Mapping",
		Takeaway:  "Review unexpected activity in monitored directories.",
		Detection: "RuntimeGuard event pipeline",

		ReferenceURL: event.ReferenceURL,
	}

	msg := strings.ToLower(event.Message)
	path := strings.ToLower(event.Path)

	// ============================================
	// OPTIONAL EXTRA CONTEXT ENRICHMENT
	// ============================================

	if strings.Contains(path, ".sh") || strings.Contains(msg, "shell") {

		analysis.Takeaway = "Shell scripts should be reviewed carefully for suspicious commands."
		analysis.Detection = "Shell activity monitoring"
	}

	if strings.Contains(msg, "chmod") {

		analysis.Takeaway = "Unexpected permission changes may indicate malware staging."
		analysis.Detection = "Permission modification monitoring"
	}

	if strings.Contains(msg, "delete") {

		analysis.Takeaway = "Deleted files may indicate defense evasion attempts."
		analysis.Detection = "Artifact removal detection"
	}

	return analysis
}
