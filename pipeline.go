package main

import (
	"time"
)

// ------------------------------------
// PIPELINE START
// ------------------------------------

func StartPipeline() {

	go func() {

		for e := range ingestBus {
			ProcessEvent(e)
		}
	}()
}

// ------------------------------------
// CORE PROCESSOR (ONLY ONE VERSION)
// ------------------------------------

func ProcessEvent(e Event) {

	// 1. DEDUPE
	if !AllowEvent(e) {
		return
	}

	// 2. MITRE ENRICHMENT
	mitre := mapMITRE(e)

	e.MITREID = mitre.ID
	e.MITREName = mitre.Technique

	// optional new fields
	e.Description = mitre.Description
	e.ReferenceURL = mitre.URL

	// only overwrite if empty
	if e.Severity == "" {
		e.Severity = mitre.Severity
	}

	// 3. TIMESTAMP NORMALIZATION
	e.Timestamp = time.Now()

	// 4. INCIDENT TRACKING
	AddToIncident(e)

	// 5. PUSH TO UI BUS
	select {
	case eventBus <- e:
	default:
	}
}
