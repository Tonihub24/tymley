package main

import "time"

// Core normalized event used everywhere in the pipeline
type Event struct {
	Type    string
	Message string
	Path    string

	Severity string

	MITREID   string
	MITREName string

	Description  string
	ReferenceURL string

	Timestamp time.Time
}
