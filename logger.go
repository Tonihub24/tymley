package main

import (
	"encoding/json"
	"os"
	"time"
)

type LogEvent struct {
	Time     string `json:"time"`
	Type     string `json:"type"`
	Severity string `json:"severity"`
	Path     string `json:"path"`
	Message  string `json:"message"`
}

var logFile *os.File

func InitLogger() {
	var err error

	logFile, err = os.OpenFile(
		"events.log",
		os.O_APPEND|os.O_CREATE|os.O_WRONLY,
		0644,
	)

	if err != nil {
		panic(err)
	}
}

func PersistEvent(e Event) {
	if logFile == nil {
		return
	}

	entry := LogEvent{
		Time:     time.Now().Format(time.RFC3339),
		Type:     e.Type,
		Severity: e.Severity,
		Path:     e.Path,
		Message:  e.Message,
	}

	data, _ := json.Marshal(entry)

	logFile.Write(append(data, '\n'))
}
