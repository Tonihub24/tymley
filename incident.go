package main

import (
	"sort"
	"strings"
	"time"
)

type Incident struct {
	ID        string
	Path      string
	Events    []Event
	RiskScore int
	LastSeen  time.Time
}

var incidents = make(map[string]*Incident)

// group by file path (simple v1)
func getIncidentKey(e Event) string {
	return e.Path
}

func AddToIncident(e Event) {

	key := getIncidentKey(e)

	inc, ok := incidents[key]
	if !ok {
		inc = &Incident{
			ID:     key,
			Path:   key,
			Events: []Event{},
		}
		incidents[key] = inc
	}

	inc.Events = append(inc.Events, e)
	inc.LastSeen = e.Timestamp

	updateRisk(inc)
}

func updateRisk(i *Incident) {

	score := 0

	for _, e := range i.Events {

		msg := strings.ToLower(e.Message)

		switch {
		case strings.Contains(msg, "created"):
			score += 10
		case strings.Contains(msg, "chmod"):
			score += 25
		case strings.Contains(msg, "shell"):
			score += 40
		case strings.Contains(msg, "deleted"):
			score += 30
		}
	}

	i.RiskScore = score
}

func GetTimeline(path string) []Event {

	inc, ok := incidents[path]
	if !ok {
		return nil
	}

	sort.Slice(inc.Events, func(a, b int) bool {
		return inc.Events[a].Timestamp.Before(inc.Events[b].Timestamp)
	})

	return inc.Events
}
