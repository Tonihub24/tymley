package main

import (
	"sync"
)

var (
	ingestBus chan Event
	eventBus  chan Event
	once      sync.Once
)

// InitBus initializes channels once
func InitBus() {

	once.Do(func() {

		ingestBus = make(chan Event, 500)

		eventBus = make(chan Event, 500)
	})
}

// Emit sends RAW events into pipeline
func Emit(e Event) {

	PersistEvent(e)

	if ingestBus == nil {
		return
	}

	select {
	case ingestBus <- e:
	default:
	}
}

// EventStream exposes processed events to UI
func EventStream() <-chan Event {
	return eventBus
}
