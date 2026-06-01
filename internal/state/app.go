package state

type AppState struct {
	User         string
	Progress     int
	ActiveModule string
}

func LoadDefault() AppState {
	return AppState{
		User:         "sally",
		Progress:     31,
		ActiveModule: "Server Foundations",
	}
}
