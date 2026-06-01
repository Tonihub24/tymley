package events

type Event struct {
    Type      string
    Path      string
    Message   string

    MitreID   string
    MitreName string

    Score     int
    Tags      []string
}
