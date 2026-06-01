package main

import (
	"github.com/shirou/gopsutil/v4/process"
)

func getProcesses() []string {

	var names []string

	procs, err := process.Processes()
	if err != nil {
		return names
	}

	for _, p := range procs {

		name, err := p.Name()
		if err == nil {
			names = append(names, name)
		}
	}

	return names
}
