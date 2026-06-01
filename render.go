package main

import (
	"fmt"

	"github.com/Tonihub24/RunxGuard/detector"
)

func RenderAnalysisFromAlert(alert *detector.Alert) string {
	if alert == nil {
		return ""
	}

	return fmt.Sprintf(`
┌──────────── ALERT ────────────┐
│ Target: %s
│ Severity: %s
│ Reason: %s
└───────────────────────────────┘
`,
		alert.Target,
		alert.Severity,
		alert.Reason,
	)
}
