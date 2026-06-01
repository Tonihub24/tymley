package detector

type Event struct {
	Type     string
	Name     string
	Path     string
	User     string
	PID      int
	Metadata map[string]string
}

type Alert struct {
	Severity string
	Reason   string
	Target   string
}

func Analyze(e Event) *Alert {

	// ============================================
	// /tmp execution or staging area activity
	// ============================================
	if contains(e.Path, "/tmp") {
		return &Alert{
			Severity: "HIGH",
			Reason:   "Activity in untrusted directory (/tmp)",
			Target:   e.Path,
		}
	}

	// ============================================
	// Shell script logic (NOW event-aware)
	// ============================================
	if contains(e.Name, ".sh") {

		switch e.Type {

		case "create":
			return &Alert{
				Severity: "INFO",
				Reason:   "Shell script created",
				Target:   e.Path,
			}

		case "write":
			return &Alert{
				Severity: "MEDIUM",
				Reason:   "Shell script modified",
				Target:   e.Path,
			}

		case "delete":
			return &Alert{
				Severity: "HIGH",
				Reason:   "Shell script deleted",
				Target:   e.Path,
			}

		case "chmod":
			return &Alert{
				Severity: "LOW",
				Reason:   "Shell script permission change",
				Target:   e.Path,
			}

		default:
			return &Alert{
				Severity: "INFO",
				Reason:   "Shell script activity detected",
				Target:   e.Path,
			}
		}
	}

	// ============================================
	// Suspicious filenames
	// ============================================
	if contains(e.Name, "backdoor") || contains(e.Name, "kworker") {
		return &Alert{
			Severity: "CRITICAL",
			Reason:   "Suspicious filename detected",
			Target:   e.Path,
		}
	}

	// ============================================
	// File integrity drift (baseline logic)
	// ============================================
	if e.Metadata != nil && e.Metadata["hash"] == "" {
		return &Alert{
			Severity: "WARN",
			Reason:   "Missing file hash (baseline drift)",
			Target:   e.Path,
		}
	}

	// ============================================
	// Generic filesystem events
	// ============================================
	switch e.Type {

	case "create":
		return &Alert{
			Severity: "INFO",
			Reason:   "File created",
			Target:   e.Path,
		}

	case "write":
		return &Alert{
			Severity: "INFO",
			Reason:   "File modified",
			Target:   e.Path,
		}

	case "delete":
		return &Alert{
			Severity: "MEDIUM",
			Reason:   "File deleted",
			Target:   e.Path,
		}

	case "chmod":
		return &Alert{
			Severity: "LOW",
			Reason:   "Permission change detected",
			Target:   e.Path,
		}
	}

	return nil
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
