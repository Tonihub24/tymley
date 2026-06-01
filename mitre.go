package main

type MITREInfo struct {
	ID          string
	Technique   string
	Severity    string
	Description string
	URL         string
}

func mapMITRE(e Event) MITREInfo {

	switch e.Type {

	case "filesystem":

		switch e.Message {

		case "create":
			return MITREInfo{
				ID:          "T1105",
				Technique:   "Ingress Tool Transfer",
				Severity:    "HIGH",
				Description: "A new file was created in a monitored directory. Attackers often transfer payloads, scripts, or malware into a target system before execution.",
				URL:         "https://attack.mitre.org/techniques/T1105/",
			}

		case "write":
			return MITREInfo{
				ID:          "T1059",
				Technique:   "Command and Scripting Interpreter",
				Severity:    "MEDIUM",
				Description: "A monitored file was modified. Script or command execution activity may indicate automation, persistence, or malware behavior.",
				URL:         "https://attack.mitre.org/techniques/T1059/",
			}

		case "delete":
			return MITREInfo{
				ID:          "T1070",
				Technique:   "Indicator Removal on Host",
				Severity:    "HIGH",
				Description: "A file was deleted from a monitored location. Attackers may remove files, logs, or artifacts to hide malicious activity.",
				URL:         "https://attack.mitre.org/techniques/T1070/",
			}

		case "chmod":
			return MITREInfo{
				ID:          "T1222",
				Technique:   "File and Directory Permissions Modification",
				Severity:    "MEDIUM",
				Description: "File permissions were modified. Attackers may change permissions to execute payloads or maintain persistence.",
				URL:         "https://attack.mitre.org/techniques/T1222/",
			}
		}

	case "alert":
		return MITREInfo{
			ID:          "T1059",
			Technique:   "Command and Scripting Interpreter",
			Severity:    "HIGH",
			Description: "RuntimeGuard detected suspicious activity related to scripting or command execution.",
			URL:         "https://attack.mitre.org/techniques/T1059/",
		}

	case "process":
		return MITREInfo{
			ID:          "T1059",
			Technique:   "Command and Scripting Interpreter",
			Severity:    "MEDIUM",
			Description: "A suspicious process or command execution event was detected.",
			URL:         "https://attack.mitre.org/techniques/T1059/",
		}
	}

	return MITREInfo{
		ID:          "T0000",
		Technique:   "Unknown Activity",
		Severity:    "LOW",
		Description: "The activity could not be mapped to a known MITRE ATT&CK technique.",
		URL:         "https://attack.mitre.org/",
	}
}
