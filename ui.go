package main

import (
	"fmt"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

var (
	app   *tview.Application
	uiLog *tview.TextView
)

// ============================================
// MAIN UI
// ============================================
func RunUI() {

	app = tview.NewApplication()
	app.EnableMouse(false)

	// ============================================
	// HEADER
	// ============================================
	header := tview.NewTextView().
		SetDynamicColors(true).
		SetTextAlign(tview.AlignCenter)

	header.SetText(
		"[green::b]RuntimeGuard EDR[-:-:-] " +
			"[white]Live Threat Monitoring Console",
	)

	header.SetBorder(true)
	header.SetBorderColor(tcell.ColorGreen)

	// ============================================
	// MENU
	// ============================================
	menu := tview.NewList()
	menu.ShowSecondaryText(true)

	// ============================================
	// WATCH MODE
	// ============================================
	menu.AddItem("Watch Mode", "Start filesystem monitoring", '1', func() {

		if watchRunning {

			Emit(Event{
				Type:      "SYSTEM",
				Path:      "-",
				Severity:  "INFO",
				Message:   "Watch mode already running",
				Timestamp: time.Now(),
			})

			return
		}

		watchRunning = true

		Emit(Event{
			Type:      "SYSTEM",
			Path:      "-",
			Severity:  "INFO",
			Message:   "Watch mode active",
			Timestamp: time.Now(),
		})

		go watchDirs()
	})

	// ============================================
	// BASELINE CHECK
	// ============================================
	menu.AddItem("Check Baseline", "Run integrity verification", '2', func() {

		if baselineRunning {

			Emit(Event{
				Type:      "SYSTEM",
				Path:      "-",
				Severity:  "INFO",
				Message:   "Baseline check already running",
				Timestamp: time.Now(),
			})

			return
		}

		baselineRunning = true

		Emit(Event{
			Type:      "SYSTEM",
			Path:      "-",
			Severity:  "INFO",
			Message:   "Running baseline verification",
			Timestamp: time.Now(),
		})

		go func() {

			checkBaseline()

			baselineRunning = false

			Emit(Event{
				Type:      "SYSTEM",
				Path:      "-",
				Severity:  "INFO",
				Message:   "Baseline verification complete",
				Timestamp: time.Now(),
			})

		}()
	})

	// ============================================
	// TRAINING MODE
	// ============================================
	menu.AddItem("Training Mode", "Simulated attack scenarios", '3', func() {

		if trainingRunning {

			Emit(Event{
				Type:      "SYSTEM",
				Path:      "-",
				Severity:  "INFO",
				Message:   "Training mode already active",
				Timestamp: time.Now(),
			})

			return
		}

		trainingRunning = true

		Emit(Event{
			Type:      "SYSTEM",
			Path:      "-",
			Severity:  "INFO",
			Message:   "Training mode initialized",
			Timestamp: time.Now(),
		})
	})

	// ============================================
	// EXIT
	// ============================================
	menu.AddItem("Exit", "Quit RunxGuard", 'q', func() {
		app.Stop()
	})

	// ============================================
	// INPUT HANDLING
	// ============================================

	// ============================================
	// MENU STYLE
	// ============================================
	menu.SetBorder(true)
	menu.SetBorderColor(tcell.ColorBlue)
	menu.SetTitle(" Control Panel ")
	menu.SetTitleAlign(tview.AlignCenter)

	// ============================================
	// LIVE EVENT LOG
	// ============================================
	uiLog = tview.NewTextView()

	uiLog.SetDynamicColors(true)
	uiLog.SetScrollable(true)
	uiLog.SetWrap(false)
	uiLog.SetWordWrap(false)

	uiLog.SetBorder(true)
	uiLog.SetBorderColor(tcell.ColorRed)
	uiLog.SetTitle(" Live Events ")
	uiLog.SetTitleAlign(tview.AlignCenter)

	// ============================================
	// ANALYSIS PANEL
	// ============================================
	analysisView := tview.NewTextView()

	analysisView.SetDynamicColors(true)
	analysisView.SetWrap(true)
	analysisView.SetWordWrap(true)

	analysisView.SetBorder(true)
	analysisView.SetBorderColor(tcell.ColorRed)
	analysisView.SetTitle(" Learning / Analysis ")
	analysisView.SetTitleAlign(tview.AlignCenter)
	// INPUT HANDLING
	// ============================================
	menu.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {

		switch event.Rune() {

		case '1':
			menu.SetCurrentItem(0)
			menu.GetItemSelectedFunc(0)()
			return nil

		case '2':
			menu.SetCurrentItem(1)
			menu.GetItemSelectedFunc(1)()
			return nil

		case '3':
			menu.SetCurrentItem(2)
			menu.GetItemSelectedFunc(2)()
			return nil

		case 'l':
			app.SetFocus(uiLog)
			return nil

		case 'a':
			app.SetFocus(analysisView)
			return nil

		case 'm':
			app.SetFocus(menu)
			return nil

		case 'q':
			app.Stop()
			return nil
		}

		return event
	})

	// ============================================
	// STATUS BAR
	// ============================================
	status := tview.NewTextView().
		SetDynamicColors(true)

	status.SetText(
		"[green]STATUS[-]: ACTIVE    " +
			"[yellow]MODE[-]: MONITORING    " +
			"[red]ALERTS[-]: LIVE",
	)

	status.SetBorder(true)
	status.SetBorderColor(tcell.ColorDarkCyan)

	// ============================================
	// EVENT LISTENER
	// ============================================
	go func() {

		for e := range EventStream() {

			ev := e

			app.QueueUpdateDraw(func() {

				// ====================================
				// SEVERITY COLORS
				// ====================================
				color := "white"

				switch ev.Severity {

				case "INFO":
					color = "deepskyblue"

				case "LOW":
					color = "green"

				case "MEDIUM":
					color = "yellow"

				case "HIGH":
					color = "red"

				case "CRITICAL":
					color = "maroon"
				}

				// ====================================
				// LOG OUTPUT
				// ====================================
				msg := fmt.Sprintf(
					"[%s][%s] %s | %s",
					color,
					ev.Severity,
					ev.Path,
					ev.Message,
				)

				fmt.Fprintln(uiLog, msg)
				uiLog.ScrollToEnd()

				// ====================================
				// ANALYSIS UPDATE
				// ====================================
				analysis := ConvertToAnalysis(ev)

				if analysis.MITREName == "" {
					analysis.MITREName = "Unmapped Activity"
				}

				if analysis.MITREID == "" {
					analysis.MITREID = "N/A"
				}

				analysisView.SetText(RenderAnalysis(analysis))
			})
		}
	}()

	// ============================================
	// MAIN CONTENT
	// ============================================
	content := tview.NewFlex().
		SetDirection(tview.FlexColumn).
		AddItem(menu, 28, 1, true).
		AddItem(uiLog, 0, 2, false).
		AddItem(analysisView, 45, 1, false)

	// ============================================
	// FULL LAYOUT
	// ============================================
	layout := tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(header, 3, 0, false).
		AddItem(content, 0, 1, true).
		AddItem(status, 3, 0, false)

	// ============================================
	// START UI
	// ============================================
	if err := app.SetRoot(layout, true).Run(); err != nil {
		panic(err)
	}
}

// ============================================
// ANALYSIS PANEL RENDERER
// ============================================
func RenderAnalysis(ev AnalysisPanel) string {

	return fmt.Sprintf(

		"[::b][yellow]%40s[-:-:-]\n"+
			"[white]%40s\n\n"+

			"[::b][red]%40s[-:-:-]\n"+
			"[white]%40s\n\n"+

			"[::b][orange]%40s[-:-:-]\n"+
			"[white]%40s\n\n"+

			"[::b][green]%40s[-:-:-]\n"+
			"[white]%40s\n\n"+

			"[::b][cyan]%40s[-:-:-]\n"+
			"[white]%40s\n\n"+

			"[::b][purple]%40s[-:-:-]\n"+
			"[white]%40s",

		"MITRE ATT&CK",
		"["+ev.MITREID+"] "+ev.MITREName,

		"WHAT HAPPENED",
		ev.WhatHappened,

		"WHY IT MATTERS",
		ev.Why,

		"SEVERITY",
		ev.Severity,

		"REFERENCE",
		ev.ReferenceURL,

		"DETECTION",
		ev.Detection,
	)
}
