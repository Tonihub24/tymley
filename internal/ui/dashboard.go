package ui

import (
	"fmt"
	"github.com/Tonihub24/RunxGuard/internal/state"
)

func RenderDashboard(s state.AppState) {
	fmt.Println("====================================")
	fmt.Println("   🧠 RunXShop Tech Stack CLI")
	fmt.Println("====================================")

	fmt.Printf("Welcome, %s\n", s.User)
	fmt.Printf("Overall Progress: %d%%\n\n", s.Progress)

	fmt.Println("Your Learning Path")
	fmt.Println("-------------------")

	fmt.Printf("[ ACTIVE ] %s\n", s.ActiveModule)

	fmt.Println("\n🛡 LAB: Process Visibility")
	fmt.Println("→ run: runtimeguard lab process")

	fmt.Println("\nLocked Modules:")
	fmt.Println("  🔒 API Routing & HTTP")
	fmt.Println("  🔒 Database Systems")
	fmt.Println("  🔒 Authentication")
}
