package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/Finsys/hawser/internal/config"
	"github.com/Finsys/hawser/internal/edge"
	"github.com/Finsys/hawser/internal/log"
	"github.com/Finsys/hawser/internal/server"
)

var (
	version = "dev"
	commit  = "unknown"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}

	// Initialize logger before anything else
	log.Init(cfg.LogLevel)

	// Set version info from ldflags
	cfg.Version = version
	cfg.Commit = commit

	// Print startup banner
	printBanner(cfg)

	// Setup graceful shutdown
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	errChan := make(chan error, 1)

	if cfg.EdgeMode() {
		// Edge mode: connect outbound to Dockhand server
		log.Infof("Starting in Edge mode, connecting to %s", cfg.DockhandServerURL)
		go func() {
			errChan <- edge.Run(cfg, stop)
		}()
	} else {
		// Standard mode: listen for incoming connections
		log.Infof("Starting in Standard mode on port %d", cfg.Port)
		go func() {
			errChan <- server.Run(cfg, stop)
		}()
	}

	// Wait for shutdown signal or error
	select {
	case <-stop:
		log.Info("Shutdown signal received, stopping...")
	case err := <-errChan:
		if err != nil {
			log.Errorf("Error: %v", err)
			os.Exit(1)
		}
	}

	log.Info("Hawser stopped")
}

func printBanner(cfg *config.Config) {
	fmt.Println("╭─────────────────────────────────────╮")
	fmt.Println("│           HAWSER AGENT              │")
	fmt.Println("│     Remote Docker Agent for         │")
	fmt.Println("│           Dockhand                  │")
	fmt.Println("╰─────────────────────────────────────╯")
	fmt.Printf("Version: %s (%s)\n", version, commit)
	fmt.Printf("Agent ID: %s\n", cfg.AgentID)
	fmt.Printf("Agent Name: %s\n", cfg.AgentName)
	fmt.Printf("Docker Socket: %s\n", cfg.DockerSocket)
	fmt.Printf("Log Level: %s\n", log.GetLevel())
	fmt.Println()
}
