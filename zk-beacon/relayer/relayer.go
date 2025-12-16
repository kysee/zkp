package relayer

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
)

// Config holds the relayer configuration
type Config struct {
	// DataSource can be "file" or "rpc"
	DataSource string
	// FilePath is used when DataSource is "file"
	FilePath string
	// RPCEndpoint is used when DataSource is "rpc"
	RPCEndpoint string
}

// Relayer is the main relayer struct
type Relayer struct {
	fetcher LCUpdateFetcher
	config  Config
}

// NewRelayer creates a new Relayer with the given configuration
func NewRelayer(config Config) (*Relayer, error) {
	var fetcher LCUpdateFetcher

	switch config.DataSource {
	case "file":
		if config.FilePath == "" {
			return nil, fmt.Errorf("file path is required when data source is 'file'")
		}
		fetcher = NewFileFetcher(config.FilePath)
	case "rpc":
		if config.RPCEndpoint == "" {
			return nil, fmt.Errorf("RPC endpoint is required when data source is 'rpc'")
		}
		fetcher = NewRPCFetcher(config.RPCEndpoint)
	default:
		return nil, fmt.Errorf("invalid data source: %s (must be 'file' or 'rpc')", config.DataSource)
	}

	return &Relayer{
		fetcher: fetcher,
		config:  config,
	}, nil
}

// Run executes the relayer to fetch and display attested header information
func (r *Relayer) Run() error {
	// Fetch the light client update
	update, err := r.fetcher.FetchUpdate()
	if err != nil {
		return fmt.Errorf("failed to fetch update: %w", err)
	}

	// Extract attested header
	attestedHeader := update.Data.AttestedHeader

	// Print attested header information
	fmt.Println("=== Attested Header ===")
	fmt.Printf("Beacon Block Header:\n")
	fmt.Printf("  Slot: %s\n", attestedHeader.Beacon.Slot)
	fmt.Printf("  Proposer Index: %s\n", attestedHeader.Beacon.ProposerIndex)
	fmt.Printf("  Parent Root: %s\n", attestedHeader.Beacon.ParentRoot)
	fmt.Printf("  State Root: %s\n", attestedHeader.Beacon.StateRoot)
	fmt.Printf("  Body Root: %s\n", attestedHeader.Beacon.BodyRoot)

	fmt.Printf("\nExecution Payload Header:\n")
	fmt.Printf("  Block Number: %s\n", attestedHeader.Execution.BlockNumber)
	fmt.Printf("  Block Hash: %s\n", attestedHeader.Execution.BlockHash)
	fmt.Printf("  Timestamp: %s\n", attestedHeader.Execution.Timestamp)
	fmt.Printf("  Parent Hash: %s\n", attestedHeader.Execution.ParentHash)
	fmt.Printf("  State Root: %s\n", attestedHeader.Execution.StateRoot)
	fmt.Printf("  Gas Used: %s\n", attestedHeader.Execution.GasUsed)
	fmt.Printf("  Gas Limit: %s\n", attestedHeader.Execution.GasLimit)

	// Optionally output full JSON
	fmt.Printf("\nFull Attested Header JSON:\n")
	jsonData, err := json.MarshalIndent(attestedHeader, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal attested header: %w", err)
	}
	fmt.Println(string(jsonData))

	return nil
}

// Main entry point for the relayer
func Main() {
	// Parse configuration from environment variables or command line args
	config := Config{
		DataSource:  getEnv("DATA_SOURCE", "file"),
		FilePath:    getEnv("FILE_PATH", "data/sc-update-1105.json"),
		RPCEndpoint: getEnv("RPC_ENDPOINT", ""),
	}

	// Override with command line arguments if provided
	if len(os.Args) > 1 {
		config.DataSource = os.Args[1]
	}
	if len(os.Args) > 2 {
		if config.DataSource == "file" {
			config.FilePath = os.Args[2]
		} else {
			config.RPCEndpoint = os.Args[2]
		}
	}

	// Create and run relayer
	relayer, err := NewRelayer(config)
	if err != nil {
		log.Fatalf("Failed to create relayer: %v", err)
	}

	if err := relayer.Run(); err != nil {
		log.Fatalf("Failed to run relayer: %v", err)
	}
}

// getEnv retrieves an environment variable or returns a default value
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
