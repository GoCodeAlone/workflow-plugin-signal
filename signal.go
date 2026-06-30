package component

import (
	"context"
)

// Name returns the name of the signal plugin.
func Name() string { return "signal" }

// Init initializes the Signal plugin.
func Init(services map[string]interface{}) error {
	return nil
}

// Start starts the Signal plugin.
func Start(ctx context.Context) error {
	return nil
}

// Stop stops the Signal plugin.
func Stop(ctx context.Context) error {
	return nil
}

// Execute runs the Signal plugin logic.
func Execute(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	result := map[string]interface{}{
		"status": "ok",
	}
	return result, nil
}
