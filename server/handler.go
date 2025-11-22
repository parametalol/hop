package server

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/parametalol/hop/client"
	"github.com/parametalol/hop/parser"
)

func ProxyHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("Received %s request to %s", r.Method, r.URL.Path)

	// Parse the path
	parsedReq, err := parser.ParsePath(r.URL.Path)
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid path: "+err.Error())
		return
	}

	var proxyResp *client.ProxyResponse
	statusCode := http.StatusOK

	if parsedReq != nil {
		// Apply sleep if specified
		if sleepDuration := parsedReq.Options.GetSleepDuration(); sleepDuration > 0 {
			log.Printf("Sleeping for %v before processing request", sleepDuration)
			time.Sleep(sleepDuration)
		}

		// Check for panic option first
		if msg, shouldPanic := parsedReq.Options.GetPanicMessage(); shouldPanic {
			log.Printf("Panic triggered by request option: %s", msg)
			panic(msg)
		}

		// Check for exit option
		if exitCode, shouldExit := parsedReq.Options.GetExitCode(); shouldExit {
			log.Printf("Exit triggered by request option with code: %d", exitCode)
			// Send response before exiting
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"message":   "Server shutting down",
				"exit_code": exitCode,
			})
			// Give a brief moment for response to be sent
			time.Sleep(50 * time.Millisecond)
			os.Exit(exitCode)
		}

		log.Printf("Parsed target URL: %s, options: %v", parsedReq.TargetURL, parsedReq.Options)

		if parsedReq.TargetURL != "" {
			proxyResp = client.ExecuteRequest(parsedReq)
		}

		statusCode = parsedReq.Options.GetHTTPStatus()
		parsedReq.Options.ApplyServerHeaders(w.Header())
	}
	if proxyResp != nil && proxyResp.Error != "" {
		statusCode = http.StatusBadGateway
	}
	// Send JSON response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	if proxyResp != nil {
		if err := json.NewEncoder(w).Encode(proxyResp); err != nil {
			log.Printf("Error encoding response: %v", err)
		}
	}
}

func respondError(w http.ResponseWriter, statusCode int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	resp := map[string]string{
		"error": message,
	}

	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Printf("Error encoding error response: %v", err)
	}
}
