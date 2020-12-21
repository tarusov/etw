//+build windows

package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"sync"

	"github.com/tarusov/etw"
)

/*
	This example tracing events for target provider by GUID or name.
*/
func main() {
	if len(os.Args) != 2 {
		log.Fatalf("Usage: %s <providerGUID>", filepath.Base(os.Args[0]))
	}

	session, err := etw.NewSession(&etw.SessionOptions{
		ProviderName: os.Args[1],
		TraceLevel:   "verbose",
	})
	if err != nil {
		log.Fatalf("[ERR] Create session failed: %v", err.Error())
	}

	cb := func(data []byte) {
		fmt.Println(string(data))
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		if err := session.Process(cb); err != nil {
			log.Printf("[ERR] Got error processing events: %s", err)
		} else {
			log.Printf("[DBG] Successfully shut down")
		}

		wg.Done()
	}()

	// Trap cancellation (the only signal values guaranteed to be present in
	// the os package on all systems are os.Interrupt and os.Kill).
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)

	// Wait for stop and shutdown gracefully.
	for range sigCh {
		log.Printf("[DBG] Shutting the session down")

		err = session.Close()
		if err != nil {
			log.Printf("[ERR] Failed to stop session: %s\n", err)
			os.Exit(1)
		} else {
			break
		}
	}

	wg.Wait()
}
