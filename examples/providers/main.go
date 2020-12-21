// +build windows

package main

import (
	"fmt"
	"log"

	"github.com/tarusov/etw/internal/provider"
)

/*
	This example get list of event tracing providers, and show it's keywords.
*/
func main() {
	providers, err := provider.EnumerateProviders()
	if err != nil {
		log.Fatal(err)
	}

	for pName, pGUID := range providers {
		fmt.Printf("PROVIDER: %s %s\n", pName, pGUID.String())

		keywords, err := provider.EnumerateProviderKeywords(pGUID)
		if err != nil {
			fmt.Printf("[ERR] Failed enumerate provider keywords: %v\n", err)
			continue
		}

		for kName, kVal := range keywords {
			fmt.Printf("KEYWORD: %s %d\n", kName, kVal)
		}
	}
}
