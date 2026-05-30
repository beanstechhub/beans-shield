package main

import (
	"context"
	"fmt"
	"os"

	"github.com/beanstech/beans-shield/scanner"
)

func main() {
	target := "."
	if len(os.Args) > 1 {
		target = os.Args[1]
	}

	s := scanner.New()
	result, err := s.ScanDir(context.Background(), target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scan error: %v\n", err)
		os.Exit(1)
	}

	fmt.Print(s.FormatFindings(result))

	if result.Critical > 0 || result.High > 0 {
		os.Exit(2)
	}
}
