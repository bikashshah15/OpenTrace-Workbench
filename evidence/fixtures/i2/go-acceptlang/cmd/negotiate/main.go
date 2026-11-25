package main

import (
	"fmt"
	"os"

	fixture "example.com/opentrace/fixture/i2"
)

func main() {
	got, err := fixture.Negotiate(os.Args[1], []string{"en", "fr", "de"})
	if err != nil {
		fmt.Println("error:", err)
		os.Exit(1)
	}
	fmt.Println(got)
}
