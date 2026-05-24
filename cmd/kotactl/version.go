package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

// Version is set at link time (e.g. -ldflags "-X main.Version=1.2.3").
var Version = "dev"

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print kotactl version",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println(Version)
	},
}
