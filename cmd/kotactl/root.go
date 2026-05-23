package main

import (
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "kotactl",
	Short: "KOTA control plane CLI",
	Long: `kotactl talks to the node-local kotad daemon (gRPC over Unix domain socket)
to apply policy and inspect enforcement status.`,
}

func init() {
	rootCmd.AddCommand(applyCmd, statusCmd, versionCmd)
}
