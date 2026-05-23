package main

import (
	"context"
	"fmt"
	"os"
	"time"

	controlv1 "github.com/sai-kumar-peddireddy/KOTA/api/gen/go"
	"github.com/spf13/cobra"
)

var (
	applyFilePath string
	applySocket   string
)

var applyCmd = &cobra.Command{
	Use:   "apply",
	Short: "Apply policy to kotad",
	Long:  `Reads policy YAML from a file and sends it to kotad over UDS gRPC.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if applyFilePath == "" {
			return fmt.Errorf("required flag \"-f, --file\" not set")
		}
		raw, err := os.ReadFile(applyFilePath)
		if err != nil {
			return fmt.Errorf("read %q: %w", applyFilePath, err)
		}
		if len(raw) == 0 {
			return fmt.Errorf("policy file %q is empty", applyFilePath)
		}

		ctx, cancel := context.WithTimeout(cmd.Context(), 5*time.Second)
		defer cancel()

		conn, err := dialControlConn(ctx, applySocket)
		if err != nil {
			return fmt.Errorf("connect kotad (%s): %w", applySocket, err)
		}
		defer conn.Close()

		resp, err := newControlClient(conn).ApplyPolicy(ctx, &controlv1.ApplyPolicyRequest{
			PolicyYaml: string(raw),
			Source:     "kotactl apply -f " + applyFilePath,
		})
		if err != nil {
			return fmt.Errorf("apply policy: %w", err)
		}

		fmt.Fprintf(cmd.OutOrStdout(), "applied policy_id=%s created=%t\n", resp.GetPolicyId(), resp.GetCreated())
		return nil
	},
}

func init() {
	applyCmd.Flags().StringVarP(&applyFilePath, "file", "f", "", "Path to policy YAML file")
	applyCmd.Flags().StringVar(&applySocket, "socket", defaultControlSocket, "UDS endpoint for kotad (unix:///path or /path)")
}
