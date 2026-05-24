package main

import (
	"context"
	"encoding/json"
	"fmt"
	"text/tabwriter"
	"time"

	controlv1 "github.com/sai-kumar-peddireddy/KOTA/api/gen/go"
	"github.com/spf13/cobra"
)

var (
	statusSocket string
	statusOutput string
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show enforcement status from kotad",
	Long:  `Displays per-cgroup or per-pod verdict and profile state from kotad.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if statusOutput != "table" && statusOutput != "json" {
			return fmt.Errorf("unsupported output format %q (allowed: table, json)", statusOutput)
		}

		ctx, cancel := context.WithTimeout(cmd.Context(), 5*time.Second)
		defer cancel()

		conn, err := dialControlConn(ctx, statusSocket)
		if err != nil {
			return fmt.Errorf("connect kotad (%s): %w", statusSocket, err)
		}
		defer conn.Close()

		resp, err := newControlClient(conn).GetStatus(ctx, &controlv1.GetStatusRequest{})
		if err != nil {
			return fmt.Errorf("get status: %w", err)
		}

		type row struct {
			Key     string `json:"key"`
			Verdict string `json:"verdict"`
			Profile string `json:"profile"`
			Armed   bool   `json:"armed"`
		}

		rows := make([]row, 0, len(resp.Workloads))
		for _, w := range resp.Workloads {
			key := w.GetWorkloadKey()
			if ns, pod := w.GetNamespace(), w.GetPod(); ns != "" && pod != "" {
				key = ns + "/" + pod
			}
			rows = append(rows, row{
				Key:     key,
				Verdict: w.GetVerdict(),
				Profile: w.GetProfile(),
				Armed:   w.GetArmed(),
			})
		}

		if statusOutput == "json" {
			enc := json.NewEncoder(cmd.OutOrStdout())
			enc.SetIndent("", "  ")
			return enc.Encode(rows)
		}

		tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "KEY\tVERDICT\tPROFILE\tARMED")
		for _, r := range rows {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%t\n", r.Key, r.Verdict, r.Profile, r.Armed)
		}
		return tw.Flush()
	},
}

func init() {
	statusCmd.Flags().StringVar(&statusSocket, "socket", defaultControlSocket, "UDS endpoint for kotad (unix:///path or /path)")
	statusCmd.Flags().StringVarP(&statusOutput, "output", "o", "table", "Output format: table|json")
}
