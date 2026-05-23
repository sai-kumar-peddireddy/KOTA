package main

import (
	"context"
	"net"
	"strings"

	controlv1 "github.com/sai-kumar-peddireddy/KOTA/api/gen/go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const defaultControlSocket = "unix:///run/kota/kotad.sock"

// newControlClient wires the generated V4.2 gRPC client.
// Connection/dial options are finalized in V4.5/V4.6.
func newControlClient(conn grpc.ClientConnInterface) controlv1.KotaControlPlaneClient {
	return controlv1.NewKotaControlPlaneClient(conn)
}

func dialControlConn(ctx context.Context, socket string) (*grpc.ClientConn, error) {
	addr := socket
	if strings.HasPrefix(addr, "unix://") {
		addr = strings.TrimPrefix(addr, "unix://")
	}
	return grpc.DialContext(
		ctx,
		"unix://"+addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", addr)
		}),
	)
}
