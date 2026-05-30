// Package bgp は gobgpd の gRPC API を SR Policy イベント源として提供する adapter。
// control.Source を(暗黙的に)満たす。
package bgp

import (
	"context"
	"fmt"

	api "github.com/osrg/gobgp/v4/api"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/ryskn/safi73-vpp/internal/srpolicy"
)

// Source は gobgpd gRPC クライアント。
type Source struct {
	conn   *grpc.ClientConn
	client api.GoBgpServiceClient
}

// Dial は gobgpd の gRPC API に接続する。
func Dial(addr string) (*Source, error) {
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("dial gobgp %s: %w", addr, err)
	}
	return &Source{conn: conn, client: api.NewGoBgpServiceClient(conn)}, nil
}

// Close は gRPC 接続を閉じる。
func (s *Source) Close() error { return s.conn.Close() }

// Subscribe は best-path 更新を購読し、SR Policy (SAFI 73) のみを handler に渡す。
// gobgp の WatchEvent は family フィルタを持たないため、ここで SAFI73 を選別する。
func (s *Source) Subscribe(ctx context.Context, handler func(srpolicy.Event)) error {
	stream, err := s.client.WatchEvent(ctx, &api.WatchEventRequest{
		Table: &api.WatchEventRequest_Table{
			Filters: []*api.WatchEventRequest_Table_Filter{
				{Type: api.WatchEventRequest_Table_Filter_TYPE_BEST, Init: true},
			},
		},
	})
	if err != nil {
		return fmt.Errorf("watch event: %w", err)
	}
	for {
		resp, err := stream.Recv()
		if err != nil {
			return err
		}
		te := resp.GetTable()
		if te == nil {
			continue
		}
		for _, path := range te.GetPaths() {
			if ev, ok := decodePath(path); ok {
				handler(ev)
			}
		}
	}
}
