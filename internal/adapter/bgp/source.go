// Package bgp は gobgpd の gRPC API を SR Policy イベント源として提供する adapter。
// control.Source を(暗黙的に)満たす。
package bgp

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	api "github.com/osrg/gobgp/v4/api"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/ryskn/safi73-vpp/internal/srpolicy"
)

// syncedFallback は、gobgp が初期 dump を送ってこない場合(テーブルが空など)でも
// synced を必ず発火させるためのタイムアウト。
const syncedFallback = 5 * time.Second

// Source は gobgpd gRPC クライアント。
type Source struct {
	conn   *grpc.ClientConn
	client api.GoBgpServiceClient
	log    *slog.Logger

	// localID は自ノードの BGP Identifier(RFC 9830 §4.2.2 の RT 照合先)。
	// 空なら Subscribe 時に GetBgp で取得する。
	localID netip.Addr
}

// Dial は gobgpd の gRPC API に接続する。routerID は RT 照合に使う自ノードの
// BGP Identifier の明示指定(空文字なら gobgpd から自動取得)。
func Dial(addr, routerID string, log *slog.Logger) (*Source, error) {
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("dial gobgp %s: %w", addr, err)
	}
	if log == nil {
		log = slog.Default()
	}
	s := &Source{conn: conn, client: api.NewGoBgpServiceClient(conn), log: log}
	if routerID != "" {
		id, err := netip.ParseAddr(routerID)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("parse router-id %q: %w", routerID, err)
		}
		s.localID = id
	}
	return s, nil
}

// Close は gRPC 接続を閉じる。
func (s *Source) Close() error { return s.conn.Close() }

// Subscribe は best-path 更新を購読し、SR Policy (SAFI 73) のみを handler に渡す。
// gobgp の WatchEvent は family フィルタを持たないため、ここで SAFI73 を選別する。
// 初期 dump(Init:true の最初の応答)を処理し終えた時点で synced を 1 回呼ぶ。
// gobgp から初期応答が来ない場合でも syncedFallback 経過後に(別 goroutine から)呼ぶ。
func (s *Source) Subscribe(ctx context.Context, handler func(srpolicy.Event), synced func()) error {
	if !s.localID.IsValid() {
		if err := s.fetchLocalID(ctx); err != nil {
			s.log.Warn("could not determine local BGP identifier; updates carrying route targets will be unusable",
				"err", err)
		} else {
			s.log.Info("local BGP identifier for route-target matching", "id", s.localID)
		}
	}

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

	var syncOnce sync.Once
	fireSynced := func() {
		if synced != nil {
			syncOnce.Do(synced)
		}
	}
	timer := time.AfterFunc(syncedFallback, fireSynced)
	defer timer.Stop()

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
			ev, ok, note := decodePath(path, s.localID)
			if !ok {
				continue
			}
			if note != "" {
				s.log.Warn("SR Policy update not usable; treating as withdraw",
					"policy", ev.Key.String(), "discriminator", ev.Path.Discriminator, "reason", note)
			}
			handler(ev)
		}
		fireSynced() // 最初の応答 = 初期 dump 処理完了
	}
}

func (s *Source) fetchLocalID(ctx context.Context) error {
	resp, err := s.client.GetBgp(ctx, &api.GetBgpRequest{})
	if err != nil {
		return err
	}
	id, err := netip.ParseAddr(resp.GetGlobal().GetRouterId())
	if err != nil {
		return fmt.Errorf("parse gobgp router-id %q: %w", resp.GetGlobal().GetRouterId(), err)
	}
	s.localID = id
	return nil
}
