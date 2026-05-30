// safi73-vppd: gobgpd が広告する SR Policy (SAFI 73) を購読し、govpp 経由で
// VPP の SRv6 SR Policy として投入/削除する daemon。
//
// このファイルは composition root。具体実装(bgp.Source / vpp.Programmer)と任意の
// 変換(usid.Compactor)を生成し、抽象にのみ依存する control.Reconciler に注入する。
package main

import (
	"context"
	"flag"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"syscall"

	"github.com/ryskn/safi73-vpp/internal/adapter/bgp"
	"github.com/ryskn/safi73-vpp/internal/adapter/vpp"
	"github.com/ryskn/safi73-vpp/internal/control"
	"github.com/ryskn/safi73-vpp/internal/usid"
)

func main() {
	gobgpAddr := flag.String("gobgp", "127.0.0.1:50051", "gobgpd gRPC API アドレス")
	vppSock := flag.String("vpp", "/run/vpp/api.sock", "VPP binary API socket")
	encap := flag.Bool("encap", true, "SR Policy を encap モード(T.Encaps)で投入する")
	fibTable := flag.Uint("fib", 0, "SR Policy の FIB table 番号")
	usidBlock := flag.String("usid-block", "", "uSID ブロック (例 fcbb:bb00::/32)。指定すると segment list を uSID carrier に圧縮する")
	usidLen := flag.Int("usid-len", 16, "uSID 長(ビット)")
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))

	conn, err := vpp.Connect(*vppSock)
	if err != nil {
		log.Error("vpp connect", "err", err)
		os.Exit(1)
	}
	defer conn.Close()
	log.Info("connected to VPP", "sock", *vppSock, "encap", *encap, "fib", *fibTable)

	src, err := bgp.Dial(*gobgpAddr)
	if err != nil {
		log.Error("gobgp dial", "err", err)
		os.Exit(1)
	}
	defer src.Close()
	log.Info("watching gobgp for SR Policy (SAFI 73)", "addr", *gobgpAddr)

	prog := vpp.NewProgrammer(conn.Channel, vpp.Options{Encap: *encap, FIBTable: uint32(*fibTable)})

	var opts []control.Option
	if *usidBlock != "" {
		pfx, err := netip.ParsePrefix(*usidBlock)
		if err != nil {
			log.Error("parse usid-block", "err", err)
			os.Exit(1)
		}
		blk := usid.Block{Prefix: pfx, USIDBits: *usidLen}
		if err := blk.Validate(); err != nil {
			log.Error("invalid uSID block", "err", err)
			os.Exit(1)
		}
		opts = append(opts, control.WithTransform(usid.Compactor{Block: blk}))
		log.Info("uSID compaction enabled", "block", pfx, "usid_bits", *usidLen, "per_carrier", blk.PerCarrier())
	}

	rec := control.NewReconciler(src, prog, control.NewMemStore(), log, opts...)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := rec.Run(ctx); err != nil && ctx.Err() == nil {
		log.Error("reconciler stopped", "err", err)
		os.Exit(1)
	}
	log.Info("shutting down")
}
