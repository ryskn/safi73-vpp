// safi73-vppd: gobgpd が広告する SR Policy (SAFI 73) を購読し、govpp 経由で
// VPP の SRv6 SR Policy として投入/削除する daemon。
//
// このファイルは composition root。具体実装(bgp.Source / vpp.Programmer)を生成し、
// 抽象にのみ依存する control.Reconciler に注入して結線する。
package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/ryskn/safi73-vpp/internal/adapter/bgp"
	"github.com/ryskn/safi73-vpp/internal/adapter/vpp"
	"github.com/ryskn/safi73-vpp/internal/control"
)

func main() {
	gobgpAddr := flag.String("gobgp", "127.0.0.1:50051", "gobgpd gRPC API アドレス")
	vppSock := flag.String("vpp", "/run/vpp/api.sock", "VPP binary API socket")
	encap := flag.Bool("encap", true, "SR Policy を encap モード(T.Encaps)で投入する")
	fibTable := flag.Uint("fib", 0, "SR Policy の FIB table 番号")
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
	rec := control.NewReconciler(src, prog, control.NewMemStore(), log)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := rec.Run(ctx); err != nil && ctx.Err() == nil {
		log.Error("reconciler stopped", "err", err)
		os.Exit(1)
	}
	log.Info("shutting down")
}
