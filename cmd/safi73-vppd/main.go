// safi73-vppd: gobgpd が広告する SR Policy (SAFI 73) を購読し、RFC 9256 の
// candidate-path 選択を行って active CP を govpp 経由で VPP に instantiate する daemon。
//
// composition root: 具象(bgp.Source / vpp.Programmer)と任意の変換(usid.Compactor)を
// 生成し、抽象にのみ依存する control.Reconciler に注入する。
package main

import (
	"context"
	"flag"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ryskn/safi73-vpp/binapi/sr"
	"github.com/ryskn/safi73-vpp/internal/adapter/bgp"
	"github.com/ryskn/safi73-vpp/internal/adapter/vpp"
	"github.com/ryskn/safi73-vpp/internal/control"
	"github.com/ryskn/safi73-vpp/internal/usid"
)

// reconnectWait は gobgp ストリーム断からの再購読までの待ち。
const reconnectWait = 3 * time.Second

func main() {
	gobgpAddr := flag.String("gobgp", "127.0.0.1:50051", "gobgpd gRPC API アドレス")
	routerID := flag.String("router-id", "", "RT 照合に使う自ノードの BGP Identifier (省略時は gobgpd から取得)")
	vppSock := flag.String("vpp", "/run/vpp/api.sock", "VPP binary API socket")
	encap := flag.Bool("encap", true, "SR Policy を encap モード(T.Encaps)で投入する")
	encapSrc := flag.String("encap-src", "", "per-policy の outer IPv6 送信元 (sr_policy_add_v2)。省略時は VPP グローバル設定に従う")
	policyType := flag.String("policy-type", "default", "SR Policy type: default | spray | tef")
	fibTable := flag.Uint("fib", 0, "SR Policy の FIB table 番号 (BSID の VRF 兼 encap 後の egress lookup テーブル)")
	steer := flag.Bool("steer", true, "endpoint/128(/32) への L3 steering を policy と一緒に投入する")
	orphanGC := flag.Bool("orphan-gc", false, "初期同期後、BGP 側に対応 CP が無い VPP 上の SR Policy を削除する (VPP を他の管理主体と共有しているなら無効のまま)")
	usidBlock := flag.String("usid-block", "", "uSID ブロック (例 fcbb:bb00::/32)。指定すると segment list を uSID carrier に圧縮する")
	usidLen := flag.Int("usid-len", 16, "uSID 長(ビット)")
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))

	ptype, ok := map[string]sr.SrPolicyType{
		"default": sr.SR_API_POLICY_TYPE_DEFAULT,
		"spray":   sr.SR_API_POLICY_TYPE_SPRAY,
		"tef":     sr.SR_API_POLICY_TYPE_TEF,
	}[*policyType]
	if !ok {
		log.Error("invalid -policy-type", "value", *policyType)
		os.Exit(1)
	}

	popts := vpp.Options{Encap: *encap, FIBTable: uint32(*fibTable), Type: ptype, SteerEndpoint: *steer}
	if *encapSrc != "" {
		a, err := netip.ParseAddr(*encapSrc)
		if err != nil || !a.Is6() || a.Is4In6() {
			log.Error("invalid -encap-src (IPv6 のみ)", "value", *encapSrc, "err", err)
			os.Exit(1)
		}
		popts.EncapSrc = a
	} else if *encap {
		log.Warn("no -encap-src; VPP グローバルの encap source (既定 ::) が使われる。" +
			"未設定なら vppctl 'set sr encaps source addr <ip6>' が必要")
	}

	conn, err := vpp.Connect(*vppSock)
	if err != nil {
		log.Error("vpp connect", "err", err)
		os.Exit(1)
	}
	defer conn.Close()
	log.Info("connected to VPP", "sock", *vppSock, "encap", *encap, "fib", *fibTable,
		"steer", *steer, "policy_type", *policyType)

	src, err := bgp.Dial(*gobgpAddr, *routerID, log)
	if err != nil {
		log.Error("gobgp dial", "err", err)
		os.Exit(1)
	}
	defer src.Close()
	log.Info("watching gobgp for SR Policy (SAFI 73)", "addr", *gobgpAddr)

	prog := vpp.NewProgrammer(conn.Channel, popts, log)

	var opts []control.Option
	if *orphanGC {
		opts = append(opts, control.WithOrphanGC())
	}
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

	rec := control.NewReconciler(src, prog, log, opts...)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// gobgpd の再起動やストリーム断では daemon を落とさず再購読する。
	// Reconciler は状態を保持したまま、再購読の初期 dump + 世代 sweep で追い付く。
	for {
		err := rec.Run(ctx)
		if ctx.Err() != nil {
			break
		}
		log.Error("gobgp stream broken; resubscribing", "err", err, "wait", reconnectWait)
		select {
		case <-time.After(reconnectWait):
		case <-ctx.Done():
		}
	}
	log.Info("shutting down")
}
