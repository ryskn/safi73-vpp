// smoke: govpp -> VPP 疎通確認。VPPバージョン取得 + SR policy dump。
package main

import (
	"fmt"
	"log"

	"go.fd.io/govpp"

	"github.com/ryskn/safi73-vpp/binapi/sr"
	"github.com/ryskn/safi73-vpp/binapi/vpe"
)

const sock = "/run/vpp/api.sock"

func main() {
	conn, err := govpp.Connect(sock)
	if err != nil {
		log.Fatalf("connect %s: %v", sock, err)
	}
	defer conn.Disconnect()

	ch, err := conn.NewAPIChannel()
	if err != nil {
		log.Fatalf("api channel: %v", err)
	}
	defer ch.Close()

	// 1) VPP バージョン
	verReply := &vpe.ShowVersionReply{}
	if err := ch.SendRequest(&vpe.ShowVersion{}).ReceiveReply(verReply); err != nil {
		log.Fatalf("show version: %v", err)
	}
	fmt.Printf("connected to VPP %s (%s)\n", verReply.Version, verReply.BuildDate)

	// 2) SR policy dump (SAFI73 で受けた経路をここに入れていく対象)
	fmt.Println("--- SR policies ---")
	n := 0
	reqCtx := ch.SendMultiRequest(&sr.SrPoliciesDump{})
	for {
		msg := &sr.SrPoliciesDetails{}
		stop, err := reqCtx.ReceiveReply(msg)
		if err != nil {
			log.Fatalf("sr dump: %v", err)
		}
		if stop {
			break
		}
		n++
		fmt.Printf("  bsid=%s segs-lists=%d\n", msg.Bsid, msg.NumSidLists)
	}
	fmt.Printf("total SR policies: %d\n", n)
}
