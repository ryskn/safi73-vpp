// inject-srpolicy: テスト用。gobgpd の gRPC API に SRv6 SR Policy (SAFI 73) を 1 本
// 注入(または withdraw)する。safi73-vppd の動作確認に使う。
package main

import (
	"context"
	"flag"
	"log"
	"net"
	"strings"
	"time"

	api "github.com/osrg/gobgp/v4/api"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	addr := flag.String("gobgp", "127.0.0.1:50051", "gobgpd gRPC API")
	color := flag.Uint("color", 100, "SR Policy color")
	dist := flag.Uint("distinguisher", 1, "SR Policy distinguisher")
	endpoint := flag.String("endpoint", "2001:db8::1", "SR Policy endpoint (IPv6)")
	nexthop := flag.String("nexthop", "2001:db8::1", "next-hop (IPv6)")
	bsid := flag.String("bsid", "2001:db8:b::1", "Binding SID (IPv6)")
	segs := flag.String("segments", "2001:db8:cafe::1,2001:db8:cafe::2", "SRv6 SID list (comma separated)")
	pref := flag.Uint("preference", 100, "SR Policy preference")
	withdraw := flag.Bool("withdraw", false, "withdraw instead of add")
	flag.Parse()

	conn, err := grpc.NewClient(*addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	client := api.NewGoBgpServiceClient(conn)

	nlri := &api.NLRI{Nlri: &api.NLRI_SrPolicy{SrPolicy: &api.SRPolicyNLRI{
		Length:        192, // bits: distinguisher(4)+color(4)+endpoint(16) = 24B
		Distinguisher: uint32(*dist),
		Color:         uint32(*color),
		Endpoint:      net.ParseIP(*endpoint).To16(),
	}}}

	var segList []*api.TunnelEncapSubTLVSRSegmentList_Segment
	for _, s := range strings.Split(*segs, ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		segList = append(segList, &api.TunnelEncapSubTLVSRSegmentList_Segment{
			Segment: &api.TunnelEncapSubTLVSRSegmentList_Segment_B{
				B: &api.SegmentTypeB{
					Flags: &api.SegmentFlags{},
					Sid:   net.ParseIP(s).To16(),
					EndpointBehaviorStructure: &api.SRv6EndPointBehavior{
						Behavior: api.SRV6Behavior_SRV6_BEHAVIOR_END_DT6,
					},
				},
			},
		})
	}

	tunnelEncap := &api.TunnelEncapAttribute{Tlvs: []*api.TunnelEncapTLV{{
		Type: 15, // TUNNEL_TYPE_SR_POLICY
		Tlvs: []*api.TunnelEncapTLV_TLV{
			{Tlv: &api.TunnelEncapTLV_TLV_SrPreference{
				SrPreference: &api.TunnelEncapSubTLVSRPreference{Preference: uint32(*pref)},
			}},
			{Tlv: &api.TunnelEncapTLV_TLV_SrBindingSid{
				SrBindingSid: &api.TunnelEncapSubTLVSRBindingSID{
					Bsid: &api.TunnelEncapSubTLVSRBindingSID_SrBindingSid{
						SrBindingSid: &api.SRBindingSID{Sid: net.ParseIP(*bsid).To16()},
					},
				},
			}},
			{Tlv: &api.TunnelEncapTLV_TLV_SrSegmentList{
				SrSegmentList: &api.TunnelEncapSubTLVSRSegmentList{
					Weight:   &api.SRWeight{Weight: 1},
					Segments: segList,
				},
			}},
		},
	}}}

	pattrs := []*api.Attribute{
		{Attr: &api.Attribute_Origin{Origin: &api.OriginAttribute{Origin: 0}}},
		{Attr: &api.Attribute_NextHop{NextHop: &api.NextHopAttribute{NextHop: *nexthop}}},
		{Attr: &api.Attribute_TunnelEncap{TunnelEncap: tunnelEncap}},
	}

	path := &api.Path{
		Family: &api.Family{Afi: api.Family_AFI_IP6, Safi: api.Family_SAFI_SR_POLICY},
		Nlri:   nlri,
		Pattrs: pattrs,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if *withdraw {
		_, err = client.DeletePath(ctx, &api.DeletePathRequest{
			TableType: api.TableType_TABLE_TYPE_GLOBAL,
			Path:      path,
		})
		if err != nil {
			log.Fatalf("DeletePath: %v", err)
		}
		log.Printf("withdrew SR Policy color=%d endpoint=%s bsid=%s", *color, *endpoint, *bsid)
		return
	}

	resp, err := client.AddPath(ctx, &api.AddPathRequest{
		TableType: api.TableType_TABLE_TYPE_GLOBAL,
		Path:      path,
	})
	if err != nil {
		log.Fatalf("AddPath: %v", err)
	}
	log.Printf("added SR Policy color=%d endpoint=%s bsid=%s segs=%q uuid=%x",
		*color, *endpoint, *bsid, *segs, resp.GetUuid())
}
