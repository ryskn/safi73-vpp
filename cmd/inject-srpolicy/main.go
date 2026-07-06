// inject-srpolicy: テスト用。gobgpd の gRPC API に SRv6 SR Policy (SAFI 73) を 1 candidate
// path 注入(または withdraw)する。複数 SID-list(weighted ECMP)に対応。
package main

import (
	"context"
	"flag"
	"log"
	"net"
	"strconv"
	"strings"
	"time"

	api "github.com/osrg/gobgp/v4/api"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	addr := flag.String("gobgp", "127.0.0.1:50051", "gobgpd gRPC API")
	color := flag.Uint("color", 100, "SR Policy color")
	dist := flag.Uint("distinguisher", 1, "candidate path distinguisher")
	endpoint := flag.String("endpoint", "2001:db8::1", "SR Policy endpoint (IPv6)")
	nexthop := flag.String("nexthop", "2001:db8::1", "next-hop (IPv6)")
	bsid := flag.String("bsid", "2001:db8:b::1", "Binding SID (IPv6)。空文字で BSID sub-TLV を省略 (headend の動的割当を試す用)")
	segs := flag.String("segments", "2001:db8:cafe::1,2001:db8:cafe::2", "SID-list。';' で複数 SID-list (weighted ECMP) を区切る")
	weights := flag.String("weights", "", "各 SID-list の weight (カンマ区切り 例 1,3)。省略時は全て 1")
	pref := flag.Uint("preference", 100, "SR Policy preference")
	prio := flag.Uint("priority", 128, "SR Policy priority (低い値ほど再検証が先, 既定 128 = RFC 9256 §2.12)")
	rt := flag.String("rt", "", "Route Target (対象 headend の BGP router-id, カンマ区切り可)。省略時は NO_ADVERTISE を付ける (RFC 9830 §4.1)")
	dropInvalid := flag.Bool("drop-upon-invalid", false, "BSID sub-TLV に I-Flag を立てる (invalid 時に drop, RFC 9256 §8.2)")
	withdraw := flag.Bool("withdraw", false, "withdraw instead of add")
	flag.Parse()

	conn, err := grpc.NewClient(*addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	client := api.NewGoBgpServiceClient(conn)

	nlri := &api.NLRI{Nlri: &api.NLRI_SrPolicy{SrPolicy: &api.SRPolicyNLRI{
		Length:        192,
		Distinguisher: uint32(*dist),
		Color:         uint32(*color),
		Endpoint:      net.ParseIP(*endpoint).To16(),
	}}}

	wlist := strings.Split(*weights, ",")
	subTLVs := []*api.TunnelEncapTLV_TLV{
		{Tlv: &api.TunnelEncapTLV_TLV_SrPreference{
			SrPreference: &api.TunnelEncapSubTLVSRPreference{Preference: uint32(*pref)},
		}},
		{Tlv: &api.TunnelEncapTLV_TLV_SrPriority{
			SrPriority: &api.TunnelEncapSubTLVSRPriority{Priority: uint32(*prio)},
		}},
	}
	if *bsid != "" {
		subTLVs = append(subTLVs, &api.TunnelEncapTLV_TLV{
			Tlv: &api.TunnelEncapTLV_TLV_SrBindingSid{
				SrBindingSid: &api.TunnelEncapSubTLVSRBindingSID{
					Bsid: &api.TunnelEncapSubTLVSRBindingSID_SrBindingSid{
						SrBindingSid: &api.SRBindingSID{Sid: net.ParseIP(*bsid).To16(), IFlag: *dropInvalid},
					},
				},
			},
		})
	}
	for i, group := range strings.Split(*segs, ";") {
		var segList []*api.TunnelEncapSubTLVSRSegmentList_Segment
		for s := range strings.SplitSeq(group, ",") {
			if s = strings.TrimSpace(s); s == "" {
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
		w := uint32(1)
		if i < len(wlist) {
			if v, err := strconv.Atoi(strings.TrimSpace(wlist[i])); err == nil && v >= 0 {
				w = uint32(v)
			}
		}
		subTLVs = append(subTLVs, &api.TunnelEncapTLV_TLV{
			Tlv: &api.TunnelEncapTLV_TLV_SrSegmentList{
				SrSegmentList: &api.TunnelEncapSubTLVSRSegmentList{
					Weight:   &api.SRWeight{Weight: w},
					Segments: segList,
				},
			},
		})
	}

	pattrs := []*api.Attribute{
		{Attr: &api.Attribute_Origin{Origin: &api.OriginAttribute{Origin: 0}}},
		{Attr: &api.Attribute_NextHop{NextHop: &api.NextHopAttribute{NextHop: *nexthop}}},
		{Attr: &api.Attribute_TunnelEncap{TunnelEncap: &api.TunnelEncapAttribute{
			Tlvs: []*api.TunnelEncapTLV{{Type: 15, Tlvs: subTLVs}},
		}}},
	}
	// RFC 9830 §4.1: RT を付けるか、無ければ NO_ADVERTISE を必ず付ける。
	if *rt != "" {
		var comms []*api.ExtendedCommunity
		for target := range strings.SplitSeq(*rt, ",") {
			comms = append(comms, &api.ExtendedCommunity{
				Extcom: &api.ExtendedCommunity_Ipv4AddressSpecific{
					Ipv4AddressSpecific: &api.IPv4AddressSpecificExtended{
						IsTransitive: true,
						SubType:      0x02, // Route Target
						Address:      strings.TrimSpace(target),
					},
				},
			})
		}
		pattrs = append(pattrs, &api.Attribute{Attr: &api.Attribute_ExtendedCommunities{
			ExtendedCommunities: &api.ExtendedCommunitiesAttribute{Communities: comms},
		}})
	} else {
		pattrs = append(pattrs, &api.Attribute{Attr: &api.Attribute_Communities{
			Communities: &api.CommunitiesAttribute{Communities: []uint32{0xFFFFFF02}}, // NO_ADVERTISE
		}})
	}

	path := &api.Path{
		Family: &api.Family{Afi: api.Family_AFI_IP6, Safi: api.Family_SAFI_SR_POLICY},
		Nlri:   nlri,
		Pattrs: pattrs,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if *withdraw {
		if _, err := client.DeletePath(ctx, &api.DeletePathRequest{
			TableType: api.TableType_TABLE_TYPE_GLOBAL, Path: path,
		}); err != nil {
			log.Fatalf("DeletePath: %v", err)
		}
		log.Printf("withdrew CP color=%d disc=%d bsid=%s", *color, *dist, *bsid)
		return
	}
	if _, err := client.AddPath(ctx, &api.AddPathRequest{
		TableType: api.TableType_TABLE_TYPE_GLOBAL, Path: path,
	}); err != nil {
		log.Fatalf("AddPath: %v", err)
	}
	log.Printf("added CP color=%d disc=%d pref=%d bsid=%s segs=%q weights=%q",
		*color, *dist, *pref, *bsid, *segs, *weights)
}
