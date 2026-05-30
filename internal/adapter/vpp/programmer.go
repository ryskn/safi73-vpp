package vpp

import (
	"fmt"
	"net/netip"

	govppapi "go.fd.io/govpp/api"

	"github.com/ryskn/safi73-vpp/binapi/ip_types"
	"github.com/ryskn/safi73-vpp/binapi/sr"
	sr_types "github.com/ryskn/safi73-vpp/binapi/sr_types"
	"github.com/ryskn/safi73-vpp/internal/srpolicy"
)

// maxSids は VPP の Srv6SidList が持てる SID 数の上限。
const maxSids = 16

// Options は SR Policy 投入時の挙動。
type Options struct {
	Encap    bool   // true: encap (T.Encaps) / false: insert
	FIBTable uint32 // SR Policy を置く FIB table
}

// Programmer は govpp channel 越しに VPP の SRv6 SR Policy を操作する。
// 具体接続ではなく govppapi.Channel(インターフェース)に依存するため、テスト可能。
type Programmer struct {
	ch   govppapi.Channel
	opts Options
}

// NewProgrammer は channel と挙動オプションを注入して生成する。
func NewProgrammer(ch govppapi.Channel, opts Options) *Programmer {
	return &Programmer{ch: ch, opts: opts}
}

// Add は SR Policy を投入する。先頭 segment list を sr_policy_add で作り、
// 2 本目以降は sr_policy_mod(ADD) で同じ BSID に追加する。
func (p *Programmer) Add(pol srpolicy.Policy) error {
	bsid := toIP6(pol.BSID)

	reply := &sr.SrPolicyAddReply{}
	if err := p.ch.SendRequest(&sr.SrPolicyAdd{
		BsidAddr: bsid,
		Weight:   pol.SegmentLists[0].Weight,
		IsEncap:  p.opts.Encap,
		FibTable: p.opts.FIBTable,
		Sids:     sidList(pol.SegmentLists[0]),
	}).ReceiveReply(reply); err != nil {
		return fmt.Errorf("sr_policy_add bsid=%s: %w", pol.BSID, err)
	}
	if reply.Retval != 0 {
		return fmt.Errorf("sr_policy_add bsid=%s retval=%d", pol.BSID, reply.Retval)
	}

	for i := 1; i < len(pol.SegmentLists); i++ {
		if err := p.addSegmentList(bsid, pol.SegmentLists[i]); err != nil {
			return err
		}
	}
	return nil
}

func (p *Programmer) addSegmentList(bsid ip_types.IP6Address, sl srpolicy.SegmentList) error {
	reply := &sr.SrPolicyModReply{}
	if err := p.ch.SendRequest(&sr.SrPolicyMod{
		BsidAddr:  bsid,
		Operation: sr_types.SR_POLICY_OP_API_ADD,
		FibTable:  p.opts.FIBTable,
		Weight:    sl.Weight,
		Sids:      sidList(sl),
	}).ReceiveReply(reply); err != nil {
		return fmt.Errorf("sr_policy_mod add-sl: %w", err)
	}
	if reply.Retval != 0 {
		return fmt.Errorf("sr_policy_mod add-sl retval=%d", reply.Retval)
	}
	return nil
}

// Remove は BSID をキーに SR Policy を削除する。
func (p *Programmer) Remove(pol srpolicy.Policy) error {
	reply := &sr.SrPolicyDelReply{}
	if err := p.ch.SendRequest(&sr.SrPolicyDel{
		BsidAddr: toIP6(pol.BSID),
	}).ReceiveReply(reply); err != nil {
		return fmt.Errorf("sr_policy_del bsid=%s: %w", pol.BSID, err)
	}
	if reply.Retval != 0 {
		return fmt.Errorf("sr_policy_del bsid=%s retval=%d", pol.BSID, reply.Retval)
	}
	return nil
}

func toIP6(a netip.Addr) ip_types.IP6Address {
	return ip_types.IP6Address(a.As16())
}

func sidList(sl srpolicy.SegmentList) sr.Srv6SidList {
	n := len(sl.SIDs)
	if n > maxSids {
		n = maxSids
	}
	out := sr.Srv6SidList{NumSids: uint8(n), Weight: sl.Weight}
	for i := 0; i < n; i++ {
		out.Sids[i] = toIP6(sl.SIDs[i])
	}
	return out
}
