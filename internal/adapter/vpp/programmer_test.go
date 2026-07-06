package vpp

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	govppapi "go.fd.io/govpp/api"

	"github.com/ryskn/safi73-vpp/binapi/fib_types"
	ipbin "github.com/ryskn/safi73-vpp/binapi/ip"
	"github.com/ryskn/safi73-vpp/binapi/sr"
	"github.com/ryskn/safi73-vpp/internal/srpolicy"
)

// fakeChannel は govppapi.Channel の検証用 fake。送信メッセージを記録し、
// メッセージ名ごとに設定された retval / dump 応答を返す。
type fakeChannel struct {
	sent        []govppapi.Message
	retvals     map[string][]int32            // メッセージ名 -> 返す retval 列(先頭から消費、尽きたら 0)
	dumps       map[string][]govppapi.Message // multi-request 応答
	lookupReply *ipbin.IPRouteLookupReply     // ip_route_lookup の応答
}

func newFakeChannel() *fakeChannel {
	return &fakeChannel{retvals: map[string][]int32{}, dumps: map[string][]govppapi.Message{}}
}

func (f *fakeChannel) nextRetval(name string) int32 {
	q := f.retvals[name]
	if len(q) == 0 {
		return 0
	}
	f.retvals[name] = q[1:]
	return q[0]
}

type fakeReqCtx struct {
	ch  *fakeChannel
	req govppapi.Message
}

func (c fakeReqCtx) ReceiveReply(msg govppapi.Message) error {
	rv := c.ch.nextRetval(c.req.GetMessageName())
	switch m := msg.(type) {
	case *sr.SrPolicyAddReply:
		m.Retval = rv
	case *sr.SrPolicyAddV2Reply:
		m.Retval = rv
	case *sr.SrPolicyModReply:
		m.Retval = rv
	case *sr.SrPolicyModV2Reply:
		m.Retval = rv
	case *sr.SrPolicyDelReply:
		m.Retval = rv
	case *sr.SrSteeringAddDelReply:
		m.Retval = rv
	case *ipbin.IPRouteLookupReply:
		if c.ch.lookupReply != nil {
			*m = *c.ch.lookupReply
		}
	case *ipbin.IPRouteAddDelReply:
		m.Retval = rv
	default:
		return fmt.Errorf("fake: unexpected reply type %T", msg)
	}
	return nil
}

type fakeMultiCtx struct {
	replies []govppapi.Message
	pos     int
}

func (c *fakeMultiCtx) ReceiveReply(msg govppapi.Message) (bool, error) {
	if c.pos >= len(c.replies) {
		return true, nil
	}
	src := c.replies[c.pos]
	c.pos++
	switch m := msg.(type) {
	case *sr.SrPoliciesV2Details:
		*m = *(src.(*sr.SrPoliciesV2Details))
	case *sr.SrPoliciesWithSlIndexDetails:
		*m = *(src.(*sr.SrPoliciesWithSlIndexDetails))
	default:
		return true, fmt.Errorf("fake: unexpected dump type %T", msg)
	}
	return false, nil
}

func (f *fakeChannel) SendRequest(msg govppapi.Message) govppapi.RequestCtx {
	f.sent = append(f.sent, msg)
	return fakeReqCtx{ch: f, req: msg}
}

func (f *fakeChannel) SendMultiRequest(msg govppapi.Message) govppapi.MultiRequestCtx {
	f.sent = append(f.sent, msg)
	return &fakeMultiCtx{replies: f.dumps[msg.GetMessageName()]}
}

func (f *fakeChannel) SubscribeNotification(chan govppapi.Message, govppapi.Message) (govppapi.SubscriptionCtx, error) {
	return nil, fmt.Errorf("not implemented")
}
func (f *fakeChannel) SetReplyTimeout(time.Duration)               {}
func (f *fakeChannel) CheckCompatiblity(...govppapi.Message) error { return nil }
func (f *fakeChannel) Close()                                      {}

func (f *fakeChannel) sentNames() []string {
	var out []string
	for _, m := range f.sent {
		out = append(out, m.GetMessageName())
	}
	return out
}

func addr(s string) netip.Addr { return netip.MustParseAddr(s) }

func testCP(bsid string, sls ...srpolicy.SegmentList) srpolicy.CandidatePath {
	if len(sls) == 0 {
		sls = []srpolicy.SegmentList{{Weight: 1, SIDs: []netip.Addr{addr("2001:db8:c::1")}}}
	}
	return srpolicy.CandidatePath{BSID: addr(bsid), SegmentLists: sls}
}

var testKey = srpolicy.PolicyKey{Color: 100, Endpoint: addr("2001:db8::1")}

func TestAddInstallsPolicyAndSteering(t *testing.T) {
	ch := newFakeChannel()
	p := NewProgrammer(ch, Options{Encap: true, SteerEndpoint: true}, nil)

	cp := testCP("2001:db8:b::1",
		srpolicy.SegmentList{Weight: 1, SIDs: []netip.Addr{addr("2001:db8:c::1")}},
		srpolicy.SegmentList{Weight: 3, SIDs: []netip.Addr{addr("2001:db8:c::2")}},
	)
	if err := p.Add(testKey, cp); err != nil {
		t.Fatal(err)
	}
	want := []string{"sr_policy_add", "sr_policy_mod", "sr_steering_add_del"}
	got := ch.sentNames()
	if len(got) != len(want) {
		t.Fatalf("sent=%v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("sent=%v, want %v", got, want)
		}
	}
	steer := ch.sent[2].(*sr.SrSteeringAddDel)
	if steer.IsDel || steer.Prefix.Len != 128 {
		t.Fatalf("steering=%+v", steer)
	}
}

// BSID が既に居る(再起動後)場合は del → add で置き換える(-12 で止まらない)。
func TestAddReplacesExistingPolicy(t *testing.T) {
	ch := newFakeChannel()
	ch.retvals["sr_policy_add"] = []int32{rvPolicyExists, 0}
	p := NewProgrammer(ch, Options{Encap: true}, nil)

	if err := p.Add(testKey, testCP("2001:db8:b::1")); err != nil {
		t.Fatal(err)
	}
	want := []string{"sr_policy_add", "sr_policy_del", "sr_policy_add"}
	got := ch.sentNames()
	if len(got) != 3 || got[0] != want[0] || got[1] != want[1] || got[2] != want[2] {
		t.Fatalf("sent=%v, want %v", got, want)
	}
}

// 2 本目の SID-list 追加に失敗したら policy ごと巻き戻す(半端な状態を残さない)。
func TestAddRollsBackOnPartialFailure(t *testing.T) {
	ch := newFakeChannel()
	ch.retvals["sr_policy_mod"] = []int32{-3}
	p := NewProgrammer(ch, Options{Encap: true}, nil)

	cp := testCP("2001:db8:b::1",
		srpolicy.SegmentList{Weight: 1, SIDs: []netip.Addr{addr("2001:db8:c::1")}},
		srpolicy.SegmentList{Weight: 3, SIDs: []netip.Addr{addr("2001:db8:c::2")}},
	)
	if err := p.Add(testKey, cp); err == nil {
		t.Fatal("want error")
	}
	got := ch.sentNames()
	if got[len(got)-1] != "sr_policy_del" {
		t.Fatalf("sent=%v, want rollback sr_policy_del at end", got)
	}
}

// 同一 BSID の Replace は del/add ではなく mod による差分更新。
func TestReplaceSameBSIDInPlace(t *testing.T) {
	bsid := "2001:db8:b::1"
	keep := srpolicy.SegmentList{Weight: 1, SIDs: []netip.Addr{addr("2001:db8:c::1")}}
	drop := srpolicy.SegmentList{Weight: 2, SIDs: []netip.Addr{addr("2001:db8:c::2")}}
	gain := srpolicy.SegmentList{Weight: 5, SIDs: []netip.Addr{addr("2001:db8:c::3")}}

	dump := &sr.SrPoliciesWithSlIndexDetails{Bsid: toIP6(addr(bsid)), NumSidLists: 2}
	mkSL := func(idx uint32, sl srpolicy.SegmentList) sr.Srv6SidListWithSlIndex {
		out := sr.Srv6SidListWithSlIndex{NumSids: uint8(len(sl.SIDs)), Weight: sl.Weight, SlIndex: idx}
		for i, s := range sl.SIDs {
			out.Sids[i] = toIP6(s)
		}
		return out
	}
	dump.SidLists = []sr.Srv6SidListWithSlIndex{mkSL(10, keep), mkSL(11, drop)}

	ch := newFakeChannel()
	ch.dumps["sr_policies_with_sl_index_dump"] = []govppapi.Message{dump}
	p := NewProgrammer(ch, Options{Encap: true}, nil)

	if err := p.Replace(testKey, testCP(bsid, keep, drop), testCP(bsid, keep, gain)); err != nil {
		t.Fatal(err)
	}
	got := ch.sentNames()
	want := []string{"sr_policies_with_sl_index_dump", "sr_policy_mod", "sr_policy_mod"}
	if len(got) != 3 || got[1] != want[1] || got[2] != want[2] {
		t.Fatalf("sent=%v, want %v", got, want)
	}
	add := ch.sent[1].(*sr.SrPolicyMod)
	del := ch.sent[2].(*sr.SrPolicyMod)
	if add.Operation != 1 || add.Sids.Weight != 5 { // ADD が先(≥1 SL 維持)
		t.Fatalf("first mod=%+v, want ADD of new SL", add)
	}
	if del.Operation != 2 || del.SlIndex != 11 { // DEL は sl_index 指定
		t.Fatalf("second mod=%+v, want DEL of stale sl_index 11", del)
	}
}

// BSID が変わる Replace は make-before-break: 新 add → steering 付替え → 旧 del。
func TestReplaceDifferentBSIDMakeBeforeBreak(t *testing.T) {
	ch := newFakeChannel()
	p := NewProgrammer(ch, Options{Encap: true, SteerEndpoint: true}, nil)

	if err := p.Replace(testKey, testCP("2001:db8:b::1"), testCP("2001:db8:b::2")); err != nil {
		t.Fatal(err)
	}
	got := ch.sentNames()
	want := []string{"sr_policy_add", "sr_steering_add_del", "sr_policy_del"}
	if len(got) != 3 || got[0] != want[0] || got[1] != want[1] || got[2] != want[2] {
		t.Fatalf("sent=%v, want %v (make-before-break)", got, want)
	}
	del := ch.sent[2].(*sr.SrPolicyDel)
	if netip.AddrFrom16(del.BsidAddr) != addr("2001:db8:b::1") {
		t.Fatalf("deleted bsid=%s, want old b::1", netip.AddrFrom16(del.BsidAddr))
	}
}

// Remove は steering → policy の順で消し、不在(-1)は成功扱い(冪等)。
func TestRemoveIdempotent(t *testing.T) {
	ch := newFakeChannel()
	ch.retvals["sr_policy_del"] = []int32{rvPolicyNotFound}
	p := NewProgrammer(ch, Options{Encap: true, SteerEndpoint: true}, nil)

	if err := p.Remove(testKey, testCP("2001:db8:b::1")); err != nil {
		t.Fatal(err)
	}
	got := ch.sentNames()
	if len(got) != 2 || got[0] != "sr_steering_add_del" || got[1] != "sr_policy_del" {
		t.Fatalf("sent=%v", got)
	}
}

// -encap-src / -policy-type 指定時は v2 API を使う。
func TestV2APIUsedWithEncapSrc(t *testing.T) {
	ch := newFakeChannel()
	p := NewProgrammer(ch, Options{Encap: true, EncapSrc: addr("2001:db8:fe::1")}, nil)

	if err := p.Add(testKey, testCP("2001:db8:b::1")); err != nil {
		t.Fatal(err)
	}
	add := ch.sent[0].(*sr.SrPolicyAddV2)
	if netip.AddrFrom16(add.EncapSrc) != addr("2001:db8:fe::1") {
		t.Fatalf("encap_src=%s", netip.AddrFrom16(add.EncapSrc))
	}
}

// 17 SID の list は error(silent truncation 禁止)。
func TestSidListRejectsOversize(t *testing.T) {
	sl := srpolicy.SegmentList{Weight: 1}
	for i := 0; i <= srpolicy.MaxSIDsPerList; i++ {
		sl.SIDs = append(sl.SIDs, addr(fmt.Sprintf("2001:db8:c::%x", i+1)))
	}
	if _, err := sidList(sl); err == nil {
		t.Fatal("want error for oversized segment list")
	}
}

// InstallDrop は steering を消して drop 経路を入れ、RemoveDrop はそれを撤去する。
func TestInstallAndRemoveDrop(t *testing.T) {
	ch := newFakeChannel()
	p := NewProgrammer(ch, Options{Encap: true, SteerEndpoint: true}, nil)

	if err := p.InstallDrop(testKey); err != nil {
		t.Fatal(err)
	}
	got := ch.sentNames()
	if len(got) != 2 || got[0] != "sr_steering_add_del" || got[1] != "ip_route_add_del" {
		t.Fatalf("sent=%v", got)
	}
	route := ch.sent[1].(*ipbin.IPRouteAddDel)
	if !route.IsAdd || route.Route.Prefix.Len != 128 ||
		route.Route.Paths[0].Type != fib_types.FIB_API_PATH_TYPE_DROP {
		t.Fatalf("drop route=%+v", route)
	}

	if err := p.RemoveDrop(testKey); err != nil {
		t.Fatal(err)
	}
	del := ch.sent[len(ch.sent)-1].(*ipbin.IPRouteAddDel)
	if del.IsAdd {
		t.Fatalf("remove drop must send IsAdd=false: %+v", del)
	}

	// steering 無効構成では drop-steer 不可
	p = NewProgrammer(newFakeChannel(), Options{Encap: true}, nil)
	if err := p.InstallDrop(testKey); err == nil {
		t.Fatal("want error when steering is disabled")
	}
}

// SIDReachable: drop 系 path しか無い route (::/0 の既定 drop 等) は到達不能扱い。
func TestSIDReachable(t *testing.T) {
	ch := newFakeChannel()
	p := NewProgrammer(ch, Options{}, nil)

	// drop only → false
	ch.lookupReply = &ipbin.IPRouteLookupReply{
		Route: ipbin.IPRoute{Paths: []fib_types.FibPath{{Type: fib_types.FIB_API_PATH_TYPE_DROP}}},
	}
	ok, err := p.SIDReachable(addr("2001:db8:c::1"))
	if err != nil || ok {
		t.Fatalf("drop-only route: ok=%v err=%v, want unreachable", ok, err)
	}

	// normal path → true
	ch.lookupReply = &ipbin.IPRouteLookupReply{
		Route: ipbin.IPRoute{Paths: []fib_types.FibPath{{Type: fib_types.FIB_API_PATH_TYPE_NORMAL}}},
	}
	if ok, err = p.SIDReachable(addr("2001:db8:c::1")); err != nil || !ok {
		t.Fatalf("normal route: ok=%v err=%v, want reachable", ok, err)
	}

	// retval != 0 (route 無し) → false
	ch.lookupReply = &ipbin.IPRouteLookupReply{Retval: -5}
	if ok, err = p.SIDReachable(addr("2001:db8:c::1")); err != nil || ok {
		t.Fatalf("no route: ok=%v err=%v, want unreachable", ok, err)
	}
}

// InstalledBSIDs は v2 dump から BSID を列挙する。
func TestInstalledBSIDs(t *testing.T) {
	ch := newFakeChannel()
	ch.dumps["sr_policies_v2_dump"] = []govppapi.Message{
		&sr.SrPoliciesV2Details{Bsid: toIP6(addr("2001:db8:b::1"))},
		&sr.SrPoliciesV2Details{Bsid: toIP6(addr("2001:db8:b::2"))},
	}
	p := NewProgrammer(ch, Options{}, nil)
	got, err := p.InstalledBSIDs()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != addr("2001:db8:b::1") || got[1] != addr("2001:db8:b::2") {
		t.Fatalf("got=%v", got)
	}
}
