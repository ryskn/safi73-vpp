package vpp

import (
	"fmt"
	"log/slog"
	"net/netip"

	govppapi "go.fd.io/govpp/api"

	"github.com/ryskn/safi73-vpp/binapi/fib_types"
	"github.com/ryskn/safi73-vpp/binapi/ip"
	"github.com/ryskn/safi73-vpp/binapi/ip_types"
	"github.com/ryskn/safi73-vpp/binapi/sr"
	sr_types "github.com/ryskn/safi73-vpp/binapi/sr_types"
	"github.com/ryskn/safi73-vpp/internal/srpolicy"
)

// VPP sr_policy_rewrite.c が返す raw retval。
const (
	rvPolicyExists   = -12 // sr_policy_add: BSID の policy が既に存在
	rvPolicyNotFound = -1  // sr_policy_del: BSID の policy が存在しない
)

// Options は SR Policy 投入時の挙動。
type Options struct {
	Encap    bool   // true: encap (T.Encaps) / false: insert
	FIBTable uint32 // BSID を置く VRF。encap 後パケットの egress lookup テーブルも兼ねる(VPP の仕様)
	// EncapSrc は per-policy の outer IPv6 送信元(sr_policy_add_v2)。未指定(zero)なら
	// v1 API を使い、VPP グローバルの encap source(既定 :: — 要 set sr encaps source)に従う。
	EncapSrc netip.Addr
	// Type は policy type(default/spray/tef)。default 以外は v2 API を使う。
	Type sr.SrPolicyType
	// SteerEndpoint は endpoint への L3 steering(endpoint/128 または /32 → policy)を
	// policy と一緒に投入する。null endpoint(::)の policy は対象外。
	SteerEndpoint bool
}

func (o Options) useV2() bool {
	return o.EncapSrc.IsValid() || o.Type != sr.SR_API_POLICY_TYPE_DEFAULT
}

// Programmer は govpp channel 越しに VPP の SRv6 SR Policy を操作する。
// govppapi.Channel(インターフェース)に依存するため、テスト可能。
// control.Programmer / control.Resyncer を(暗黙的に)満たす。
type Programmer struct {
	ch   govppapi.Channel
	opts Options
	log  *slog.Logger
}

// NewProgrammer は channel と挙動オプションを注入して生成する。
func NewProgrammer(ch govppapi.Channel, opts Options, log *slog.Logger) *Programmer {
	if log == nil {
		log = slog.Default()
	}
	return &Programmer{ch: ch, opts: opts, log: log}
}

// Add は active candidate path を投入する。冪等: 同じ BSID の policy が既に居れば
// 一旦削除して置き換える(daemon 再起動後の再同期で必ず起きる)。
func (p *Programmer) Add(key srpolicy.PolicyKey, cp srpolicy.CandidatePath) error {
	sls := cp.ValidSegmentLists()
	if len(sls) == 0 {
		return fmt.Errorf("candidate path bsid=%s has no valid segment list", cp.BSID)
	}
	if err := p.installPolicy(toIP6(cp.BSID), sls); err != nil {
		return err
	}
	return p.steerTo(key, cp.BSID)
}

// Replace は active CP の切替。同一 BSID なら in-place の差分更新(traffic 無停止)、
// BSID が変わるなら make-before-break(新 policy 投入 → steering 付替え → 旧削除)。
func (p *Programmer) Replace(key srpolicy.PolicyKey, prev, next srpolicy.CandidatePath) error {
	sls := next.ValidSegmentLists()
	if len(sls) == 0 {
		return fmt.Errorf("candidate path bsid=%s has no valid segment list", next.BSID)
	}
	if prev.BSID == next.BSID {
		return p.updateInPlace(toIP6(next.BSID), sls)
	}

	if err := p.installPolicy(toIP6(next.BSID), sls); err != nil {
		return err
	}
	if err := p.steerTo(key, next.BSID); err != nil {
		return err
	}
	// 旧 policy の削除は best-effort: 失敗しても新 CP は転送に使えている。
	// 残骸は次回起動時の再同期(orphan GC)で回収される。
	if err := p.deletePolicy(toIP6(prev.BSID)); err != nil {
		p.log.Warn("remove superseded SR policy failed; stale policy remains",
			"bsid", prev.BSID, "err", err)
	}
	return nil
}

// Remove は steering(あれば)と SR Policy を削除する。冪等: 対象が無ければ成功扱い。
func (p *Programmer) Remove(key srpolicy.PolicyKey, cp srpolicy.CandidatePath) error {
	if p.steerable(key) {
		if err := p.steerDel(key.Endpoint); err != nil {
			p.log.Warn("remove steering", "endpoint", key.Endpoint, "err", err)
		}
	}
	return p.deletePolicy(toIP6(cp.BSID))
}

// InstalledBSIDs は dataplane に居る SR Policy の BSID を列挙する(再同期用)。
func (p *Programmer) InstalledBSIDs() ([]netip.Addr, error) {
	ctx := p.ch.SendMultiRequest(&sr.SrPoliciesV2Dump{})
	var out []netip.Addr
	for {
		d := &sr.SrPoliciesV2Details{}
		stop, err := ctx.ReceiveReply(d)
		if err != nil {
			return nil, fmt.Errorf("sr_policies_v2_dump: %w", err)
		}
		if stop {
			break
		}
		out = append(out, netip.AddrFrom16(d.Bsid))
	}
	return out, nil
}

// RemoveBSID は BSID 指定で SR Policy を削除する(orphan GC 用)。
func (p *Programmer) RemoveBSID(bsid netip.Addr) error {
	return p.deletePolicy(toIP6(bsid))
}

// InstallDrop は endpoint 宛の steering を drop 経路に差し替える
// (drop-upon-invalid, RFC 9256 §8.2)。steering 対象外の policy(steering 無効 /
// null endpoint)には適用できない。
func (p *Programmer) InstallDrop(key srpolicy.PolicyKey) error {
	if !p.steerable(key) {
		return fmt.Errorf("endpoint steering is disabled or endpoint is null; cannot drop-steer")
	}
	// steering 削除から drop 投入までの短い間だけ既定経路へ逃げる余地がある
	// (同一 prefix を FIB source 違いで持たせると優先関係が不定になるため順に入れ替える)。
	if err := p.steerDel(key.Endpoint); err != nil {
		p.log.Warn("remove steering before drop", "endpoint", key.Endpoint, "err", err)
	}
	return p.dropRoute(true, key.Endpoint)
}

// RemoveDrop は drop 経路を撤去する(冪等: 対象が無ければ成功扱い)。
func (p *Programmer) RemoveDrop(key srpolicy.PolicyKey) error {
	if !key.Endpoint.IsValid() || key.Endpoint.IsUnspecified() {
		return nil
	}
	return p.dropRoute(false, key.Endpoint)
}

func (p *Programmer) dropRoute(add bool, endpoint netip.Addr) error {
	var path fib_types.FibPath
	path.Type = fib_types.FIB_API_PATH_TYPE_DROP
	route := ip.IPRoute{TableID: p.opts.FIBTable}
	if endpointIs4(endpoint) {
		v4 := endpoint.Unmap().As4()
		path.Proto = fib_types.FIB_API_PATH_NH_PROTO_IP4
		route.Prefix.Address.Af = ip_types.ADDRESS_IP4
		route.Prefix.Address.Un.SetIP4(ip_types.IP4Address(v4))
		route.Prefix.Len = 32
	} else {
		path.Proto = fib_types.FIB_API_PATH_NH_PROTO_IP6
		route.Prefix.Address.Af = ip_types.ADDRESS_IP6
		route.Prefix.Address.Un.SetIP6(toIP6(endpoint))
		route.Prefix.Len = 128
	}
	route.Paths = []fib_types.FibPath{path}

	reply := &ip.IPRouteAddDelReply{}
	if err := p.ch.SendRequest(&ip.IPRouteAddDel{IsAdd: add, Route: route}).ReceiveReply(reply); err != nil {
		return fmt.Errorf("ip_route_add_del drop endpoint=%s: %w", endpoint, err)
	}
	if reply.Retval != 0 && add {
		return fmt.Errorf("ip_route_add_del drop endpoint=%s retval=%d", endpoint, reply.Retval)
	}
	return nil // 削除の retval != 0 は冪等扱い(対象無しなど)
}

// SIDReachable は SID を FIB (opts.FIBTable, encap 後の lookup と同じテーブル) で
// LPM 解決し、drop 以外の path に解決できるかを返す(RFC 9256 §5.1 の SID 解決)。
// IPv6 FIB は ::/0 が既定 drop なので「route が引けた」だけでは到達可能とみなさない。
func (p *Programmer) SIDReachable(sid netip.Addr) (bool, error) {
	req := &ip.IPRouteLookup{TableID: p.opts.FIBTable}
	req.Prefix.Address.Af = ip_types.ADDRESS_IP6
	req.Prefix.Address.Un.SetIP6(toIP6(sid))
	req.Prefix.Len = 128

	reply := &ip.IPRouteLookupReply{}
	if err := p.ch.SendRequest(req).ReceiveReply(reply); err != nil {
		return false, fmt.Errorf("ip_route_lookup sid=%s: %w", sid, err)
	}
	if reply.Retval != 0 {
		return false, nil // 一致 route 無し
	}
	for _, path := range reply.Route.Paths {
		switch path.Type {
		case fib_types.FIB_API_PATH_TYPE_DROP,
			fib_types.FIB_API_PATH_TYPE_ICMP_UNREACH,
			fib_types.FIB_API_PATH_TYPE_ICMP_PROHIBIT:
		default:
			return true, nil
		}
	}
	return false, nil
}

// installPolicy は policy を新規投入する。BSID が既に居れば削除して置き換え、
// 途中で失敗したら投入分を巻き戻す(半端な policy を残さない)。
func (p *Programmer) installPolicy(bsid ip_types.IP6Address, sls []srpolicy.SegmentList) error {
	rv, err := p.policyAdd(bsid, sls[0])
	if err != nil {
		return err
	}
	if rv == rvPolicyExists {
		p.log.Info("SR policy already in dataplane; replacing", "bsid", bsidStr(bsid))
		if err := p.deletePolicy(bsid); err != nil {
			return fmt.Errorf("replace existing policy bsid=%s: %w", bsidStr(bsid), err)
		}
		if rv, err = p.policyAdd(bsid, sls[0]); err != nil {
			return err
		}
	}
	if rv != 0 {
		return fmt.Errorf("sr_policy_add bsid=%s retval=%d", bsidStr(bsid), rv)
	}

	for _, sl := range sls[1:] {
		if err := p.addSegmentList(bsid, sl); err != nil {
			if derr := p.deletePolicy(bsid); derr != nil {
				p.log.Error("rollback partial SR policy failed", "bsid", bsidStr(bsid), "err", derr)
			}
			return err
		}
	}
	return nil
}

func (p *Programmer) policyAdd(bsid ip_types.IP6Address, sl srpolicy.SegmentList) (int32, error) {
	sids, err := sidList(sl)
	if err != nil {
		return 0, err
	}
	if p.opts.useV2() {
		reply := &sr.SrPolicyAddV2Reply{}
		req := &sr.SrPolicyAddV2{
			BsidAddr: bsid,
			Weight:   sl.Weight,
			IsEncap:  p.opts.Encap,
			Type:     p.opts.Type,
			FibTable: p.opts.FIBTable,
			Sids:     sids,
		}
		if p.opts.EncapSrc.IsValid() {
			req.EncapSrc = toIP6(p.opts.EncapSrc)
		}
		if err := p.ch.SendRequest(req).ReceiveReply(reply); err != nil {
			return 0, fmt.Errorf("sr_policy_add_v2 bsid=%s: %w", bsidStr(bsid), err)
		}
		return reply.Retval, nil
	}
	reply := &sr.SrPolicyAddReply{}
	if err := p.ch.SendRequest(&sr.SrPolicyAdd{
		BsidAddr: bsid,
		Weight:   sl.Weight,
		IsEncap:  p.opts.Encap,
		FibTable: p.opts.FIBTable,
		Sids:     sids,
	}).ReceiveReply(reply); err != nil {
		return 0, fmt.Errorf("sr_policy_add bsid=%s: %w", bsidStr(bsid), err)
	}
	return reply.Retval, nil
}

func (p *Programmer) addSegmentList(bsid ip_types.IP6Address, sl srpolicy.SegmentList) error {
	sids, err := sidList(sl)
	if err != nil {
		return err
	}
	if p.opts.useV2() {
		reply := &sr.SrPolicyModV2Reply{}
		req := &sr.SrPolicyModV2{
			BsidAddr:  bsid,
			Operation: sr_types.SR_POLICY_OP_API_ADD,
			FibTable:  p.opts.FIBTable,
			Weight:    sl.Weight,
			Sids:      sids,
		}
		if p.opts.EncapSrc.IsValid() {
			req.EncapSrc = toIP6(p.opts.EncapSrc)
		}
		if err := p.ch.SendRequest(req).ReceiveReply(reply); err != nil {
			return fmt.Errorf("sr_policy_mod_v2 add-sl: %w", err)
		}
		if reply.Retval != 0 {
			return fmt.Errorf("sr_policy_mod_v2 add-sl retval=%d", reply.Retval)
		}
		return nil
	}
	reply := &sr.SrPolicyModReply{}
	if err := p.ch.SendRequest(&sr.SrPolicyMod{
		BsidAddr:  bsid,
		Operation: sr_types.SR_POLICY_OP_API_ADD,
		FibTable:  p.opts.FIBTable,
		Weight:    sl.Weight,
		Sids:      sids,
	}).ReceiveReply(reply); err != nil {
		return fmt.Errorf("sr_policy_mod add-sl: %w", err)
	}
	if reply.Retval != 0 {
		return fmt.Errorf("sr_policy_mod add-sl retval=%d", reply.Retval)
	}
	return nil
}

func (p *Programmer) delSegmentList(bsid ip_types.IP6Address, slIndex uint32) error {
	reply := &sr.SrPolicyModReply{}
	if err := p.ch.SendRequest(&sr.SrPolicyMod{
		BsidAddr:  bsid,
		Operation: sr_types.SR_POLICY_OP_API_DEL,
		FibTable:  p.opts.FIBTable,
		SlIndex:   slIndex,
	}).ReceiveReply(reply); err != nil {
		return fmt.Errorf("sr_policy_mod del-sl: %w", err)
	}
	if reply.Retval != 0 {
		return fmt.Errorf("sr_policy_mod del-sl index=%d retval=%d", slIndex, reply.Retval)
	}
	return nil
}

// updateInPlace は同一 BSID の policy の SID-list 集合を差分更新する。
// 追加(mod ADD)を先に、削除(mod DEL)を後に行うことで、policy は常に
// 1 本以上の SID-list を持ち続け、traffic は流れたまま更新される。
func (p *Programmer) updateInPlace(bsid ip_types.IP6Address, desired []srpolicy.SegmentList) error {
	existing, found, err := p.dumpSegmentLists(bsid)
	if err != nil {
		return err
	}
	if !found {
		p.log.Warn("policy missing during in-place update; reinstalling", "bsid", bsidStr(bsid))
		return p.installPolicy(bsid, desired)
	}

	// 既存と欲しい SID-list を多重集合として突き合わせ、共通部分は触らない。
	var toAdd []srpolicy.SegmentList
	stale := existing
	for _, d := range desired {
		matched := false
		for i, e := range stale {
			if e.matches(d) {
				stale = append(stale[:i], stale[i+1:]...)
				matched = true
				break
			}
		}
		if !matched {
			toAdd = append(toAdd, d)
		}
	}
	for _, sl := range toAdd {
		if err := p.addSegmentList(bsid, sl); err != nil {
			return err
		}
	}
	for _, e := range stale {
		if err := p.delSegmentList(bsid, e.index); err != nil {
			return err
		}
	}
	return nil
}

// slEntry は dataplane 上の 1 SID-list(VPP 内部の sl_index 付き)。
type slEntry struct {
	index  uint32
	weight uint32
	sids   []netip.Addr
}

func (e slEntry) matches(sl srpolicy.SegmentList) bool {
	if e.weight != sl.Weight || len(e.sids) != len(sl.SIDs) {
		return false
	}
	for i := range e.sids {
		if e.sids[i] != sl.SIDs[i] {
			return false
		}
	}
	return true
}

func (p *Programmer) dumpSegmentLists(bsid ip_types.IP6Address) ([]slEntry, bool, error) {
	ctx := p.ch.SendMultiRequest(&sr.SrPoliciesWithSlIndexDump{})
	var out []slEntry
	found := false
	for {
		d := &sr.SrPoliciesWithSlIndexDetails{}
		stop, err := ctx.ReceiveReply(d)
		if err != nil {
			return nil, false, fmt.Errorf("sr_policies_with_sl_index_dump: %w", err)
		}
		if stop {
			break
		}
		if d.Bsid != bsid {
			continue
		}
		found = true
		for _, sl := range d.SidLists {
			e := slEntry{index: sl.SlIndex, weight: sl.Weight}
			for i := 0; i < int(sl.NumSids) && i < len(sl.Sids); i++ {
				e.sids = append(e.sids, netip.AddrFrom16(sl.Sids[i]))
			}
			out = append(out, e)
		}
	}
	return out, found, nil
}

func (p *Programmer) deletePolicy(bsid ip_types.IP6Address) error {
	reply := &sr.SrPolicyDelReply{}
	if err := p.ch.SendRequest(&sr.SrPolicyDel{
		BsidAddr: bsid,
	}).ReceiveReply(reply); err != nil {
		return fmt.Errorf("sr_policy_del bsid=%s: %w", bsidStr(bsid), err)
	}
	if reply.Retval != 0 && reply.Retval != rvPolicyNotFound {
		return fmt.Errorf("sr_policy_del bsid=%s retval=%d", bsidStr(bsid), reply.Retval)
	}
	return nil
}

// steerable は steering を入れるべき policy かを返す。null endpoint(色のみの
// steering, RFC 9256 §8.8)は対象外。IPv4 endpoint への steering は VPP の制約で
// encap policy のみ。
func (p *Programmer) steerable(key srpolicy.PolicyKey) bool {
	if !p.opts.SteerEndpoint || !key.Endpoint.IsValid() || key.Endpoint.IsUnspecified() {
		return false
	}
	if endpointIs4(key.Endpoint) && !p.opts.Encap {
		return false
	}
	return true
}

// steerTo は endpoint 宛の L3 steering を bsid の policy に向ける。
// 既存 entry があれば付け替える(冪等)。
func (p *Programmer) steerTo(key srpolicy.PolicyKey, bsid netip.Addr) error {
	if !p.steerable(key) {
		if p.opts.SteerEndpoint && key.Endpoint.IsValid() && key.Endpoint.IsUnspecified() {
			p.log.Info("null endpoint; skipping automatic steering (color-only policy)",
				"policy", key.String())
		}
		return nil
	}
	rv, err := p.steerReq(false, key.Endpoint, bsid)
	if err != nil {
		return err
	}
	if rv != 0 {
		// 既存の steering entry(旧 BSID 宛や前回起動の残骸)を付け替える。
		if err := p.steerDel(key.Endpoint); err != nil {
			return fmt.Errorf("replace steering endpoint=%s: %w", key.Endpoint, err)
		}
		if rv, err = p.steerReq(false, key.Endpoint, bsid); err != nil {
			return err
		}
		if rv != 0 {
			return fmt.Errorf("sr_steering_add endpoint=%s retval=%d", key.Endpoint, rv)
		}
	}
	return nil
}

func (p *Programmer) steerDel(endpoint netip.Addr) error {
	rv, err := p.steerReq(true, endpoint, netip.Addr{})
	if err != nil {
		return err
	}
	// -4: 対象 steering entry 無し → 冪等扱い
	if rv != 0 && rv != -4 {
		return fmt.Errorf("sr_steering_del endpoint=%s retval=%d", endpoint, rv)
	}
	return nil
}

func (p *Programmer) steerReq(isDel bool, endpoint, bsid netip.Addr) (int32, error) {
	req := &sr.SrSteeringAddDel{
		IsDel:   isDel,
		TableID: p.opts.FIBTable,
	}
	if bsid.IsValid() {
		req.BsidAddr = toIP6(bsid)
	}
	if endpointIs4(endpoint) {
		v4 := endpoint.Unmap().As4()
		req.TrafficType = sr_types.SR_STEER_API_IPV4
		req.Prefix.Address.Af = ip_types.ADDRESS_IP4
		req.Prefix.Address.Un.SetIP4(ip_types.IP4Address(v4))
		req.Prefix.Len = 32
	} else {
		req.TrafficType = sr_types.SR_STEER_API_IPV6
		req.Prefix.Address.Af = ip_types.ADDRESS_IP6
		req.Prefix.Address.Un.SetIP6(toIP6(endpoint))
		req.Prefix.Len = 128
	}
	reply := &sr.SrSteeringAddDelReply{}
	if err := p.ch.SendRequest(req).ReceiveReply(reply); err != nil {
		return 0, fmt.Errorf("sr_steering_add_del: %w", err)
	}
	return reply.Retval, nil
}

func endpointIs4(a netip.Addr) bool { return a.Is4() || a.Is4In6() }

func toIP6(a netip.Addr) ip_types.IP6Address {
	return ip_types.IP6Address(a.As16())
}

func bsidStr(b ip_types.IP6Address) string {
	return netip.AddrFrom16(b).String()
}

// sidList は domain の SegmentList を VPP API の固定長 Srv6SidList に変換する。
// 上限超過は呼び出し前に srpolicy.SegmentList.Valid() で弾かれている前提だが、
// 万一届いた場合も黙って切り詰めず error にする(誤転送防止)。
func sidList(sl srpolicy.SegmentList) (sr.Srv6SidList, error) {
	if len(sl.SIDs) > srpolicy.MaxSIDsPerList {
		return sr.Srv6SidList{}, fmt.Errorf("segment list has %d SIDs, exceeds VPP API limit %d",
			len(sl.SIDs), srpolicy.MaxSIDsPerList)
	}
	out := sr.Srv6SidList{NumSids: uint8(len(sl.SIDs)), Weight: sl.Weight}
	for i, s := range sl.SIDs {
		out.Sids[i] = toIP6(s)
	}
	return out, nil
}
