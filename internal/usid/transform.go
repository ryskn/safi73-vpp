package usid

import "github.com/ryskn/safi73-vpp/internal/srpolicy"

// Compactor は uSID を carrier に詰める制御層の PolicyTransform 実装。
// control.PolicyTransform を(暗黙的に)満たす。
type Compactor struct {
	Block Block
}

// Apply は各 segment list の SID 列を uSID carrier に圧縮した Policy を返す。
// 元の Policy は変更しない。
func (c Compactor) Apply(p srpolicy.Policy) srpolicy.Policy {
	out := p
	out.SegmentLists = make([]srpolicy.SegmentList, len(p.SegmentLists))
	for i, sl := range p.SegmentLists {
		out.SegmentLists[i] = srpolicy.SegmentList{
			Weight: sl.Weight,
			SIDs:   c.Block.Compact(sl.SIDs),
		}
	}
	return out
}
