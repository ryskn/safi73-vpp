package usid

import "github.com/ryskn/safi73-vpp/internal/srpolicy"

// Compactor は uSID を carrier に詰める制御層の PolicyTransform 実装。
// control.PolicyTransform を(暗黙的に)満たす。
type Compactor struct {
	Block Block
}

// Apply は各 segment list の SID 列を uSID carrier に圧縮した CandidatePath を返す。
// 元の値は変更しない。
func (c Compactor) Apply(cp srpolicy.CandidatePath) srpolicy.CandidatePath {
	out := cp
	out.SegmentLists = make([]srpolicy.SegmentList, len(cp.SegmentLists))
	for i, sl := range cp.SegmentLists {
		out.SegmentLists[i] = srpolicy.SegmentList{
			Weight: sl.Weight,
			SIDs:   c.Block.Compact(sl.SIDs),
		}
	}
	return out
}
