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
		t := srpolicy.SegmentList{
			Weight:      sl.Weight,
			SIDs:        c.Block.Compact(sl.SIDs),
			Unsupported: sl.Unsupported, // 妥当性判定は圧縮後に行われるため必ず引き継ぐ
		}
		// 圧縮で SID と mask bit の対応が崩れるため、verification 要求があった list は
		// 先頭 SID (carrier) の検証要求に落とす。first SID は §5.1 で常に検証対象なので
		// 意味は保存される。
		if sl.VerifyMask != 0 {
			t.VerifyMask = 1
		}
		out.SegmentLists[i] = t
	}
	return out
}
