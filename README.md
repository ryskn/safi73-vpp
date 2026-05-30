# safi73-vpp

gobgpd が広告する **BGP SR Policy (SAFI 73)** を購読し、[govpp](https://github.com/FDio/govpp) 経由で
**VPP の SRv6 SR Policy** として投入/削除する PoC。

- control-plane: gobgpd (gRPC `WatchEvent`)
- data-plane: VPP 26.02 (`sr_policy_add` / `sr_policy_mod` / `sr_policy_del`)

```
gobgpd ──gRPC WatchEvent──▶ safi73-vppd ──govpp──▶ VPP /run/vpp/api.sock
            (SAFI73 best-path)   │
                                 │ decode  : SRPolicyNLRI(color/endpoint) + TunnelEncap(BSID/segment-list)
                                 │ reconcile
                                 └ program : SrPolicyAdd(先頭SL) + SrPolicyMod ADD(追加SL) / withdraw→SrPolicyDel
```

## 設計 (SOLID)

レイヤを「ドメイン / 制御 / adapter」に分け、依存はすべて内側(ドメイン)へ向かう。
`Reconciler` は gobgp/VPP の具象を知らず、抽象だけに依存する (依存性逆転)。

```
  レイヤと依存方向 (上 → 下へ依存)

    cmd/safi73-vppd        composition root。具象を生成し Reconciler に注入する
          │ inject
          ▼
    control.Reconciler     反映ロジック。Source / Programmer / Store の抽象だけに依存
          │ uses
          ▼
    internal/srpolicy      ドメイン (Policy / SegmentList / Event)。依存ゼロ


  抽象 (control が定義)    ←─  実装 (adapter は control を import せず暗黙的に満たす)

    control.Source          ←─  adapter/bgp.Source       gobgpd gRPC WatchEvent を購読
    control.Programmer      ←─  adapter/vpp.Programmer    govpp で sr_policy_add/mod/del
    control.Store           ←─  control.MemStore          投入済み Policy をインメモリ追跡
    control.PolicyTransform ←─  usid.Compactor            uSID を carrier に圧縮 (任意/OCP)


  データの流れ (runtime)

    gobgpd ─▶ adapter/bgp.Source ─▶ control.Reconciler ─▶ adapter/vpp.Programmer ─▶ VPP
                                         │ (任意) PolicyTransform: usid.Compactor
```

| 原則 | 反映箇所 |
|------|----------|
| **S** 単一責任 | `srpolicy`(モデル) / `control`(制御) / `adapter/bgp`(購読・デコード) / `adapter/vpp`(投入) / `MemStore`(状態) を分離 |
| **O** 開放閉鎖 | 投入前に `PolicyTransform` を差し込める。例: `usid.Compactor` で uSID 圧縮を `Reconciler` 無変更で追加。供給源・投入先・状態ストアも差し替え可能 |
| **L** リスコフ | `Source`/`Programmer`/`Store` のどの実装でも `Reconciler` は同じ契約で動く(fake で代替してテスト) |
| **I** インターフェース分離 | `Programmer` は `Add`/`Remove` のみ等、利用側が必要とする最小の口だけを定義 |
| **D** 依存性逆転 | `Reconciler` は具象(gobgp/VPP)を知らず抽象のみに依存。結線は composition root に集約 |

抽象(`Source`/`Programmer`/`Store`)は利用側 `control` パッケージが定義し、adapter 側が暗黙的に満たす
(Go 的な DIP)。adapter は `srpolicy` ドメインにのみ依存し、`control` を import しない。

## レイアウト

```
internal/srpolicy/        ドメイン層 (gobgp/VPP 非依存)
  policy.go               Policy / SegmentList / Key / ValidateSRv6
  event.go                Event (追加/withdraw)
internal/control/         制御層 (抽象のみに依存)
  ports.go                Source / Programmer / Store / PolicyTransform インターフェース
  reconciler.go           Reconciler: イベント→(変換)→データプレーン反映 (更新は冪等)
  memstore.go             MemStore: Store のインメモリ実装
internal/usid/            uSID (micro-SID) サポート
  usid.go                 Block: uSID を 128bit carrier に圧縮する純ロジック
  transform.go            Compactor: control.PolicyTransform 実装
internal/adapter/bgp/     control.Source 実装
  source.go               gobgpd gRPC WatchEvent 購読 + SAFI73 選別
  decode.go               api.Path → srpolicy.Event
internal/adapter/vpp/     control.Programmer 実装
  conn.go                 govpp 接続/channel
  programmer.go           SrPolicyAdd / SrPolicyMod / SrPolicyDel
cmd/safi73-vppd/          本体 daemon (composition root)
cmd/inject-srpolicy/      テスト用 SR Policy 注入/withdraw クライアント
cmd/smoke/                govpp↔VPP 疎通確認
binapi/                   VPP 26.02 の /usr/share/vpp/api から生成した govpp バインディング
```

## マッピング

| BGP SR Policy | VPP |
|---|---|
| NLRI (distinguisher, color, endpoint) | 状態追跡キー (withdraw 用) |
| Tunnel Encap / Binding SID sub-TLV | `bsid_addr` (SR Policy のキー) |
| Segment List sub-TLV (SegmentTypeB = SRv6 SID) | `Srv6SidList` |
| 2 本目以降の Segment List | `sr_policy_mod` operation=ADD |
| withdraw | `sr_policy_del` (BSID 指定) |

SegmentTypeA (SR-MPLS label) は対象外 (SRv6 dataplane のみ)。BSID が無い/IPv6 でない経路は skip。

## uSID (micro-SID)

`-usid-block <prefix>` を指定すると、BGP で受けた segment list 中の per-node uSID
(block 配下の単一 uSID アドレス) を 128bit の uSID carrier に圧縮してから VPP に投入する。

```sh
safi73-vppd -usid-block fcbb:bb00::/32 -usid-len 16   # block /32 + 16bit uSID → 1 carrier に最大 6 個
```

例: BGP segment list `[fcbb:bb00:1::, fcbb:bb00:2::, fcbb:bb00:3::]`
→ 圧縮 → VPP の SID リストは `[fcbb:bb00:1:2:3::]` (1 carrier)。単一 carrier なので
VPP は **SRH 無し (reduced encap)** で carrier を outer DA に載せる。中継ノードは
`sr localsid prefix fcbb:bb00:1::/48 behavior un 16` (uN) で先頭 uSID を pop し、
DA を `fcbb:bb00:2:3::` にシフトして転送する。

圧縮ロジックは `internal/usid` の純関数 (byte 境界の block/uSID 長に対応、単体テスト済み)。
それを `control.PolicyTransform` として composition root で注入するだけで、圧縮無効時 (既定) の
挙動は一切変わらない (OCP)。実機で headend 圧縮 → reduced encap → uN シフトまで確認済み。

## ビルド / テスト

```sh
go build ./...
go test  ./...   # control / srpolicy は VPP・gobgp 無しで検証可能 (DIP の成果)
```

`binapi/` は生成物。VPP バージョンを変えたら再生成する:

```sh
binapi-generator --input=/usr/share/vpp/api --output-dir=./binapi \
  --import-prefix=github.com/ryskn/safi73-vpp/binapi \
  memclnt vpe interface interface_types ip ip_types sr sr_types
```

## 動作確認 — 自己完結 eBGP ラボ (外部 peer 不要)

1 ホスト上で gobgpd を 2 台立て、loopback 越し eBGP を張る。A=本体が watch する側、B=SR Policy 広告役。

| | AS | listen | gRPC | role |
|---|---|---|---|---|
| A (`gobgpd-a.toml`) | 64514 | 127.0.0.1:179 | :50051 | safi73-vppd が watch |
| B (`gobgpd-b.toml`) | 64515 | 127.0.0.2:179 | :50052 | SR Policy 広告役 |

```sh
# 1. gobgpd 2 台 (179 バインドは要 root)
sudo gobgpd -f gobgpd-a.toml &
sudo gobgpd -f gobgpd-b.toml --api-hosts 127.0.0.1:50052 &
gobgp neighbor                       # 127.0.0.2 ... Establ

# 2. connector
sudo ./safi73-vppd &                 # /run/vpp/api.sock へ

# 3. B に SR Policy を入れる → eBGP で A へ → VPP
go run ./cmd/inject-srpolicy --gobgp 127.0.0.1:50052 \
  --color 100 --bsid 2001:db8:b::1 --segments 2001:db8:cafe::1,2001:db8:cafe::2
gobgp neighbor 127.0.0.2             # Received: 1 / Accepted: 1
sudo vppctl show sr policies         # BSID 2001:db8:b::1 が出る

# 4. withdraw
go run ./cmd/inject-srpolicy --gobgp 127.0.0.1:50052 \
  --color 100 --bsid 2001:db8:b::1 --segments 2001:db8:cafe::1 --withdraw
sudo vppctl show sr policies         # 空

# 後片付け
sudo pkill -f gobgpd ; sudo pkill -f safi73-vppd
```

## 本番接続 (実 peer)

gobgpd の設定に neighbor を追加し `afi-safi-name = "ipv6-srpolicy"` を有効化、

```sh
sudo ./safi73-vppd -gobgp <gobgpd:50051> -vpp /run/vpp/api.sock -encap -fib 0
```

flags: `-gobgp` / `-vpp` / `-encap`(T.Encaps, 既定 true) / `-fib`(FIB table)。

## 動作環境

Ubuntu 24.04 / Go 1.26 / VPP 26.02 (fd.io apt) / gobgp v4.5 で確認。
