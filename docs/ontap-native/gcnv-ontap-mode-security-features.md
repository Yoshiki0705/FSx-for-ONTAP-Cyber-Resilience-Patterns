# GCNV ONTAP モードでの WORM / ランサム対策機能の呼び出し / Reaching WORM and Ransomware Controls on GCNV ONTAP-mode

## 概要 / Overview

このリポジトリの SnapLock・Tamperproof Snapshot・ARP の各ドキュメントは、Amazon FSx for NetApp ONTAP を前提にしています。同じ ONTAP ネイティブ機能は、Google Cloud NetApp Volumes (GCNV) の **ONTAP モード** のストレージプールでも利用できます。ただし呼び出し経路と制約が異なります。この文書は、FSx for ONTAP 側の設定内容を繰り返さず、**GCNV 側で同じ機能に到達する経路と、その経路に固有の制約**だけを記録します。機能そのものの設計判断は各 FSx for ONTAP 側ドキュメントを参照してください。

The SnapLock, Tamperproof Snapshot, and ARP documents in this repository assume Amazon FSx for NetApp ONTAP. The same ONTAP-native features are available on Google Cloud NetApp Volumes (GCNV) **ONTAP-mode** storage pools, but the access path and its constraints differ. This document does not repeat the FSx for ONTAP configuration; it records only **how to reach the same features on GCNV and the constraints specific to that path**. For the feature design decisions themselves, see the FSx for ONTAP documents.

> **区分 / Tier**: `documented`. 経路と制約は Google Cloud / NetApp の公開ドキュメントで確認しています（2026-11-04 全文確認）。WORM・不可逆機能を含むため、**このリポジトリでは GCNV 側の実機再現はしていません。** 外部記事（出典）をきっかけに、一次資料で裏取りした内容です。IP・SVM 名・プール名・UID/GID はすべて一般化したプレースホルダで、実値は含みません。
>
> All access paths and constraints are confirmed against Google Cloud / NetApp public documentation (read in full 2026-11-04). Because WORM and irreversible features are involved, **none of this was reproduced on GCNV in this repository.** The content was prompted by an external article and verified against primary sources. Every IP, SVM name, pool name, and UID/GID is a generalized placeholder; no real values are included.

---

## GCNV ONTAP モードの管理経路 / The GCNV ONTAP-mode Management Path

GCNV の ONTAP モードでは、ONTAP 管理 LIF への直接接続（SSH / System Manager）が許可されていません。管理は 2 経路のいずれかで行います [E-029]。

GCNV ONTAP-mode does not allow a direct connection to the ONTAP management LIF (SSH / System Manager). Management goes through one of two paths [E-029].

| 経路 / Path | 用途 / Use | 制約 / Constraint |
|---|---|---|
| `gcloud netapp storage-pools execute` (CLI プロキシ) | 対話不要の単発 ONTAP CLI コマンド / One-shot, non-interactive ONTAP CLI | 1 回に 1 コマンド。対話コマンド不可。許可されたコマンドのみ / One command at a time; no interactive commands; allowlisted commands only |
| Google プロキシ API（ONTAP REST API 呼び出し）/ Google proxy API for ONTAP REST | 自動化、対話コマンドの代替 / Automation; the fallback for interactive commands | `fields=` ではなく `ontap_fields=`。ペイロードは `body: {}` で包む / Use `ontap_fields=`, not `fields=`; wrap payloads in `body: {}` |

GUI（Google Cloud コンソール）と `gcloud` の通常のボリューム操作では、ONTAP モードのボリュームを作成・表示・更新・削除できません [E-030]。ONTAP モードのリソース操作は上記 2 経路に限られます。

Neither the Google Cloud console nor ordinary `gcloud` volume commands can create, view, update, or delete ONTAP-mode volumes [E-030]. Operating ONTAP-mode resources is limited to the two paths above.

---

## 許可されるコマンドは制限されている / The Allowed Command Set Is Restricted

CLI プロキシと REST API の両方で、システムが許可されない ONTAP アクションを遮断します [E-031]。許可されないパラメータやコマンドを送るとエラーになります。セキュリティ機能に関係する範囲では、次が重要です。

Both the CLI proxy and the REST API filter out disallowed ONTAP actions [E-031]. Sending a disallowed parameter or command returns an error. For the security features in scope here, the relevant points are:

- **`cluster peer create` は CLI プロキシでは実行できません。** 対話コマンドのため、REST API を使います [E-032]。外部記事は CLI プロキシ経由の無認証ピア作成例を示していますが、Google の公開ドキュメントは `cluster peer create` を CLI プロキシ非対応とし REST API を案内しています。採用前に現行ドキュメントで確認してください。
- **SnapLock の `event-retention` と `legal-hold` は REST API 専用です。** CLI プロキシでは実行できません [E-033]。`snaplock compliance-clock` と `snaplock log`、および `volume snaplock modify` は CLI プロキシで実行できます。
- **ARP（anti-ransomware）は CLI プロキシで有効化できます。** `security anti-ransomware volume` はフルアクセスで、ボリューム作成時にもパラメータ指定できます [E-034]。
- **QoS は参照のみです。** GCNV の CLI プロキシでは QoS コマンドは read-only で、ceiling / burst の設定はできません [E-035]。この点は FSx for ONTAP（ONTAP 管理面で設定可）と異なります。

- **`cluster peer create` cannot be run through the CLI proxy.** It is interactive, so use the REST API [E-032]. The external article shows an unauthenticated-peer example via the CLI proxy, but Google's public documentation lists `cluster peer create` as not supported by the CLI proxy and directs you to the REST API. Re-check the current documentation before relying on either.
- **SnapLock `event-retention` and `legal-hold` are REST-API only.** They cannot be run through the CLI proxy [E-033]. `snaplock compliance-clock`, `snaplock log`, and `volume snaplock modify` do work through the CLI proxy.
- **ARP (anti-ransomware) can be enabled through the CLI proxy.** `security anti-ransomware volume` has full access, and parameters can also be set at volume creation [E-034].
- **QoS is view-only.** QoS commands are read-only through the GCNV CLI proxy; you cannot set a ceiling or burst [E-035]. This differs from FSx for ONTAP, where it is set on the ONTAP management plane.

---

## WORM 機能の呼び出しに固有の注意 / Cautions Specific to Invoking WORM Features

このリポジトリで最も強いルールは、WORM・不可逆機能をエージェントが自分の判断で有効化しないことです。**GCNV でも同じです。** GCNV の経路に固有の、追加の注意点を記録します。機能そのものの危険性（Compliance は保持期間満了まで誰も削除できない [E-036]、など）は [SnapLock Configuration](snaplock-configuration.md) と [Tamperproof Snapshot](tamperproof-snapshot.md) にあり、ここでは繰り返しません。

The strongest rule in this repository is that an agent does not enable WORM or irreversible features on its own judgement. **The same holds on GCNV.** Recorded here are only the additional cautions specific to the GCNV path. The danger of the features themselves (Compliance cannot be deleted by anyone until retention expires [E-036], and so on) lives in the SnapLock and Tamperproof documents and is not repeated.

- **CLI プロキシのパーサーは時間単位の短縮形を拒否します。** `min` のような短縮形は `unable to parse command` になり得るため、保持期間は `minutes` / `hours` / `days` / `months` / `years` と完全形で指定します <!-- allow:unverified: 外部記事の実機観察。Google/NetApp の公開文書に短縮形拒否の明記を確認できていない -->（外部記事の観察。採用前に現行の挙動を確認）。短縮形が弾かれること自体は無害ですが、**完全形で桁を一つ書き間違えると、意図より長い保持期間が不可逆に設定されます。**
- **プール・ボリュームの削除可否は WORM に縛られます。** GCNV でも、ロック中のファイルが残るボリュームはオフライン化・削除が拒否され、そのボリュームを含むストレージプールの削除もできません。Compliance では保持期間満了まで、管理者権限でも不可能です [E-036]。検証は最短の保持期間で、Enterprise を使います。
- **保持期間とロック期限は、作成後に変更・短縮・延長できません。** 新規作成時にのみ指定できます [E-037]。これは ONTAP の仕様で、GCNV・FSx for ONTAP に共通です。

- **The CLI proxy parser rejects abbreviated time units.** A shorthand such as `min` can return `unable to parse command`, so specify retention in full as `minutes` / `hours` / `days` / `months` / `years` <!-- allow:unverified: hands-on observation from the external article; the parser's rejection of shorthand is not stated in a Google/NetApp public document I could confirm -->(observed in the external article; confirm current behavior before relying on it). The rejection itself is harmless, but **a single mistyped digit in the full form sets a longer retention than intended, irreversibly.**
- **Pool and volume deletion are bound by WORM.** On GCNV too, a volume holding locked files refuses offline and delete, and the storage pool containing it cannot be deleted either. Under Compliance this holds until retention expires, even with administrator privilege [E-036]. Verify with the shortest retention, using Enterprise.
- **Retention periods and lock expiry cannot be changed, shortened, or extended after creation.** They can be set only at creation [E-037]. This is an ONTAP property, shared by GCNV and FSx for ONTAP.

---

## 参照 / References

一次資料を主たる根拠とし、外部記事はきっかけ（第三者の実機記録）として併記します。

Primary sources are the grounds; the external articles are listed as the third-party origin that prompted this.

### 一次資料 / Primary sources

- [Google Cloud: Manage ONTAP in ONTAP-mode](https://docs.cloud.google.com/netapp/volumes/docs/ontap/manage-ontap) — 直接接続不可、CLI プロキシと REST API、許可されるコマンド一覧（`cluster peer create` 非対応、SnapLock `event-retention`/`legal-hold` は REST 専用、ARP フルアクセス、QoS 参照のみ）/ No direct connection, the CLI proxy and REST API, and the allowed-command table
- [Google Cloud: FlexCache overview (ONTAP-mode)](https://docs.cloud.google.com/netapp/volumes/docs/configure-and-use/volumes/cache-ontap-volumes/overview) — ONTAP モードのボリュームはコンソール・`gcloud` で操作不可 [E-030]、write-around / write-back の挙動 / ONTAP-mode volumes cannot be operated via console or `gcloud` [E-030]; write behavior
- [NetApp: ONTAP FlexCache write-back overview](https://docs.netapp.com/us-en/ontap/flexcache-writeback/flexcache-write-back-overview.html) — write-back は ONTAP 9.15.1 以降 / write-back is 9.15.1 and later
- [FSx for ONTAP: Replicating your data with FlexCache](https://docs.aws.amazon.com/fsx/latest/ONTAPGuide/using-flexcache.html) — FSx for ONTAP 側の FlexCache / the FSx for ONTAP side

### このリポジトリの FSx for ONTAP 側ドキュメント / FSx for ONTAP documents in this repository

- [SnapLock Configuration](snaplock-configuration.md)
- [Tamperproof Snapshot](tamperproof-snapshot.md)
- [ARP Configuration](arp-configuration.md)

### 第三者記事（きっかけ）/ Third-party articles (origin)

- GCNV ONTAP モードでの Volume / SnapLock / Tamperproof Snapshot / ARP / FlexCache 操作に関する Qiita 連載（投稿者ハンドル: lewip）。実機操作の記録であり、本書の主張は上記一次資料で裏取りしています / A Qiita series on GCNV ONTAP-mode operations (author handle: lewip). A record of hands-on operations; the claims in this document are verified against the primary sources above.
  - <https://qiita.com/lewip/items/0f8b9155ed4c6e301256>
  - <https://qiita.com/lewip/items/8a6c6f2a69e32d40098e>
  - <https://qiita.com/lewip/items/cf068ffd11c1989464fb>
  - <https://qiita.com/lewip/items/04146dfc1cb622b2ddd2>
