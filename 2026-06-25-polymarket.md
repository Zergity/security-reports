# Polymarket Frontend Supply-Chain Hack — June 2026

**Report date:** 2026-06-30
**Last updated:** 2026-07-01
**Incident date:** 2026-06-25
**Target:** Polymarket (decentralized prediction market)
**Loss:** ~$3.1M (initially reported ~$2.9M, revised within days)
**Category:** Frontend / software supply-chain attack (not a smart-contract exploit)
**Status:** Contained; full reimbursement pledged by Polymarket. Bulk of proceeds (~1,788 ETH) traced and still sitting in an attacker EOA as of 2026-07-01.

> Scope note: This is an internal reference report for security analysis. The fund flow (§4), the drain transactions (§4.7), and the attack mechanism (§3.3) were independently verified against on-chain data (2026-07-01); those findings are first-hand. Off-chain context (vendor identity, script IoCs) remains as-reported and is flagged where unconfirmed.

---

## 1. Executive summary

On 2026-06-25, attackers drained approximately $3.1 million in pUSD (Polymarket's USDC-backed settlement token) from 11 user wallets. The attack was not a smart-contract vulnerability in Polymarket's on-chain protocol. Instead, a third-party vendor that supplies front-end code to the Polymarket website was compromised, and the attacker injected a malicious JavaScript payload into the page served to a subset of users.

When affected users loaded the site, the injected script prompted them to sign a Polymarket proxy-wallet execution authorization that appeared routine. On-chain (§3.3), the attacker then relayed that signature through a drainer contract (`0x000000…cc07`), causing each victim's Polymarket proxy wallet to transfer its own pUSD to attacker collectors. This abuses Polymarket's account-abstraction flow rather than a standard `approve`/`permit` allowance. The stolen pUSD was swapped to ETH (1,892.92 ETH, verified on-chain) and bridged from Polygon to Ethereum, then consolidated into `0xe65b1C…E1eD`. Initial press reporting said the funds "had not moved," but on-chain data shows the attacker moved everything off the consolidation address the next day (2026-06-26); the bulk, 1,788.52 ETH, now sits in a fresh EOA `0x9752…8ac0` (see §4).

The incident reflects the dominant 2026 attack trend: the security boundary failed at the intersection of systems, people, and permissions rather than in audited contract code.

---

## 2. Timeline (as reported)

| Date (2026) | Event |
|---|---|
| (prior, ~6 yrs) | Unrelated context: a separate **May 22, 2026** incident drained ~$520K–$700K from internal payout wallets via an exposed private key that had been active for ~6 years (user funds unaffected in that case). |
| Jun 25 | Frontend supply-chain attack executed; malicious script served to a subset of users; 11 wallets drained of pUSD. |
| Jun 25 12:28–13:28 UTC | **(on-chain)** Proceeds bridged to Ethereum and consolidated into `0xe65b1C…E1eD` — 6 inbound transfers totaling **1,892.92 ETH**. |
| Jun 25 (post-disclosure) | Polymarket states it **contained** the incident, **removed the affected vendor dependency**, and publicly **pledged full refunds** to affected pUSD holders. |
| Jun 25 21:55 – Jun 26 20:49 UTC | **(on-chain)** Attacker **empties the consolidation address** in 4 outbound txs; final large move of **1,788.52 ETH** to EOA `0x9752…8ac0`. This directly contradicts press reports (~Jun 27) that funds were "stationary." |
| ~Jun 27 | Loss estimate **revised upward** from ~$2.9M to ~$3.1M (CoinDesk). |
| (concurrent) | Polymarket reported to be facing a **CFTC probe** (separate regulatory matter, per PYMNTS). |
| Jul 01 (verification) | **(on-chain)** Consolidation address holds only ~0.0005 ETH dust; **1,788.52 ETH still unmoved** in `0x9752…8ac0` (an EOA, no contract code). |

---

## 3. Attack vector & root cause

### 3.1 Attack chain
1. **Vendor compromise** — Attackers breached a third-party vendor that supplies front-end code/dependencies to Polymarket. *(The specific vendor was not publicly disclosed in the cited sources.)*
2. **Code injection** — A rogue script was inserted into the front-end dependency.
3. **Delivery** — The compromised code was served to legitimate Polymarket users through the normal website load path (affecting only a subset of users).
4. **Exploitation** — In the victim's browser, the script prompted **unintended signatures**. On-chain (§3.3, confirmed), these were **Polymarket proxy-wallet execution authorizations**: each victim signed a message that let their Polymarket proxy wallet execute a transaction, which the attacker relayed to make the proxy `transfer` its pUSD to an attacker-controlled collector.

### 3.2 Why it worked
- The malicious prompts looked like routine signing requests, so they bypassed user suspicion.
- In a dApp front end, whatever code reaches the browser is implicitly trusted by the wallet flow, so a compromised dependency inherits the site's trust.
- The on-chain contracts were never the weak point. The off-chain delivery pipeline was.

### 3.3 Signing primitive — CONFIRMED on-chain
On-chain, the Polygon drain transactions (see §4.7) show the mechanism is **not** a standard ERC-20 `approve`/`permit` drainer — it is **abuse of Polymarket's proxy-wallet (account-abstraction) signed-execution flow**. Every drain has the identical call tree:

```
attacker EOA (rotating, e.g. 0xde9e08b9…, 0x4c917200…)
  → CALL attacker drainer contract 0x00000000000fb5c9adea0298d729a0cb3823cc07  [sel 0x0a3c4405]
     → DELEGATECALL impl 0xb6f9c7e6…
        → CALL victim's Polymarket proxy wallet (e.g. 0xb61b2079…)              [sel 0xe8c8bf64 = proxy exec]
           → DELEGATECALL Polymarket proxy impl 0x58ca52eb…
              → STATICCALL (validate the victim's signed authorization)
              → CALL pUSD 0xC011a7E1… transfer(collector, amount)              [sel 0xa9059cbb]
```

Interpretation: the malicious frontend tricked each victim into signing an EIP-712 Polymarket proxy-execution authorization, which renders as a routine Polymarket action rather than an obvious token transfer. The attacker relayed that signature through their own drainer contract, causing the victim's proxy wallet to transfer its pUSD to an attacker collector. The use of `transfer` (`0xa9059cbb`) rather than `transferFrom` confirms the proxy moved its own balance under signed authority; there is no ERC-20 allowance in the path. This is why the drains were invisible to a naive transfer-scan (they resemble ordinary Polymarket relayer activity) and why the prompts looked routine.

Confirmed across multiple drains with different victims and different (rotating) attacker executor EOAs, same drainer contract `0x000000…cc07`.

### 3.4 Still unconfirmed
- **Vendor identity & breach method:** Not disclosed by Polymarket, Halborn, or Rescana. **(Unknown.)**
- **Script IoCs (URL / domain / hash) & the vendor:** still undisclosed off-chain. *(The signed EIP-712 payload itself is no longer unknown — it was recovered on-chain; see §3.5.)*

### 3.5 The signed payload (recovered on-chain)
Worked example — the largest drain, tx `0x2ca925546092ed6e121e3ed8aec26b98b3c176a4bb3c1e2bf76caa1a21a2b0cc`. Reconstructed first-hand from on-chain data only (no off-chain data).

**Verifying function** (proxy impl `DepositWallet` `0x58ca52eb…`, a verified contract, selector `0xe8c8bf64`):
```solidity
execute(
  (address wallet, uint256 nonce, uint256 deadline, (address target,uint256 value,bytes data)[] calls),
  bytes signature
)
```

**Signed struct values** (as carried in the `execute` calldata):
```
wallet   = 0xb61b2079…308a06                 // the victim's own DepositWallet proxy
nonce    = 3
deadline = 0x6a3d1f8b  (≈ 2026-06-25 12:31 UTC — short ~30-min expiry)
calls    = [ { target: 0xC011a7E12a19f7B1f670d46F03B03f3342E82DFB (pUSD),
              value : 0,
              data  : a9059cbb → transfer(0xe42640650c…d2222 (collector), 1,094,606.66 pUSD) } ]
signature = r=0x973f74a4…20f49c  s=0x7b85720d…dd85db  v=27
```

**Signed digest + signer** (from the `ecrecover` precompile `STATICCALL → 0x00…01`; input = `digest‖v‖r‖s`, output = signer):
```
EIP-712 digest   = 0x582080cc02b09598edec4c4d85a48253f1ad37dfad734bc5246e0f8f9149724b
recovered signer = 0x3a4bb1ec6a1f281a834709cd92c3c27de2690b0c   // victim's controlling EOA (owner of proxy 0xb61b2079…)
```
The canonical `EIP712Domain` typehash `0x8b73c3c6…400f` is embedded as a constant in the impl contract, confirming the scheme.

**Takeaway:** the victim signed a `DepositWallet.execute` batch whose sole call was `pUSD.transfer(attacker, amount)`. A single such signature is an arbitrary-call blank check — see the proxy-wallet-designer recommendation in §7.

### 3.6 What the victim saw (MetaMask)
The signature was requested via **`eth_signTypedData_v4`** (nested `Call[]` array → requires v4). The reconstructed typed data below hashes to exactly the on-chain digest `0x582080cc…`, so this is precisely what was signed.

**Exact typed data:**
```json
{
  "types": {
    "EIP712Domain": [
      {"name":"name","type":"string"},{"name":"version","type":"string"},
      {"name":"chainId","type":"uint256"},{"name":"verifyingContract","type":"address"}
    ],
    "Batch": [
      {"name":"wallet","type":"address"},{"name":"nonce","type":"uint256"},
      {"name":"deadline","type":"uint256"},{"name":"calls","type":"Call[]"}
    ],
    "Call": [
      {"name":"target","type":"address"},{"name":"value","type":"uint256"},{"name":"data","type":"bytes"}
    ]
  },
  "primaryType": "Batch",
  "domain": { "name":"DepositWallet", "version":"1", "chainId":137,
              "verifyingContract":"0xb61b2079b95f6b7476fd3203e0274ffb93308a06" },
  "message": {
    "wallet":"0xb61b2079b95f6b7476fd3203e0274ffb93308a06",
    "nonce":"3",
    "deadline":"1782390667",
    "calls":[ { "target":"0xC011a7E12a19f7B1f670d46F03B03f3342E82DFB",
                "value":"0",
                "data":"0xa9059cbb000000000000000000000000e42640650c634ad300a47635856aafbbba1d2222000000000000000000000000000000000000000000000000000000fedba41921" } ]
  }
}
```

**Approximate MetaMask render:**
```
┌─────────────────────────────────────────────┐
│  Signature request                          │
│  https://polymarket.com          [legit ✓]  │  ← ran on the real site
│  Account: 0x3a4b…0b0c   Network: Polygon    │
├─────────────────────────────────────────────┤
│  Message                                    │
│   wallet:    0xb61b2079…308a06              │
│   nonce:     3                              │
│   deadline:  1782390667                     │
│   calls:                                    │
│     0:                                      │
│       target: 0xC011a7E1…E82DFB  (pUSD)     │  ← just "some contract"
│       value:  0                             │  ← looks harmless (no MATIC)
│       data:   0xa9059cbb0000…fedba41921     │  ← OPAQUE HEX — not decoded
│                                             │
│           [ Reject ]           [ Sign ]     │
└─────────────────────────────────────────────┘
```

**Why it evaded suspicion:**
- The malicious action is buried in `calls[0].data` as **raw hex**; MetaMask does not decode nested calldata inside an EIP-712 `bytes` field, so the user never sees "transfer 1,094,606.66 pUSD to `0xe4264065…`". (`0xa9059cbb` = `transfer`; arg2 `0xfedba41921` = 1,094,606.66 with 6 decimals.)
- Everything visible looks benign: `value: 0` (no native token leaving), `target` is just an address, and the domain is the genuine `DepositWallet` v1 on chainId 137 with the user's **own proxy** as `verifyingContract`.
- **No Blockaid/scam flag:** site, contract, and signature *type* are all legitimate — the harm lives entirely in the undecoded inner payload, which typed-data signing does not simulate. (A plain `approve`/`permit` *would* be decoded and warned on; this custom-batch pattern slips past.)
- Short `deadline` (~30 min) kept the order fresh and unremarkable.

**Defense that catches it:** a wallet that **simulates the signed exec** or **decodes nested `Call.data`** would surface "this signature lets 1.09M pUSD leave your wallet." See §7.

### 3.7 Supply-chain vector — what public site captures show
The injected script could not be recovered from public captures of `polymarket.com` (checked 2026-07-01). What those captures show:
- **Captures examined:** 2026-06-23 06:24 UTC (pre-incident, `019ef325…`), 2026-06-25 08:05 UTC (during the drain window 05:51–13:22, `019efdcf…`), 2026-06-25 20:06 UTC (post-containment, `019f0063…`).
- The **08:05 during-window DOM contained none** of the attacker indicators (collector addresses, `signTypedData`, `DepositWallet`, in-page `eval`/`atob`). The capture, taken without a connected wallet, was **not served the drainer payload**.
- The only obfuscated off-domain script, `s3-us-west-2.amazonaws.com/jsstore/a/020HDQYO/ge.js` (100 KB, hex-obfuscated, ~50 `atob()` calls), **decodes to an Ensighten tag manager + ad-tech/fingerprinting stack** — endpoints `a.usbrowserspeed.com`, `alocdn.com/…/xtarget`, `pro.ip-api.com/json` (geolocation), `…execute-api.us-west-2.amazonaws.com/tm`. It was **already present pre-incident (Jun 23)** and contains **no wallet/drainer indicators → ruled out** as the malicious script.
- **Result:** the malicious drainer script was **not recoverable from public captures** — the injection was evidently gated to real wallet sessions (which automated captures, lacking a wallet, do not trigger). The compromised vendor and script IoCs (URL / hash) remain **unidentified** (see §3.4). Recovering them would require a real wallet-session capture (a victim's browser, or a client-side monitoring vendor) or Polymarket's own post-mortem.

---

## 4. On-chain fund flow (independently verified)

> **Scope:** All figures below were reconstructed first-hand from on-chain data on Ethereum and Polygon, checked **2026-07-01**. The attacker consolidation address was first attributed by sleuths **Specter** / **AMLBot**; the Polygon collectors, victim proxies, drain txs, and call trees below are our own reconstruction.

- **Asset stolen:** pUSD (Polymarket's USDC-backed token). **Source chain:** Polygon.
- **Peg stability:** the **pUSD peg held steady** throughout — the breach did not destabilize the stablecoin.

### 4.1 Attacker consolidation address
`0xe65b1C586757c5510B60F998Eebb14C1eF71E1eD` (Ethereum). Nonce 4, current balance **~0.0005 ETH** (emptied). Polygon nonce 0 → this address is **Ethereum-only, entirely post-bridge**.

### 4.2 Inbound — consolidation (2026-06-25, all UTC) — total **1,892.92 ETH**
| Time | Amount (ETH) | From (attacker staging wallet) |
|---|---|---|
| 12:28 | 325.4 | `0xc771a30a7c1aca828eeef7b822ac864a64cbaae2` |
| 12:29 | 272.0 | `0x51cf782223289c05568f9f7dede8cb1bc2f9c5ca` |
| 12:30 | 210.0 | `0x10366adbb5c4101a65c840da6639546179c5a107` |
| 12:31 | 114.0 | `0xc44f2ca6b30a54d17a62cef8fadaf2e8c8632ec4` |
| 12:32 | 832.8 | `0xe42640650c634ad300a47635856aafbbba1d2222` |
| 13:28 | 138.72 | `0x2eb06b8d81c6f26d9cb26327878999ac7db3891b` |

### 4.3 Outbound — dispersal (total **1,892.92 ETH** — the address was fully drained)
| Time (UTC) | Amount (ETH) | To |
|---|---|---|
| 06-25 21:55 | 3.4 | `0xe3c8c6cfcf…` |
| 06-25 22:19 | 1.0 | `0x5a6b2f8fab…` |
| 06-26 07:08 | 100.0 | `0xea0a80070c…` |
| **06-26 20:49** | **1,788.52** | **`0x975268a2a71e4a7e282b962ec0b1ee01d3778ac0`** |

Key tx (the 1,788.52 ETH move): `0x62781171eef8748b967d3926c82f5c73cbf2cb40a189443347ad9f276966b086`

### 4.4 Current location of funds (2026-07-01)
The bulk — **1,788.52 ETH** — sits **untouched** in EOA `0x975268a2a71e4a7e282b962ec0b1ee01d3778ac0` (verified balance = 1788.516 ETH; no contract code). Moved there 2026-06-26 and static since. **This corrects the press narrative:** the funds were *not* "stationary at the attacker address" — they were relocated to this new EOA the day after the hack.

### 4.5 Attacker cluster & tradecraft (verified)
- **Vanity-address cluster:** the funding/staging/hop addresses systematically match the pattern `0xe65b…1ed` (e.g. `0xe65b773c…e1ed`, `0xe65bf633…be1ed`, `0xe65be75e…f11ed`, `0xe65b2b27e4…`, `0xe650fb359e…`) — same fingerprint as the consolidation address. Indicates a **deliberate, well-resourced actor** (vanity generation is compute-intensive).
- **`0x1210768ac1278049e2f1875e994a443f492aca77` — NOT attacker-controlled (correction).** It touched the staging wallets, but on Polygon it blasts **0-value transfers to hundreds of addresses** (e.g. ~40 in one minute on 2026-06-17). That is **address-poisoning spam**, i.e. a shared spammer/bot that also sprayed the attacker's wallets — not a cross-chain ops wallet. Do not treat as attacker infrastructure.
- **Tracer-confusion / address-poisoning:** cluster addresses shuffle **fake ERC-20 tokens named "ETH"** using Unicode homoglyphs (`E឵Τ឵H`, `ĖTḨ`) in amounts mirroring the real ETH flow — designed to pollute on-chain history views and automated tracers.
- **Not the attacker (avoids a misattribution):** `0xf70da97812cb96acdf810712aa562db8dfa3dbef` appears as an ETH source to a staging wallet but has **~2.9M Polygon txs** and Ethereum history predating the hack → it is **infrastructure (DEX/bridge/relayer service)**, i.e. the swap/bridge venue, not an attacker hop.

### 4.6 The Polygon collectors = the Ethereum staging wallets (cross-chain reuse)
The six "staging wallets" from §4.2 are **the same EOAs that acted as pUSD collectors on Polygon** — a decisive cross-chain reuse fingerprint. On Polygon each one: (1) received the drained pUSD from victim proxies, (2) swapped pUSD → USDC.e ~1:1, then the USDC.e was routed cross-chain and (3) the same address received ETH on Ethereum and forwarded it to the consolidation `0xe65b1C…`.

| Collector / staging EOA | pUSD collected | → USDC.e | → ETH to consolidation |
|---|---|---|---|
| `0xe42640650c…d2222` | 1,368,413 | 1,367,729 | 832.8 |
| `0xc771a30a7c…baae2` | 538,064 | 537,526 | 325.4 |
| `0x51cf782223…9c5ca` | 448,780 | 446,092 | 272.0 |
| `0x10366adbb5…5a107` | 343,998 | 343,654 | 210.0 |
| `0x2eb06b8d81…3891b` | 227,000 | — | 138.72 |
| `0xc44f2ca6b3…32ec4` | 186,492 | — | 114.0 |
| **Total** | **≈3,112,747 pUSD** | | **≈1,892.9 ETH** |

The ETH cash-out was laundered through `0xf70da978…`, a **high-throughput swap/MM aggregator** (millions/min for unrelated users; trades with `0x7777…00ee`, `0x4cd00e38…`, `0xb92fe925…`; USDC minted/burned via Circle CCTP) — which is why *forward* tracing from Polygon commingles, but the collector reuse links the two chains directly.

### 4.7 The drain transactions
**17 drain transfers, 13 distinct victim proxy wallets, total 3,112,747 pUSD (≈ the reported $3.1M), 2026-06-25 05:51–13:22 UTC.** Selected/largest below; the mechanism (proxy-exec → `transfer`) is confirmed in §3.3.

| Time (UTC) | pUSD | Victim proxy | Collector | Drain tx |
|---|---|---|---|---|
| 12:00 | 1,094,607 | `0xb61b2079…` | `0xe4264065…` | `0x2ca925546092ed6e121e3ed8aec26b98b3c176a4bb3c1e2bf76caa1a21a2b0cc` |
| 10:30 | 508,518 | `0x987b441a…` | `0xc771a30a…` | `0x51e0666c649c2ddf143238c4093e1bd2f9b50aa848f58a301b08f90308dec61d` |
| 05:51 | 446,539 | `0xd88139ef…` | `0x51cf7822…` | `0x4638bbda80f4879ae661d07d13d0351c94f2016ab40c38b85963c23933b3ad9f` |
| 11:19 | 268,117 | `0x2d7be517…` | `0x10366adb…` | `0x690c2fc16037ed7b9565cf33ed3619946e4e38cca92807ff433fbd7c21400f18` |
| 12:06 | 143,033 | `0x79ae0972…` | `0xe4264065…` | `0x2ffe3161b82692f4237c963a6527fa5774a446deaba60f18514f13e97be561b0` |
| 11:21 | 149,932 | `0x08a30a0a…` | `0xc44f2ca6…` | `0x7b735393ce96a9f9c90f3719492061a2db28fe8abbe38951fa8794adfc45b76e` |
| … | | 13 victim proxies total | 6 collectors | 11 further drains, same pattern, 05:51–13:22 UTC |

**Indicators of compromise (IoCs):**

*Attack (Polygon):*
- Drainer contract (attacker-exclusive): `0x00000000000fb5c9adea0298d729a0cb3823cc07` (leading-zeros vanity, 124-byte minimal contract) → impl `0xb6f9c7e6…`
- Executor EOAs, rotating (attacker-exclusive): `0xde9e08b97b6b0c5b2aab2fac11a4f2d0f0288c3b`, `0x4c917200bda6cb9b2608cc07029f846a66d06395`, …
- Stolen token: pUSD `0xC011a7E12a19f7B1f670d46F03B03f3342E82DFB`
- Victim contracts (victim-owned, not attacker): Polymarket **proxy** wallets (delegatecall to Polymarket proxy impl `0x58ca52eb…`)
- Exploit txs: 17 drains, 2026-06-25 05:51–13:22 UTC (full set in the §4.7 table); largest `0x2ca925546092ed6e121e3ed8aec26b98b3c176a4bb3c1e2bf76caa1a21a2b0cc`

*Cash-out / fund movement:*
- pUSD collectors = cross-chain staging EOAs (attacker-exclusive; shared attack/cash-out role — see §4.6): `0xe42640650c…d2222`, `0xc771a30a7c…baae2`, `0x51cf782223…9c5ca`, `0x10366adbb5…5a107`, `0x2eb06b8d81…3891b`, `0xc44f2ca6b3…32ec4`
- Ethereum consolidation address (attacker-exclusive): `0xe65b1C586757c5510B60F998Eebb14C1eF71E1eD`
- Final holding EOA — current location of ~1,788.52 ETH (attacker-exclusive): `0x975268a2a71e4a7e282b962ec0b1ee01d3778ac0`
- Key cash-out tx (the 1,788.52 ETH move): `0x62781171eef8748b967d3926c82f5c73cbf2cb40a189443347ad9f276966b086`
- Swap/bridge laundering venue (shared public infrastructure, NOT attacker-controlled): `0xf70da97812cb96acdf810712aa562db8dfa3dbef`
- Address-poisoning spammer that touched the staging wallets (shared, NOT attacker-controlled): `0x1210768ac1278049e2f1875e994a443f492aca77`

*Note:* one address AMLBot reported as a "staging wallet," `0x7bcece0d…`, is on-chain actually a **drained victim** (3 transfers into collector `0x2eb06b8d…`) — a minor correction to public attribution.

---

## 5. Impact
- **Direct user loss:** ~$3.1M across 11 wallets.
- **Affected population:** Only users who loaded the compromised front-end during the attack window and signed the malicious prompt.
- **Protocol contracts:** No reported compromise of Polymarket's on-chain settlement contracts.
- **Reputational / regulatory:** Compounded by a concurrent CFTC probe and the earlier May 22 internal-wallet incident.

---

## 6. Response
- Polymarket **removed the compromised vendor dependency** and patched the delivery path.
- Publicly committed to **fully reimburse affected pUSD holders**.
- Began **contacting impacted users** directly.

---

## 7. Lessons & recommendations

**For protocols / dApp operators:**
- **Treat the front-end supply chain as in-scope for security.** Audited contracts do not protect users if the JS bundle is compromised. Inventory every third-party script, SDK, and build-time dependency that can reach production.
- **Subresource Integrity (SRI)** and **strict Content-Security-Policy (CSP)** to block unexpected/injected scripts and restrict script origins.
- **Pin and verify dependencies** (lockfiles, signed releases, reproducible builds); monitor for unexpected modifications to third-party code (Halborn recommendation).
- **Front-end change detection / runtime integrity monitoring** to alert on unauthorized DOM/script changes served to users.
- **Vendor risk management** — assess and continuously monitor third-party code suppliers; minimize the number of externally controlled scripts with DOM/wallet access.
- **Wallet UX hardening** — clearer human-readable transaction simulation/decoding so "routine-looking" malicious signatures are surfaced as anomalous.

**For users:**
- Use wallets with **transaction simulation / signature decoding**; scrutinize what is actually being signed — not just `approve`/`permit`, but **smart-contract-wallet / proxy execution authorizations** (EIP-712 order/exec messages), which is what was abused here and which many wallets render opaquely.
- Consider **per-session spending limits** and revoking stale token approvals.

**For account-abstraction / proxy-wallet designers (Polymarket-specific lesson):**
- A signed proxy-execution authorization is effectively a **blank check** if the frontend is compromised. Constrain what a single signed exec can do (allow-list targets/selectors, per-tx value caps, short signature expiry, explicit human-readable intent in the EIP-712 domain/struct).

---

## 8. Broader 2026 context
This fits the year's dominant pattern: **compromised accounts/keys and supply-chain attacks have overtaken smart-contract exploits** by incident count in DeFi during 2026. The failure surface has shifted from Solidity bugs to **operational security, delivery pipelines, and human-in-the-loop signing**.

---

## 9. Sources
- [CoinDesk — Polymarket hack updated to $3.1M after refund promise (Jun 27, 2026)](https://www.coindesk.com/markets/2026/06/27/polymarket-hack-updated-to-usd3-1-million-days-after-the-platform-promised-users-full-refunds)
- [Halborn — Explained: The Polymarket Hack (June 2026)](https://www.halborn.com/blog/post/explained-the-polymarket-hack-june-2026)
- [Phemex — Polymarket Hacked for $3.1M Days After Refund Promise](https://phemex.com/blogs/polymarket-hacked-3-1-million-refunds)
- [CoinMarketCap — Polymarket hackers drain $2.9M, refunds promised](https://coinmarketcap.com/academy/article/polymarket-hackers-drain-2-9m-user-wallets-refunds)
- [PYMNTS — Polymarket faces CFTC probe and $3M hack](https://www.pymnts.com/legal/2026/polymarket-faces-cftc-probe-and-deals-with-3-million-hack/)
- [SpazioCrypto — Polymarket $3M hack: a supply chain attack, not a contract exploit](https://en.spaziocrypto.com/hack/polymarket-hack-3-million-supply-chain-attack/)
- [Rescana — Supply-chain attack analysis (no public IoCs / vendor undisclosed)](https://www.rescana.com/post/polymarket-supply-chain-attack-analysis-3-million-cryptocurrency-theft-via-compromised-third-party-dependency)
- [The Defiant — AMLBot traces $3.1M across 11 wallets to Ethereum (attacker address attribution)](https://thedefiant.io/news/hacks/amlbot-polymarket-phishing-3-1-million-11-wallets-ethereum)
- **On-chain (first-hand):** Ethereum and Polygon on-chain data, checked 2026-07-01. Drain-tx set and call traces reconstructed independently.

---
*Prepared for internal security review. §4 fund-flow figures are first-hand on-chain reads (2026-07-01). The attack-method characterization in §3 combines as-reported context with labeled inference. Re-verify balances before citing externally, as funds may move.*
