# Bonzo Lend / Supra Pull-Oracle Verifier Exploit — July 2026

**Report date:** 2026-07-13
**Incident date:** 2026-07-11
**Target:** Bonzo Lend (the Aave-style lending market of Bonzo Finance, `@bonzo_finance`) on Hedera; root cause in the **Supra pull-oracle verifier** deployed on Hedera mainnet
**Loss:** attacker (Wallet A) borrowed **6,634,528.202695 USDC + 34,518,389.36109841 WHBAR** against a **250 SAUCE** deposit (worth a few dollars). At the incident-time reference of HBAR ≈ $0.06998, the WHBAR leg is ≈ $2.42M, so the drain is ≈ **$9.05M** — figures as reported by Bonzo Finance and CoinDesk, 2026-07-11. A second actor (Wallet B, self-identified white-hat) took ~$1M the same way and stated an intent to return it.
**Category:** Oracle verifier flaw — **degenerate BLS signature over BN254**. A price update referencing an unpopulated committee (ID 2) made the on-chain key lookup return zero-valued (identity-element) public-key coordinates instead of reverting; the attacker paired that with a zeroed signature `[0,0]`, and the pairing check `e(σ, g₂) == e(H(m), pk)` reduced to `1 == 1` for any message. The verifier accepted the forged update, wrote a SAUCE price inflated ~12 orders of magnitude, and Bonzo Lend — behaving exactly as written — lent against the fictitious collateral value.
**Chain:** Hedera mainnet (consensus timestamp `1783731099.646109213`, block 97,504,678; exploit tx `0xd50c…0a60`)
**Status:** Supra acknowledged the verifier bug and deployed a fix to the affected contract on Hedera mainnet *(as reported)*. Bonzo paused Lend at 01:41 UTC and Bonzo Points at 05:50 UTC. Of the proceeds, ~$5.25M was bridged to Ethereum via LayerZero and rotated through WBTC into ETH *(attributed to Specter / press)*. No full third-party post-mortem beyond Bonzo's and Supra's own reports at the time of writing.

> Scope note: This is an internal reference report. The exploit transaction and its consensus time (§2), the decoded malicious payload — committee ID, committee hash, zeroed signature, pair 425, and the 10³⁰ price field (§3.3) — the internal EVM call graph through the verifier to the BN254 pairing precompile (§3.4), the 250-SAUCE deposit, the benign warm-up update, both borrow legs and their exact amounts (§4), the attacker account's age and key type, and every contract/token entity ID and EVM address (§7) were read first-hand from Hedera mainnet on 2026-07-13 via the public mirror node (`/api/v1/transactions`, `/contracts/results/{hash}`, `/contracts/results/{hash}/actions`, `/accounts`, `/contracts`, `/tokens`) and by decoding the raw call data. Those findings are first-hand and reproducible. The cryptographic root-cause reading (§3.5) is grounded in Supra's own incident report plus the observed call graph. Off-chain context — the ~$9.05M and ~$1M USD headlines, the HBAR/SAUCE reference prices, the −77% Bonzo / ~−40% Hedera TVL moves, the LayerZero bridge-out and Ethereum-side WBTC→ETH rotation, the white-hat framing of Wallet B, and Supra's deployed fix — is as reported by Bonzo Finance, Supra, CoinDesk, Cointelegraph, and Specter, and is flagged where it goes beyond what the chain shows.

---

## 1. Executive summary

On 2026-07-11 at 00:51:39 UTC an account created less than three hours earlier drained Bonzo Lend, Hedera's largest lending market, by feeding it a fabricated price through Supra's pull oracle. The flaw was not in Bonzo. Bonzo's `LendingPool` read the SAUCE/wHBAR price its Supra adapter returned and lent against it correctly; the price it read was a forgery the oracle should never have accepted.

Supra's pull-oracle model lets anyone submit a signed price update on-chain, and the on-chain **verifier** is the only thing standing between a caller and the price feed. A valid update carries a BLS signature from a registered oracle committee, and the verifier checks it with a pairing equation over the BN254 curve. Two defects combined into a total bypass. First, the update referenced **committee ID 2**, which had no registered key material; instead of rejecting an unknown committee, the lookup returned an all-zero public key — the **identity element** (point at infinity) of the group. Second, the verifier accepted the identity element as a legitimate input and accepted a **zeroed signature `[0,0]`** to match. BLS verification is `e(σ, g₂) == e(H(m), pk)`; with both `σ` and `pk` at infinity, each pairing collapses to the identity in the target group, so the equation becomes `1 == 1` and holds *for any message whatsoever*. The BN254 pairing precompile did exactly what the spec says — a pairing involving the point at infinity is the identity — and returned true. The signature check was decorative.

With the check neutralized, the attacker wrote a SAUCE price of `10³⁰` (raw field; the feed carries 18 decimals, so ≈ `10¹²` in normalized terms) into pair 425 — roughly twelve orders of magnitude above SAUCE's real ~0.2 wHBAR. Then the money leg: deposit **250 SAUCE** as collateral, and because those 250 tokens now "valued" at an astronomical number, borrow essentially the whole pool — **6,634,528.202695 USDC** eight seconds after the fake price landed, and **34,518,389.36109841 WHBAR** ten seconds after that. The chain shows both borrows as calls to the Bonzo `LendingPool` proxy `0.0.7308459`, each crediting the attacker the exact reported amount.

The exploit used only permissionless functions: the public pull-oracle update entrypoint (selector `0x03a02dfd`) and Bonzo's ordinary `deposit`/`borrow`. No admin key, no committee key, no compromised signer. The verifier and the lending pool executed as written; "as written" trusted a signature that a caller could make trivially satisfiable.

---

## 2. Timeline (2026-07-11, UTC; on-chain verified unless noted)

| Time | Event |
|---|---|
| Jul 10 22:09:23 | Attacker account **Wallet A** `0.0.10633526` (`0x9a49…a494`, ECDSA secp256k1) is created — ~2h42m before the exploit (created timestamp `1783721363.090…`). |
| Jul 11 00:39:43 | Wallet A transacts against the SAUCE token `0.0.731861` (association/allowance ahead of the deposit). |
| Jul 11 00:39:53 | **Deposit** — Wallet A supplies **250.000000 SAUCE** to Bonzo Lend `0.0.7308459` (`−250000000` at 6 dp). |
| Jul 11 00:40:00 | Wallet A submits a **benign, correctly-valued** price update to the Supra oracle `0.0.4323024` — a warm-up / dry run one minute before the forgery. |
| Jul 11 00:51:39.646 | **Exploit** — Wallet A submits the **manipulated update for pair 425** to `0.0.4323024` (tx `0xd50c…0a60`, block 97,504,678). Verifier accepts the zeroed signature; price `10³⁰` is written. |
| Jul 11 00:51:47 | Wallet A **borrows 6,634,528.202695 USDC** (`0.0.456858`) from Bonzo Lend. |
| Jul 11 00:51:57 | Wallet A **borrows 34,518,389.36109841 WHBAR** (`0.0.1456986`) from Bonzo Lend. |
| Jul 11 ~01:11–01:36 | **Wallet B** `0.0.683607` (`0x…0a6e57`, self-identified white-hat) runs the same play — deposits SAUCE, borrows ~$1M — and later states an intent to return the funds *(as reported)*. |
| Jul 11 01:36 | Legitimate oracle publishing resumes and restores SAUCE to ~0.1964 wHBAR *(per Bonzo)*. |
| Jul 11 01:41 | Bonzo **pauses Bonzo Lend** *(per Bonzo)*. |
| Jul 11 05:50 | Bonzo **pauses Bonzo Points** *(per Bonzo)*. |
| Jul 11 (same day) | Attacker swaps borrowed assets and bridges ~$5.25M to Ethereum via LayerZero; funds rotated through WBTC into ETH *(attributed to Specter / press)*. Supra deploys a verifier fix on Hedera mainnet *(as reported)*. |

---

## 3. Attack vector and root cause

### 3.1 The system

Verified Hedera entities (IDs and EVM addresses read from the mirror node, 2026-07-13):

- **Supra pull-oracle (feed) contract** — `0.0.4323024` / `0x41ab2059baa4b73e9a3f55d30dff27179e0ea181`. The permissionless target of price updates; it delegates to an implementation `0.0.10414936` and calls the verifier before storing a price.
- **Supra verifier** — `0.0.4323006` (long-zero `0x…41f6be`, aliased `0x2fa6dbfe4291136cf272e1a3294362b6651e8517`), delegating to implementation `0.0.10414935`. This is the contract that checks the committee BLS signature.
- **Bonzo `LendingPool` proxy** — `0.0.7308459` / `0x236897c518996163E7b313aD21D1C9fCC7BA1afc`. Aave-style pool; holds the borrowable USDC/WHBAR liquidity.
- **Bonzo Supra-oracle adapter** — `0.0.7308480` / `0xc0Bb4030b55093981700559a0B751DCf7Db03cBB`. Bonzo's price source; reads the Supra feed for pair 425 and returns it to the pool.
- **BN254 / hashing precompiles** — the standard EVM precompiles at `0x02` (SHA-256), `0x06` (bn256 addition), `0x08` (bn256 pairing), reached on Hedera as system entities `0.0.2` / `0.0.6` / `0.0.8`.

Tokens (all confirmed on-chain): **SAUCE** `0.0.731861` (6 dp), **USDC** `0.0.456858` (6 dp), **WHBAR** `0.0.1456986` (8 dp).

### 3.2 The oracle trust model

Supra runs a *pull* oracle: prices are not pushed by a privileged keeper but submitted on-chain by anyone, carrying a payload signed off-chain by a Supra oracle **committee**. The on-chain verifier is the entire security boundary — it recomputes the message hash, looks up the referenced committee's aggregate BLS public key, and checks the signature with a BN254 pairing. If that check passes, the price is written and every consumer (here, Bonzo via its adapter) treats it as canonical. There is no second signer, no dispute window, and no per-caller authorization: soundness rests entirely on the verifier rejecting anything that is not a genuine committee signature.

### 3.3 The forged payload (decoded from the raw call data)

The exploit transaction's input to `0.0.4323024` is 644 bytes: a 4-byte selector `0x03a02dfd` followed by twenty 32-byte words. Decoded, the load-bearing fields are:

| Word | Value | Meaning |
|---|---|---|
| 4 | `2` | **Committee ID = 2** — an unpopulated committee (no registered key). |
| 5 | `0xd4e6b48aef731cc8cd74b25fbaec267ff8a6269aea1f4be4ee19dda5ecbf3f7f` | Message / committee-root hash `H(m)` — arbitrary; irrelevant once the check is degenerate. |
| 6–7 | `0`, `0` | **BLS signature `σ = [0,0]`** — the identity element (point at infinity) in G1. |
| 13 | `425` | Pair ID — **SAUCE/wHBAR**. |
| 14 | `1000000000000000000000000000000` (`10³⁰`) | **Injected price** — raw field. |
| 16 | `18` | Price decimals ⇒ normalized price ≈ `10¹²`, vs SAUCE's real ~0.2 wHBAR. |
| 15, 17 | `1783730770000`, `1783730181000` | Round / timestamp metadata (ms) — cosmetic. |

So the attacker did not need to forge a signature so much as choose inputs that made verification vacuous: name a committee that doesn't exist (word 4), hand over a zero signature (words 6–7), and stamp any price they liked (word 14).

### 3.4 What the chain proves about the verification path

The mirror node's internal-action trace for `0xd50c…0a60` shows the full EVM call graph, and every frame returned `OUTPUT` (success):

```
Wallet A 0.0.10633526
└─ CALL       → Supra oracle proxy      0.0.4323024
   └─ DELEGATECALL → oracle impl         0.0.10414936
      ├─ STATICCALL   → verifier proxy   0.0.4323006
      │  └─ DELEGATECALL → verifier impl 0.0.10414935
      │     ├─ STATICCALL → 0x02  SHA-256        (hash the message)   ×4
      │     ├─ STATICCALL → 0x06  bn256 add       (G1 arithmetic)      ×1
      │     └─ STATICCALL → 0x08  bn256 pairing   (the BLS check)      ×1  → SUCCESS
      ├─ STATICCALL → price store 0.0.4322850 (→ impl 0.0.6814361)
      └─ CALL       → price store 0.0.4322850 (→ impl 0.0.6814361)     write the price
```

The pairing precompile `0x08` was invoked once and returned success, after which the oracle wrote the price (the non-static `CALL` into the storage contract) and emitted a single price-update event (`topic0 = 0xf77b9be2…506824`) from `0x41ab…a181`. This is the exploit rendered mechanically: the verifier ran, called the real BN254 pairing precompile, and the precompile said the degenerate signature was valid.

### 3.5 Root cause — an identity-element signature that always verifies

BLS over BN254: a committee's aggregate public key is `pk = x·g₂` in G2; a signature over message `m` is `σ = x·H(m)` in G1; verification checks

```
e(σ, g₂) == e(H(m), pk)
```

which the verifier evaluates through the pairing precompile. The pairing `e` is bilinear, and the point at infinity `O` is the group identity, so `e(O, ·) = e(·, O) = 1` (the identity in the target group). The attack drove **both** arguments to the identity:

- **`pk = O`** came for free. Committee ID 2 had no registered key material. Rather than revert on an unknown committee, the lookup returned a zero-initialized key struct — all-zero coordinates, i.e. the point at infinity. (Supra: *"a committee reference outside the populated range returned zero-valued public-key material instead of being rejected."*)
- **`σ = O`** the attacker supplied directly, as `[0,0]` (words 6–7).

With `σ = O` and `pk = O`, the check becomes `e(O, g₂) == e(H(m), O)`, i.e. `1 == 1`, **independent of the message and the price**. Supra states it the same way: *"When both the signature and the public key are the identity element, both sides of the equation reduce to the multiplicative identity: `e(G, O) = 1 = e(O, H(m))`."*

Two things are worth stating precisely, because they mirror the "the math did what it should; the input was manipulated" pattern seen in other oracle/verifier failures:

1. **The precompile was not broken.** `0x08` correctly reports that a product of pairings involving the point at infinity equals the identity. The defect is upstream: the verifier fed it degenerate points it should have rejected first. A BLS verifier must reject the identity element as a public key or signature, and must reject group elements that are not on-curve / not in the correct prime-order subgroup, *before* pairing.
2. **The out-of-range committee is the enabling bug; the accepted zero signature is the fatal one.** Either guard alone stops the attack — you cannot reach a valid `1 == 1` without both operands being the identity. Supra's own conclusion: *"The identity-element check alone would have prevented this attack."*

### 3.6 Why 250 SAUCE unlocked ~$9M

Bonzo priced collateral through its Supra adapter for pair 425 (SAUCE denominated in wHBAR). The forged feed reported SAUCE at ~`10¹²` (normalized) instead of ~0.2 wHBAR — roughly twelve to thirteen orders of magnitude high. A 250-SAUCE deposit, worth a few dollars in reality, was therefore valued by the pool at an astronomically large wHBAR figure, so any sane loan-to-value ratio still permitted borrowing the entire available liquidity. The pool then paid out real USDC and real WHBAR against fictitious collateral. Bonzo's contracts did not misbehave; they consumed a poisoned price and lent accordingly, which is exactly why Bonzo's post-mortem places the fault in the oracle, not in the lending logic.

### 3.7 Ruled out (on-chain evidence)

- **Bonzo smart-contract bug:** not involved. Only permissionless `deposit`/`borrow` were called; the pool priced collateral off the oracle price it was handed.
- **Committee-key compromise / signer theft:** not involved. No real signature was used; the attack works precisely *because* it uses a non-signature (`σ = O`) against a non-key (`pk = O`).
- **Supra off-chain infrastructure breach:** not involved. Supra's report and the on-chain trace both locate the failure in the on-chain verifier's input validation, not in the off-chain price network.
- **A broken pairing precompile / EVM bug:** ruled out by §3.4 — `0x08` behaved to spec; it was handed degenerate inputs.

---

## 4. On-chain accounting (independently verified)

> Method: Hedera mainnet via the public mirror node (`mainnet-public.mirrornode.hedera.com`). Transactions pulled by account and time window; the exploit call decoded from `function_parameters`; the call graph from `/contracts/results/{hash}/actions`; token deltas from `token_transfers`. Checked 2026-07-13.

### 4.1 The sequence on Wallet A `0.0.10633526`

| Time (UTC) | Type | Target | Token delta (Wallet A) |
|---|---|---|---|
| 00:39:53 | deposit | Bonzo Lend `0.0.7308459` | −250.000000 SAUCE |
| 00:40:00 | benign update | Supra oracle `0.0.4323024` | — |
| 00:51:39 | **malicious update** | Supra oracle `0.0.4323024` | — (writes price `10³⁰`) |
| 00:51:47 | **borrow** | Bonzo Lend `0.0.7308459` | **+6,634,528.202695 USDC** |
| 00:51:57 | **borrow** | Bonzo Lend `0.0.7308459` | **+34,518,389.36109841 WHBAR** |

Each borrow is an `ETHEREUMTRANSACTION` to the pool paired with a child `CRYPTOTRANSFER` crediting Wallet A the exact amount above — `6634528202695` (6 dp USDC) and `3451838936109841` (8 dp WHBAR). Both match Bonzo's reported figures to the last digit. The malicious update paid a Hedera network fee of ~0.407 HBAR and burned 336,426 gas.

### 4.2 Net result

| Leg | Amount | Reference value |
|---|---|---|
| USDC borrowed | 6,634,528.202695 USDC | ≈ $6.63M |
| WHBAR borrowed | 34,518,389.36109841 WHBAR | ≈ $2.42M (HBAR ≈ $0.06998) |
| **Wallet A total** | | **≈ $9.05M** *(as reported)* |
| Wallet B (white-hat) | same method | ≈ $1.0M, stated for return *(as reported)* |
| Collateral posted | 250 SAUCE | a few dollars |

The USD totals are as reported by Bonzo Finance and CoinDesk on 2026-07-11 and depend on the incident-time HBAR price; the token amounts and the 250-SAUCE collateral are first-hand.

### 4.3 Aftermath on the account

Queried on 2026-07-13, Wallet A holds **0 USDC** and **0 WHBAR** — both borrowed balances were swapped out and moved off Hedera — while retaining ~255.96 SAUCE and ~21,000 HBAR of dust and residue, at ethereum-nonce 94 (≈94 EVM transactions since creation).

---

## 5. Laundering

First-hand on Hedera: after the two borrows, Wallet A converted the proceeds in tranches — swapping through SaucerSwap (calls routed via the Hedera Token Service system contract at `0.0.359`) and routing value through contracts `0.0.9470869` (`0xca36…1ef2`) and `0.0.9470871` (`0xda60…dcad`), consistent with a bridge/OFT egress. The account's USDC and WHBAR balances were fully drained to zero by the end of this activity.

Cross-chain, as reported: on-chain investigator Specter and subsequent press traced ~$5.25M bridged from Hedera to Ethereum via **LayerZero**, where it was rotated through **WBTC** into **ETH**. Because Wallet A's key is ECDSA secp256k1, its EVM address `0x9a4966152f6e10b33cb7a37975e8619816d6a494` is the same on Ethereum; a second Ethereum address `0xaf2…6dD93e` was also flagged. The Ethereum-side wallet was reported holding ~2,360 ETH (~$4.25M) and 15.58 WBTC (~$1M) at the time. Onward movement past ETH, and full first-hand tracing of the LayerZero delivery leg, are out of scope here and should be re-verified against Ethereum state before external citation.

Wallet B `0.0.683607` executed the same exploit for ~$1M and publicly framed itself as a white-hat intending to return the funds *(as reported)*; recovery coordination was ongoing at the time of writing.

---

## 6. Root-cause summary and remediation

**Root cause.** A BLS-over-BN254 signature verifier that (a) returned a zero-valued (identity-element) public key for an unregistered committee instead of reverting, and (b) accepted the identity element as a valid public key and signature, so that a zeroed signature satisfied the pairing equation `1 == 1` for any message. This let anyone write an arbitrary price into Supra's Hedera pull oracle. Bonzo Lend consumed the poisoned SAUCE/wHBAR price faithfully and lent ~$9M against a few dollars of collateral.

**Supra's fix (three validation layers, as reported).**

- **Committee-range validation** — reject any update whose committee identifier has no registered key material, instead of silently returning zeroed coordinates.
- **Identity-element rejection** — reject the point at infinity as either a public key or a signature. Supra notes this check alone would have blocked the attack.
- **On-curve / subgroup validation** — verify that submitted points lie on the BN254 curve and in the correct prime-order subgroup before any pairing.

**What else hardens this class.**

- **Fail closed on key lookups.** A missing/unknown key must revert, never default to a zero struct; degenerate defaults are how "unknown" silently becomes "trusted."
- **Validate group elements before cryptographic use** as a standing rule for any pairing/signature verifier — identity, on-curve, and subgroup checks are cheap relative to the blast radius.
- **Consumer-side price sanity for low-liquidity assets.** A lending market should bound single-update price movement or cross-check thin feeds (SAUCE here) against an independent reference; a ~10¹²× jump in one block should never be borrowable against. This does not fix the oracle, but it caps the damage when an oracle fails.
- **Rate-limit borrow power to fresh price moves.** Requiring collateral valuations to age, or capping borrow against just-updated prices, removes the deposit→poison→borrow-in-seconds primitive seen here (deposit 00:39:53, poison 00:51:39, borrow 00:51:47).

**Broader lesson.** A signature check is only as strong as its input validation. The BN254 pairing precompile was correct, the lending pool was correct, the off-chain oracle network was intact — and the system still lost ~$9M, because one verifier treated "no committee, no signature" as "valid committee, valid signature." Verifiers must reject the identity element and unregistered keys before they ever reach the math.

---

## 7. Indicators (addresses & identifiers)

| Role | Hedera ID | EVM address |
|---|---|---|
| Exploit transaction | `0.0.995584-1783731093-686041919` | `0xd50c55e24eb8483ec55bf74e84fc9853d0f0fe36f64abdb812a2d9afa2a10a60` |
| Block / consensus time | 97,504,678 | `1783731099.646109213` (2026-07-11 00:51:39 UTC) |
| Wallet A (attacker) | `0.0.10633526` | `0x9a4966152f6e10b33cb7a37975e8619816d6a494` |
| Wallet B (white-hat) | `0.0.683607` | `0x00000000000000000000000000000000000a6e57` |
| Supra pull-oracle (feed) | `0.0.4323024` | `0x41ab2059baa4b73e9a3f55d30dff27179e0ea181` |
| Supra oracle implementation | `0.0.10414936` | — |
| Supra verifier | `0.0.4323006` | `0x2fa6dbfe4291136cf272e1a3294362b6651e8517` (long-zero `0x…41f6be`) |
| Supra verifier implementation | `0.0.10414935` | — |
| Supra price-store contract | `0.0.4322850` (→ impl `0.0.6814361`) | — |
| Bonzo `LendingPool` proxy | `0.0.7308459` | `0x236897c518996163E7b313aD21D1C9fCC7BA1afc` |
| Bonzo Supra-oracle adapter | `0.0.7308480` | `0xc0Bb4030b55093981700559a0B751DCf7Db03cBB` |
| BN254 pairing precompile | `0.0.8` | `0x08` |
| BN254 addition precompile | `0.0.6` | `0x06` |
| SHA-256 precompile | `0.0.2` | `0x02` |
| SAUCE / USDC / WHBAR | `0.0.731861` / `0.0.456858` / `0.0.1456986` | 6 / 6 / 8 decimals |
| Egress contracts (bridge/OFT) | `0.0.9470869` / `0.0.9470871` | `0xca367694cdac8f152e33683bb36cc9d6a73f1ef2` / `0xda6087e69c51e7d31b6dbad276a3c44703dfdcad` |
| Committee hash in payload | — | `0xd4e6b48aef731cc8cd74b25fbaec267ff8a6269aea1f4be4ee19dda5ecbf3f7f` |
| Pull-oracle update selector | — | `0x03a02dfd` |
| Ethereum-side theft addresses *(reported)* | — | `0x9a49…6a494`, `0xaf2…6dD93e` |

## 8. Sources

Primary incident reports:

- Bonzo Finance — "Bonzo Lend Incident Report: Oracle Provider Exploit": https://bonzo.finance/blog/bonzo-lend-incident-report-oracle-provider-exploit
- Supra — "Security Incident Report: Hedera Pull-Oracle Verifier": https://supra.com/news/security-incident-report-hedera-pull-oracle-verifier/

Public reporting (figures and attribution as reported; re-verify before external citation):

- CoinDesk — "Bonzo Lend's total value locked plunges 77% as $9 million oracle exploit rattles Hedera": https://www.coindesk.com/web3/2026/07/11/lending-protocol-bonzo-loses-77-of-value-locked-as-usd9-million-oracle-exploit-rattles-hedera
- Cryptobriefing — "Bonzo Lend loses $9M in oracle exploit on Hedera": https://cryptobriefing.com/bonzo-lend-9m-oracle-exploit-hedera/
- The Crypto Times — "Hedera's Biggest DeFi Lender Bonzo Lend Hacked for $9M, $5.25M Bridged to Ethereum": https://www.cryptotimes.io/2026/07/11/hederas-biggest-defi-lender-bonzo-lend-hacked-for-9m-5-25m-bridged-to-ethereum/
- Blockonomi — "Bonzo Lend Loses $9.05M in Hedera Oracle Exploit Linked to Supra Flaw": https://blockonomi.com/bonzo-lend-loses-9-05m-in-hedera-oracle-exploit-linked-to-supra-flaw
- Hedera (X), 2026-07-11 — Supra acknowledgement and deployed fix: https://x.com/hedera/status/2075986869569884353
- Specter (on-chain tracing, via press) — LayerZero bridge-out and Ethereum-side WBTC→ETH rotation; Ethereum theft addresses.

All Hedera on-chain figures in §2–§4 and §7 were verified first-hand against Hedera mainnet via the public mirror node on 2026-07-13.
