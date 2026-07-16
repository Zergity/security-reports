# JaredFromSubway MEV Bot Exploit — Forensic Analysis

Forensic analysis of the JaredFromSubway MEV bot drain. Goal: reconstruct how the attacker tricked the bot, and determine whether the block-arm flag is load-bearing or vestigial. All findings below are verified on-chain.

---

## TL;DR of what happened

JaredFromSubway.eth — the most active Ethereum sandwich bot — was drained
~June 20–21, 2026 (reported $7.5M by Blockaid/PeckShield; operator claims ~$15M).
Not a key compromise, not a protocol bug. It was a **counter-MEV honeypot**: the
attacker deployed many fake WETH/USDC/USDT wrapper tokens + sham pools over time.
The bot routed through them as if they were real opportunities and, as part of
normal trading, granted ERC-20 approvals to them. Early approvals were consumed
normally (trust-building); later ones were left standing. A coordinator then
swept all the standing allowances in one transaction via `transferFrom`.

WETH stolen reconciles exactly: **16 standing allowances of 92.161407687812186112
WETH each = 1,474.58 WETH**, plus ~2.87M USDC and ~2M USDT, swapped to ~4.4K ETH,
partially laundered through Tornado Cash. Operator offered a 50% bounty (2,150 ETH);
attacker ignored it and kept laundering.

---

## Resolution — on-chain analysis (2026-06-24)

Both open questions are settled with hard evidence, verified first-hand against
on-chain data. Every figure below reconciles to the wei.

### Answer to Q#1 — the arm flag is LOAD-BEARING for conditioning, VESTIGIAL for the sweep
The earlier hypothesis holds *for the realized theft*, and this analysis also locates
where the flag IS load-bearing:
- **Sweep (`0x2be8…3e65`) = vestigial.** Whole call tree = `1× c269a509 → 66× child
  51cff8d9 → {balanceOf, allowance, conditional transferFrom}`. `4e69d560` and `086f6f56`
  occur **0 times** anywhere in the sweep's call tree. The sweep is **tx index 0** of block 25360696
  and the **only** tx in that 277-tx block touching coordinator/victim/any child — so no
  bot `wrap` could precede it. The drain works purely off standing allowances.
- **Conditioning (`0xa2c9d0a1…`, block 25360689, tx idx 2) = load-bearing.** The bot's own
  wrap/swap tx consults `4e69d560` **32×, all returning `true` (armed)** and runs the armed
  branch `086f6f56` **16×**. In the SAME block the attacker armed first:
  `idx 0`  submitter `0x5af387…` → coordinator, selector `b6e808af` → sets `slot1 = block.number`;
  `idx 2`  bot-operator `0xae2fc483…` → bot `0x1f2f10…` → wraps with the armed branch live.
  This is the sim-vs-execution divergence primitive proven end-to-end: armed only inside the
  attacker's bundle block. Auto-disarms — coordinator `slot1` is now `25360722` and
  `4e69d560()` returns `false` today (`block.number != slot1`).
- **The armed and unarmed wrap paths are NOT the same** (corrects an earlier source misread):
  on-chain, each wrap shows `unarmed → token.transferFrom(caller,this,amount)` (pulls, consumes the
  approval) vs `armed → strategy.086f6f56(amount)` store-branch with **no `transferFrom`** (does
  NOT pull → the approval is left standing). `4e69d560`'s return *at the instant the wrap runs*
  picks the branch. See the tx-ordering section below for the full proven mechanism.

### The arming mechanism, proven to transaction-index level (the dangling-approval race)
The armed flag is `4e69d560() == (block.number == slot1)`, true only during the exact block
written into `slot1`, auto-disarming the next block. Two selectors write `slot1=block.number`
on the coordinator: `b6e808af` (standalone arm) and `c269a509` (the sweep). From the
coordinator's full txlist:
- **The flag was switched on 12 times**, each for a single block, all from attacker submitter
  `0x5af387…`, within a ~59-min window: arms `b6e808af` at blocks 25360428, 25360481, 25360492,
  25360500, 25360511, 25360519, 25360551, 25360599, 25360667, 25360689, 25360722; plus the
  sweep `c269a509` at 25360696 (which arms vestigially). `slot1` is now frozen at 25360722, so
  the flag has read false for every block since.

**Where dangling approvals accrued — armed blocks only, never disarmed:** across all
362 conditioning txs (approve-set vs pulled, by armed/disarmed block):
| token | dangling-creating txs (armed / disarmed) | fully-consumed txs (armed / disarmed) |
|------|------|------|
| WETH | 29 / **0** | 61 / 136 |
| USDC | 41 / **0** | 0 / 112 |
| USDT | 20 / **0** | 0 / 24  |
Every dangling approval was created in an armed block; **zero** dangling ever occurred in a
disarmed block (in a disarmed block the wrap always pulled exactly what was approved → residual
0 — the simulation-safe behavior the bot saw before submitting).

**But the true determinant is intra-block ORDERING, not just block membership.** Block 25360428
*is* an armed block, yet its wrap read `4e69d560=0` and consumed normally — because the bot's
wrap tx was ordered **before** the arm tx that block:
| block | arm tx idx | bot-wrap tx idx | wrap saw | outcome |
|------|-----------|-----------------|----------|---------|
| 25360428 | 58 | 5  | unarmed (arm too late) | consumed (residual 0) |
| 25360519 | 0  | 2  | armed (arm front-ran)  | **left standing 92.16** |
So: **a dangling approval is created iff the attacker's arm tx is ordered ahead of the bot's
wrap tx in the same block.** It is a top-of-block front-running race (private bundle, arm at
idx 0). When the attacker won the race the wrap took the `086f6f56` store-branch and skipped the
pull; when the arm landed late, the wrap consumed normally and the attacker simply retried next
block. The surviving (swept) residuals were the ones armed in the final block per token
(WETH 25360689, USDC 25360599, USDT 25360667) — late enough that no later wrap consumed them.

**Per-armed-block master table** — all 12 arms, with builder, coinbase bribe, intra-block
ordering, victim txs before/after the arm, and dangling created. Victim tx = operator
`0xae2fc483…`→bot `0x1f2f10…`; bribe = the arm tx's `value` forwarded to `block.coinbase`;
"dangling created" = approvals set minus pulled in that block's victim tx, summed over children
(n×per-child). All times 2026-06-20 UTC.
| block | time | builder | bribe (ETH) | arm idx | victim b/a | dangling approval created |
|------|------|---------|---------------|--------|-----------|----------------------------|
| 25360428 | 17:55:23 | Titan | 0.00001 | 58 | 2 / 0 | — |
| 25360481 | 18:06:11 | Titan | 0.00001 | 68 | 2 / 0 | — |
| 25360492 | 18:08:23 | Titan | 0.00001 | 73 | 2 / 0 | — |
| 25360500 | 18:09:59 | Titan | 0.00001 | 44 | 1 / 0 | — |
| 25360511 | 18:12:11 | **Quasar** | 0.025 | 6 | 1 / 0 | — (0.025 bribe but non-targeted builder → lost) |
| 25360519 | 18:13:47 | Titan | 0.025 | 0 | 0 / 1 | 13 × 92.160059 = **1,198.080762 WETH** (transient — overwritten @25360689) |
| 25360551 | 18:20:11 | Titan | 0.025 | 0 | 0 / 1 | 21 × 143,526.674432 = **3,014,060.163072 USDC** (transient — overwritten @25360599) |
| 25360599 | 18:29:47 | Titan | 0.025 | 1 | 0 / 1 | 20 × 143,528.656384 = **2,870,573.127680 USDC** (final → fully swept) |
| 25360667 | 18:43:23 | Titan | 0.025 | 0 | 0 / 1 | 20 × 149,488.051712 = **2,989,761.034240 USDT** (final → balance-capped to 2,035,760.155871 at sweep) |
| 25360689 | 18:47:47 | Titan | 0.025 | 0 | 0 / 1 | 16 × 92.161408 = **1,474.582523 WETH** (final → fully swept) |
| 25360696 (sweep)    | 18:49:11 | Eureka | 0.010 | 0 | 0 / 0 | — (drain, not a grant) |
| 25360722 (trailing) | 18:54:23 | Builder+ | 0.025 | 1 | 0 / 0 | — |
| **TOTAL** |  |  |  |  | **8 / 5** | |

Cleanly phased: the **first 5 arms (25360428–25360511) landed late** (idx 6–73, behind all 8 bot
txs) → those wraps read unarmed → consumed normally → no residual. The **next 5 arms
(25360519–25360689) front-ran at idx 0–1** (ahead of the bot wrap at idx 2–3) → armed → standing
residual. Those 5 "after-arm" blocks are EXACTLY the dangling-creating blocks and map one-to-one
onto the token batches (WETH×2, USDC×2, USDT×1). The sweep block and the trailing 25360722 arm
had no victim tx. So the attacker's effective front-run hit rate was **5 of 11 arms**, and those
5 won races are the sole origin of every swept standing allowance.

Note the two-step "top-up per token": the first won race set a near-ceiling residual on most of
that token's wrappers (WETH 13×, USDC 21×), then a second won race ~6–16 min later **overwrote**
it with the final exact ceiling on the full set (WETH 16×, USDC 20×) immediately before the
sweep. So "dangling created" exceeds "finally swept" on the transient rows; the final rows per
token reconcile to the swept totals (WETH 1,474.58 / USDC 2,870,573.13 fully; USDT armed
2,989,761 but only 2,035,760.16 extractable — balance-capped).

This is the sim-vs-execution divergence end-to-end: the bot simulates against pre-inclusion
state (slot1 = an old block → unarmed → wrap would pull → residual 0 → profit check passes →
submit); the attacker inserts the arm at idx 0 of the inclusion block; at execution the wrap is
armed → no pull → residual left for the sweep.

### How the attacker bought top-of-block (idx 0) — coinbase bribe, not a gas auction
Landing at idx 0 ahead of the bot is NOT priority-fee outbidding. In block 25360689 the arm tx
pays **0 gwei priority fee** (gasPrice = baseFee) yet sits at idx 0, while the bot tx pays
**7.40 gwei** priority (≈0.0179 ETH on 2,461,708 gas) and sits at idx 2. A fee-sorted block would
put the bot first. The lever is a **direct `block.coinbase` bribe** inside the arm: the
coordinator's `b6e808af` forwards the tx's `value` to the builder (see the `bribe→cb` and
`builder` columns in the master table above). A builder maximizes total block value, so a bundle
paying 0.025 ETH outranks the bot's 0.0179 ETH bid → attacker at idx 0, bot at idx 2.

Two conditions had to hold to win the race, both visible in the master table: (1) **bribe > the
bot's priority bid** — the 4 earliest arms paid only 0.00001 ETH (deliberate probes) and landed
late; (2) **the bundle lands in a block built by the targeted builder** — all 5 wins were Titan
blocks, while the lone 0.025-bribe loss (25360511) was a Quasar block, so the bundle didn't get
top placement. Economics: ~0.025 ETH per won arm + 0.01 on the sweep ≈ a few hundred USD in
builder tips to enable a ~$15M theft.

### Answer to Q#2 — accrual curve (and it was ~27 HOURS, not "several weeks")
- **Whole campaign ≈ 27 h.** All 66 wrappers deployed by `0x3e37f4…` via one factory
  `0x81f248ff583d3f8592ea0354a7b8dbe66de40091`, blocks 25352684–25354707
  (2026-06-19 16:00→22:46 UTC, ~6.7 h). Conditioning approvals blocks 25354425–25360695
  (~21 h). Sweep block 25360696 = **2026-06-20 18:49 UTC**.
- **66 = 22 WETH + 22 USDC + 22 USDT** wrappers.
- **Per-child rhythm** (sample WETH child `0x4ee0b6e9…`): early small grants (0.0074, 0.60
  WETH) each *immediately consumed* by a matching wrap → residual 0 (trust-building); a late
  ladder climbing to exactly **92.161407687812186112** left *un-consumed*. Cumulative approved
  per WETH child ≈ 553–572 WETH, almost all churned through legit wraps.
- **Arming = one tx per token**, all standing allowances set to the exact ceiling in a single
  block, sent by bot-operator `0xae2fc483…` to bot `0x1f2f10…`:
  WETH `0xa2c9d0a1…`@25360689 (16 grants), USDC `0xf570bdf2…`@25360599 (20), USDT
  `0x51a1aafa…`@25360667 (20).
- **Allowance vs. realized transfer (reconciles exactly):**
  - WETH: 16 × 92.161407687812186112 = **1,474.582523 WETH** (allowance-bound; victim held ~1,965 WETH > Σallowances).
  - USDC: 20 × 143,528.656384 = **2,870,573.127680 USDC** (allowance-bound).
  - USDT: 20 ceiling allowances were armed (Σ = 2,989,761.034240) but the theft was
    **BALANCE-constrained** — victim held only **2,035,760.155871 USDT**. The sweep loop pulled
    `min(allowance, runningBalance)`: 13 full × 149,488.051712 + 1 partial of **92,415.483615**
    (= the last of the balance), then the remaining 6 USDT children pulled **0** (balance dry).
    Array order, not allowance, decided who got paid.
- **Withdraw semantics (source-confirmed):** `withdraw(src)` pulls `min(allowance(src,this),
  balanceOf(src))` to `owner()`. `owner` = `tx.origin` at deploy = `0x3e37f4…` → that is why
  every drain lands at `0x3e37f4…`. The 86f… stored amount is NOT what gets pulled.

### Corrections to earlier notes in this file
1. **Sweep submitter ≠ destination.** The sweep was sent **from `0x5aF38735B215b00aa7C9f93fEd7ee415CeCB36e1`**, not `0x3e37f4…`. `0x3e37f4…` is the fund **destination** + wrapper deployer/owner.
2. **USDT drained = 13 full + 1 partial (14 transfers), ≈ 2.04M USDT**, balance-constrained — not "~9 + 1 partial".
3. **Campaign ≈ 27 h total**, not "several weeks" (deployment 6.7 h + conditioning ~21 h).
4. **Arm flag**: resolved — load-bearing in conditioning, vestigial in the sweep.

### Additional actors identified
- `0x5aF38735B215b00aa7C9f93fEd7ee415CeCB36e1` — attacker: submits the block-arm tx (`b6e808af`) and the sweep.
- `0x81f248ff583d3f8592ea0354a7b8dbe66de40091` — factory that deployed all 66 wrappers.
- `0xae2fc483527b8ef99eb5d9b44875f005ba1fae13` — bot operator/controller EOA that drives `0x1f2f10…` (issued every conditioning approval + the 3 arming txs); also baked into each wrapper's constructor (minter/coreRef).

---

## Confirmed addresses (verified on-chain)

### Attack

| Role | Address |
|------|---------|
| Coordinator **AND** oracle (one contract, two roles) | `0xb84db016324e8f2bfdd8dd9c260338aee0a8df52` |
| Victim / drain source (Jared bot **contract**; `src` in every drain transfer) | `0x1f2f10d1c40777ae1da742455c65828ff36df387` |
| Attacker destination + wrapper deployer/owner (`dst` in every drain transfer; `owner()` of every child) | `0x3e37f4A10d771Ba9dE44b6d301410b1BEdeA65d0` |
| Attacker submitter EOA (sends the block-arm tx `b6e808af` **and** the sweep) — CORRECTION: this, not `0x3e37f4…`, is the sweep `from` | `0x5aF38735B215b00aa7C9f93fEd7ee415CeCB36e1` |
| Bot operator/controller EOA (drives `0x1f2f10…`: all conditioning approvals + 3 arming txs) | `0xae2fc483527b8ef99eb5d9b44875f005ba1fae13` |
| Wrapper factory (deployed all 66 children) | `0x81f248ff583d3f8592ea0354a7b8dbe66de40091` |
| Sweep transaction (block 25360696, tx idx 0) | `0x2be8704f5a59b69e0b71f64aefdb99eb0e8ae9fb3926147c581910d71bcf3e65` |
| Arming txs (set ceiling allowances) | WETH `0xa2c9d0a13cc985e3fe445ad8d8bc2d156eec2580b8b6700ab057f5f1f881de3f` · USDC `0xf570bdf2c44760e5a6d8879c4244c9225cac7e9772e7bbb585b1522bd0519356` · USDT `0x51a1aafacac4c30de964a44aa593e2bced9a000950fba0731d7c889f9470e14d` |
| Operator revocation tx (post-hack, set WETH approval to 0 for a helper) | `0x9f4dafa20387964cdfc8dc2b26e927f660f5fb79edde20dfff862c574da18e35` |
| Real tokens drained | WETH `0xC02aaa39b223FE8D0A0e5C4F27eAD9083C756Cc2`, USDC `0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48`, USDT `0xdAC17F958D2ee523a2206206994597C13D831ec7` |

#### The 66 child wrapper contracts (callees in the sweep array)
NOTE: only the first 10 are listed here; all 66 are present in the sweep tx
calldata and reconcile. First 10:
```
0x68ca6a0c6db92bf2d4424c7c9fba8655992187c6
0x4ee0b6e9f9c4886beeef2ebd7fc27223169531ce   <- reporting named this one as holding a ~92 WETH allowance until the sweep
0x757230bd24489b8d8817f4ff8e5a35ebeb3dde39
0x4db09fdce399f331775187bd81e9ecdfe179454a
0xa61d15479e0aee1fca32fb0f4f9865102d13b7c8
0x33eaf8c1daca2be5f28d556c91d97bfb947fc027
0x32ed8c7512a4766ac0aaab4a26a25519159d00a2
0x4556deb2280ca13e5e5109efc0ce5d89ca8ea183
0x5b646681cf3d4ed2ed1d93d3627ab6f1374e22fc
0x69216c47c5aab95f0f90db3ffa8d16970506ad0e
```

### Cash-out / fund movement
No discrete on-chain cash-out addresses were recorded in this report. The swept assets
(1,474.58 WETH, ~2.87M USDC, ~2.04M USDT) were swapped to ~4.4K ETH and partially
laundered through Tornado Cash; no specific bridge, consolidation wallet, mixer-deposit,
or exchange endpoint address is recorded here.

---

## Mechanism — what the bytecode actually showed

### The sweep tx (`0x2be8…3e65`)
- Type-2 tx from attacker EOA `0x3e37f4…` to coordinator `0xb84db0…8df52`.
- Selector `0xc269a509`, signature `f(address[] children, address arg)`.
- `children` = 66 child wrappers; `arg` = `0x1f2f10…` (the victim/source).
- Event log: 16 WETH transfers each **exactly 92.161407687812186112 WETH**
  (byte-identical → fixed allowances drained whole, NOT traded amounts),
  plus ~20 USDC at 143,528.656384 each and ~9 USDT at 149,488.051712 (+1 partial).
  All `from 0x1f2f10… to 0x3e37f4…`.

### The child wrapper (`0x68ca6a0c…87c6`, representative of all 66)
- A "Few"-style ERC-20 **wrapper token** (real wrap/unwrap), owner-gated by
  `tx.origin == owner`. Looks legitimate to a quick scan — by design.
- Slot layout: slot 7 = underlying `token()`; **slot 10 = strategy/oracle**.
- Its `wrap` path: `if (strategy != 0) { if (strategy.4e69d560()) {armed branch}
  else {benign} ; underlying.transferFrom(caller -> this) }`.
- The child NEVER calls `approve` on principal in the trade path. It pulls via
  `transferFrom` against the bot's **pre-existing** approval to the wrapper.
- Slot 10 points to `0xb84db0…8df52` (the coordinator). So the
  coordinator is ALSO the oracle every child consults.

### The orchestrator/oracle (`0xb84db0…8df52`)
- `4e69d560()` returns `bool`: **`return (block.number == slot1)`**. This is the
  "armed" flag the children branch on. True only in the exact block whose number
  was stored in slot1.
- `c269a509(children, arg)` (the sweep): writes `slot1 = block.number` (arms for
  THIS block), then loops the children calling each child's withdraw
  (`0x51cff8d9`) → each child does `transferFrom(victim -> attacker, allowance)`.
- Also pays `block.coinbase` (Flashbots-style bundle tip) in the arming/sweep
  paths → submitted as private bundles.
- `Ownable`; setters gated by `tx.origin == owner`.

### Why the loop over 66 (not children calling in)
`transferFrom` checks `allowance[victim][msg.sender]`. The bot approved the
**child wrappers**, not the orchestrator. So each child must be the `msg.sender`
of its own `transferFrom`. The orchestrator has zero allowance itself; it must
reach into each child and trigger it. Hence the 66-way loop.

### Why "block.number == armedBlock"
It's a **simulation-vs-execution divergence primitive**. A bot simulates its
bundle at a different block (pending/N) where `4e69d560` returns false → child
looks benign → bot's profit check passes → bot fires. At real inclusion the
attacker's tx sets `slot1 = block.number` first, so `4e69d560` is true and the
child's armed branch engages. Auto-disarms after the block (no cleanup, no
visible "armed" window). Invisible to pre-trade simulation because the armed
state only exists transiently inside the attacker's own tx.

This RETIRES earlier wrong hypotheses: not a size threshold, not block.coinbase
detection, not reentrancy-forced approve, not a persistent manually-flipped flag.

---

## How approvals accrued
- Unarmed wrapper = genuinely functional. Over time the bot did real, small,
  profitable wrap/route trades against the 66 fakes and (as normal bot behavior)
  granted/refreshed ERC-20 approvals to each wrapper on the real tokens.
- Early: approvals consumed by the matching trade (residual ~0) → looks clean.
- Later: routes engineered so approval > consumed → standing residual persists
  (ERC-20 allowances don't expire). Residuals accumulate to the 16×92.16 WETH
  (+ stablecoins) ceilings that got swept.
- Drain itself = one tx; the *fuel* (allowances) was laid down across many txs
  over (reportedly) several weeks.

---

## Open question #1 — is the arm flag load-bearing?  → RESOLVED (see Resolution section above)
**Verdict: load-bearing for the CONDITIONING phase, vestigial for the SWEEP.** The sweep
has zero `4e69d560`/`086f6f56`; the bot's conditioning tx `0xa2c9d0a1…` hits
`4e69d560` 32× (all `true`) with the attacker arming at idx 0 of the same block. Details +
evidence above. Original framing of the question retained below for reference.

For the realized theft (sweeping already-accrued allowances), the flag does
NOTHING — `c269a509` never reads `4e69d560`; the drain works regardless. The flag
only matters if the child's ARMED branch does something fund-moving that had to
be hidden from the bot's simulation (e.g. fresh in-block bait trades), and the
bytecode alone did not prove a fund-moving difference between armed/unarmed
(armed extra call `086f6f56` just `SSTORE`s an amount that the drain path does
not appear to read).

**DECIDING EVIDENCE:** does the SWEEP BLOCK contain bot `wrap` txs hitting the
armed branch before the sweep? The sweep tx call tree decides it:
- Only `c269a509` -> 66x child `51cff8d9` -> `transferFrom`, no `wrap`/`4e69d560`
  activity → flag was VESTIGIAL for the realized attack (user's instinct correct).
- Bot `wrap` calls hitting `4e69d560`/`086f6f56` before the loop → flag was a
  real sim-divergence guard (load-bearing).

Child slot 10 at a PRE-sweep block confirms the oracle was set then (it may be
zeroed now).

---

## Open question #2 — the accrual curve  → RESOLVED (see Resolution section above)
**Resolved in full.** Conditioning ran blocks 25354425–25360695 (~21 h, ending at the sweep
block 25360696), NOT in the guessed 25,360,696–25,385,112 window — that window is *entirely
post-sweep* (the sweep is the FIRST tx of block 25360696), which is why it only showed
cleanup. Full accounting reconciles to the wei (WETH/USDC allowance-bound; USDT balance-bound).
Why the old guess failed is preserved below.

The real conditioning approvals were initially missed. Blocks
25,360,696–25,385,112 (an earlier guessed CAMPAIGN_START) hold only
POST-exploit activity (June 22–24): 357 zero-value revocations + 174 max
approvals + ~77 small trades, 0 to the 66 children, 0 at the 92.16 ceiling.
=> Wrong era. The conditioning happened BEFORE that window.

**What the record shows:** across all 66 children, each child's full grant history —
each grant a `(value, blockNumber, timeStamp)` — resolves the accrual. The earliest
grant marks the true CAMPAIGN_START. Netting each grant's approval against the matching
`Transfer` consumption (owner → child) gives consumed-vs-standing per grant: early grants
~100% consumed, later grants ~0% consumed, standing total climbing to 1,474.58 WETH.
Child deployment times bound the campaign.

### Useful constants
- Approval(owner,spender,value) event signature = `0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925`
- Transfer(from,to,value)      event signature = `0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef`
- The 92.16 WETH ceiling, raw wei = `92161407687812186112`
- USDC per-entry swept = `143528656384` (6 dp = 143,528.656384)
- USDT per-entry swept = `149488051712` (6 dp = 149,488.051712)

---

## Confidence notes
- Addresses, the 92.16×16 reconciliation, slot10→coordinator, and
  `4e69d560 = (block.number == slot1)` are confirmed directly on-chain — solid.
- **NOW PROVEN (was inference):** the flag is a sim-divergence guard — the bot's
  conditioning tx `0xa2c9d0a1…` reads `4e69d560` 32× (all `true`) and runs the armed
  branch; attacker arms at idx 0 of the same block; flag auto-disarms. The flag does
  nothing in the sweep (0 occurrences anywhere in it).
- **NOW PROVEN (was inference):** the per-grant accrual — the full `Approval`/`Transfer`
  history reconciles standing → swept to the wei (WETH 1,474.582523 / USDC 2,870,573.127680;
  USDT balance-bound to 2,035,760.155871). Withdraw pulls `min(allowance, balance)` to
  `owner()` — source-confirmed.
- **NOW PROVEN by matched-pair (was the last inference):** the armed flag is the lever that
  creates the standing residual. Two near-identical operator→bot txs for child `0x4ee0b6e9`,
  7 blocks apart, ~92.16 WETH approve each:
  - `0x085ec144…` (blk 25360512, **UNARMED** `4e69d560=false`): approve 92.159379 → wrap
    pulls 92.159379 → **standing 0**.
  - `0x85609286…` (blk 25360519, **ARMED** `4e69d560=true`, `086f6f56` ran 13×): approve
    92.160059 → wrap pulls **0** → **standing 92.160059**.
  So under armed state the bot's approval is NOT consumed by the wrap and is left standing;
  the sweep collects it. The bot's pre-trade simulation runs against unarmed state (residual
  would be 0 → looks safe). FULLY RESOLVED (see "arming mechanism" section): the armed wrap
  takes the `086f6f56` store-branch *instead of* `transferFrom`, so it skips the pull; and the
  determinant is intra-block ordering — the arm tx must front-run the bot's wrap tx (arm at
  idx 0 vs bot at idx 2 in the dangling block; arm at idx 58 vs bot at idx 5 in a block that
  consumed). No residual inference remains on this point.
- Reconciliation figures below come from the full `Approval`/`Transfer` event history, netted per child against each allowance.

---

## X thread — the attack in 5 steps (shareable narrative)

> All facts below are reconstructed on-chain; numbers reconcile to the wei. Where the public
> narrative and our measurements differ, the measured figure is used and noted.

**1/** JaredFromSubway — the most active sandwich bot on Ethereum — was drained ~$15M on
Jun 20 2026. Not a leaked key. Not a contract bug. A counter-MEV **honeypot** that turned the
bot's own safety machinery against it. Here's the play, step by step.

**2/** Setup = patience. The attacker deployed 66 fake "Few"-style wrapper tokens (22 each for
WETH/USDC/USDT) that act like *real* wrappers. The bot routed through them, did real
profitable-looking wraps, and — as normal bot behavior — **granted them ERC-20 approvals**.
Trust, earned. (Reported as weeks of grooming; the approval-conditioning we can prove on-chain
ran the final ~21h.) The goal of all this: get the bot to leave a **dangling approval** — an
allowance it grants but never spends — that can later be swept with `transferFrom`.

**3/** Why that's hard: MEV bots are *paranoid by design*. Every trade is **simulated first**,
and a **profit check** gates execution — the bot only fires if the simulation says it profits.
That's a classic **TOCTOU** gap (time-of-check ≠ time-of-use). To beat it you must make the
**simulation** and the **real execution** disagree.

**4/** The primitive that creates the drift: every fake wrapper consults a flag on the
attacker's oracle — `4e69d560() == (block.number == slot1)`. In the bot's simulation (run
against an *earlier* block) the flag reads **FALSE** → the wrapper behaves normally → the wrap
**pulls** the approved tokens → residual 0 → profit check passes → bot submits. Looks totally
safe.

**5/** At real execution the attacker **flips the switch**: a tiny tx writes `slot1 =
block.number`, so the *same* wrap now reads the flag **TRUE** → takes the "armed" branch →
**stores instead of pulls** → the approval is **left standing**. The flag **auto-disarms** the
very next block, so there's no lingering "armed" state for the bot or mempool watchers to spot.
It must also be done **fast**, before anyone notices the irregularity.

**6/** Catch: the switch tx must land **before** the bot's wrap **in the same block** — a
front-run. So the attacker compressed the whole endgame into **<1 hour: Jun 20, 17:55–18:50
UTC**, firing **10 flag-switching txs**, each racing to the **top of the block** ahead of the
bot.

**7/** How it wins the race — *not* a gas auction. The switch tx pays **0 priority fee**, yet
lands at index 0 above the bot's 7.4-gwei tx. It wins by **bribing the block builder directly
via `block.coinbase`**, escalating the bribe from **0.00001 ETH → 0.025 ETH**. A builder
maximizes block value, so 0.025 ETH outbids the bot's ~0.0179 ETH priority → attacker first.

**8/** But a coinbase bribe only wins if your bundle lands in a block **your targeted builder
actually builds**. All **5 successful front-runs were Titan blocks**; the lone 0.025-ETH bribe
that landed in a **Quasar** block (25360511) *missed* — arm fell to idx 6, bot wrapped first,
approval consumed normally.

**9/** Endgame: once enough standing allowances were armed, **one sweep tx** drained them via
`transferFrom` → **1,474.58 WETH (16×92.16) + 2.87M USDC + 2.04M USDT**, straight to the
attacker. Reconciles to the wei. Builder tips spent: a few hundred dollars. Haul: ~$15M.

**10/** The irony: the bot's **profit-check simulation** — the very thing that keeps it safe —
is exactly what got weaponized. The honeypot never "broke" the bot. It made the bot's own
simulator **lie to it**. Defense takeaway: simulate against the *exact* inclusion state, and
treat any contract whose behavior depends on `block.number`/builder-ordering as hostile.
