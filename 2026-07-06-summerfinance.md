# Summer.fi (Lazy Summer Protocol) Fleet Commander Accounting Exploit — July 2026

**Report date:** 2026-07-07
**Incident date:** 2026-07-06
**Target:** Summer.fi — Lazy Summer Protocol, the `FleetCommander` USDC yield vaults (`@summerfinance_`)
**Loss:** attacker netted ≈ 6,016,755 DAI (≈ $6.0M); financed by a 65,419,171.88 USDC flash loan; public reports say ~$6M on a ~$65.4M flash loan
**Category:** Smart-contract exploit — ERC-4626 share-price manipulation. The vault prices shares off the spot valuations its Arks report for positions in shared lending markets; those valuations are manipulable inside a single transaction, so the attacker deposited at one NAV and redeemed at a ~9.5% higher NAV in the same transaction.
**Chain:** Ethereum mainnet (block 25,471,348, tx index 0)
**Status:** Summer.fi paused all Lazy Summer Protocol vaults. Attacker swapped the proceeds to DAI in-transaction, then converted DAI→ETH in small tranches over the following day (Uniswap V2). No full public post-mortem from Summer.fi at the time of writing.

> Scope note: This is an internal reference report. The exploit transaction, the flash-loan structure (§3.2), the call sequence (§3.3), the deposit/redeem share prices (§3.4), the per-address value flow (§4), and the laundering path (§5) were reconstructed first-hand from on-chain data on 2026-07-07, cross-checked against Summer.fi's verified `FleetCommander` source. Those findings are first-hand and reproducible. The root-cause reading (§3.5) is grounded in Summer.fi's own verified `FleetCommander`/`FleetCommanderCache`/`Ark` source. Off-chain context — the ~$6M headline, the "$7.14M inflated Ark" figure, detection by Blockaid/PeckShield/CertiK/GoPlus, and the vault pause — is as reported by public sources and is flagged where it goes beyond what the chain shows. One finding differs from the headline and is called out explicitly: FleetCommander_A's *resting* net asset value was essentially unchanged before and after the transaction (§3.6), so the extracted value came out of the shared underlying lending markets, not the vault's standing balance.

---

## 1. Executive summary

On 2026-07-06 at 05:17:59 UTC an attacker drained roughly $6.0M in a single Ethereum transaction (`0x0db528c4…da12`) targeting Summer.fi's Lazy Summer Protocol. Lazy Summer's core vault contract is the `FleetCommander`, a standard-looking ERC-4626 vault. It does not hold user deposits idle; it spreads them across a set of adapter contracts called **Arks**, each of which parks the vault's assets in an external yield venue (Morpho Blue markets, Morpho V2 vaults, Spark, Silo). The vault's share price is `totalAssets / totalSupply`, and `totalAssets` is the sum of what every Ark *reports* it is currently worth.

That reported worth is the weak point. Each Ark values its position at the spot exchange rate of the underlying market it sits in. Those rates can be pushed around inside one transaction with borrowed capital. The attacker took a 65.4M USDC flash loan from Morpho Blue, used part of it to distort the Morpho markets that back several of the vault's Arks, deposited 64,828,534.99 USDC into the `FleetCommander` while the reported NAV was at one level, pushed the reported NAV higher, and then redeemed for 70,959,584.46 USDC. Deposit and redeem happened in the same transaction at effective share prices of 1.0665 and 1.1678 respectively — a ~9.5% move on ~$65M, which is the ~$6.1M gross gain on that leg.

The redemption is what turns the paper gain into real money. `FleetCommander.redeem` routes through `redeemFromArks`, which computes the payout from the (inflated) reported NAV and then force-withdraws that many assets from the Arks. The Arks satisfy the withdrawal by pulling USDC out of the shared underlying lending markets at the manipulated rates. So the vault behaved as a conduit: it over-withdrew from the pooled markets and handed the surplus to the redeemer.

A detail worth stating plainly because it complicates the "Summer.fi lost $6M" framing: on-chain, FleetCommander_A's resting NAV was 0.422763 USDC/share both immediately before and immediately after the transaction, and its assets were ~$4.04M on both sides. The vault's standing balance did not fall by $6M. The $6M was net-withdrawn from the underlying markets the Arks share with other suppliers (Morpho Blue markets ≈ −$4.60M, a Spark/`spUSDC` position ≈ −$1.29M, an `sUSDS` position ≈ −$0.14M in stablecoin terms). Whether the ultimate loss lands on other Summer Arks that supply those same markets or on unrelated third-party suppliers depends on each market's socialization and is not fully resolvable from this one transaction's logs; §3.6 states what is and isn't provable.

The exploit used only permissionless user functions (`deposit`, `redeem`/`redeemFromArks`, `withdrawFromArks`, `withdrawFromBuffer`). No admin key, no keeper-gated `rebalance`, no signature. The `FleetCommander` verifier-equivalent — its ERC-4626 math and its `FleetCommanderCache` — executed exactly as written. The flaw is that "as written" trusts a share price that a flash loan can move.

---

## 2. Timeline (2026-07-06, UTC; on-chain verified unless noted)

| Time | Event |
|---|---|
| Jul 06 04:12:59 | Attacker EOA `0x7BF716…BDCa` deploys / prepares contracts (block 25,471,024; first of two contract-creation transactions). |
| Jul 06 05:16:23 | Second setup transaction from the attacker EOA (block 25,471,340). |
| Jul 06 05:17:23 | A dry-run call to the attack contract `0x0514F8…FC61` (block 25,471,345, one block-group before the main run). |
| Jul 06 05:17:59 | **Exploit transaction** `0x0db528c4…da12` lands (block 25,471,348, tx index 0): nested Morpho flash loans, market manipulation, deposit + redeem on FleetCommander_A and _B, flash-loan repayment, and USDC→DAI swap, all in one transaction burning 14,989,254 gas across 305 logs. |
| Jul 06 (shortly after) | Blockaid flags the transaction; PeckShield, CertiK, and GoPlus Security also report it *(as reported)*. |
| Jul 06 (same day) | Summer.fi pauses all Lazy Summer Protocol vaults *(as reported)*. |
| Jul 07 01:38–03:47 | Attacker EOA approves DAI and executes a long series of `swapExactTokensForETH` calls through the Uniswap V2 router `0x7a25…488D`, converting the ~6M DAI to ETH in small tranches (several intentional-looking reverts interspersed). |

---

## 3. Attack vector and root cause

### 3.1 The system

Verified Summer.fi contracts involved (all source-verified):

- **`FleetCommander`** — the Lazy Summer vault, an ERC-4626 (`deposit`/`mint`/`withdraw`/`redeem`). Two instances were touched: the primary **FleetCommander_A** `0x98C49e13bf99D7CAd8069faa2A370933EC9EcF17` and **FleetCommander_B** `0xE9cDA459bED6dcfb8AC61CD8cE08E2D52370cB06`. Both use 6-decimal shares over 6-decimal USDC.
- **Arks** — adapter contracts holding the vault's assets in external venues. Seen here: `BufferArk` (idle-USDC buffer, one per FleetCommander: `0x106cbb…dd2b`, `0xeb60a8…0d9d`), several `MorphoV2VaultArk` (`0xd00c16…400b`, `0x81f025…0b25`, `0xd0aadd…958f`), a `SparkArk` (`0x8948a5…062f`), a `SiloManagedVaultArk` (`0x61d706…76c2`), and an `ERC4626Ark` (`0xfd8993…8519`).
- **`Strategy`** — a Yearn-style tokenized strategy wrapper (`0xA9ca49…A9c4`, proxy → `0xbb5127…fed0`), whose `deployFunds(uint256)` was used for a small probe deposit into FleetCommander_A.

External protocols the Arks touch, and that the attacker manipulated:

- **Morpho Blue** `0xBBBBBbbBBb9cC5e90e3b3Af64bdAF62C37EEFFCb` — supplied both the flash loan and the lending markets that were distorted.
- **`MorphoMarketV1AdapterV2`** contracts (`0x9414a4…e001`, `0x1d5118…2902`, `0xcc0f95…8b41`) fronting Morpho V2 vaults whose share tokens are named `Api3CoreUSDC`, `KPK_USDC_Prime`, `skyMoneyUsdcRiskCapital`, `gtUSDC` (Gauntlet), and `AVGUSDCcons`.
- **Spark / `spUSDC`** (`0x377c3b…4815`) and **`sUSDS`** (`0xa3931d…7fbd`) positions reached via the SparkArk and Morpho arks.

### 3.2 The flash-loan wrapper

The whole operation is one call from the attacker EOA to the attack contract's `attack(address[])` (selector `0x6624ef70`), passing the list of vaults/arks to hit. Inside, the attack contract calls Morpho Blue's `flashLoan(address,uint256,bytes)` (`0xe0232b42`); Morpho calls back `onMorphoFlashLoan(uint256,bytes)` (`0x31f57072`) on the attack contract, and *all* exploit logic runs inside that callback. A second Morpho `flashLoan` is nested inside the first callback. The outer loan of 65,419,171.88 USDC is repaid in full and at zero fee in the same transaction (Morpho Blue flash loans are free), so the loan nets to zero — it is pure temporary capital.

### 3.3 The call sequence

Inside the flash-loan callback, with contracts and selectors labeled:

```
attack()                                                    // 0x6624ef70
└─ MorphoBlue.flashLoan  → onMorphoFlashLoan
   └─ MorphoBlue.flashLoan → onMorphoFlashLoan              // nested
      ├─ [manipulate]  repeated internal helper 0x414f3e80:
      │     MorphoMarketAdapter.supply → MorphoBlue.supply  (0xa99aad89)
      │     MorphoBlue.accrueInterest  (0x151c1ade)
      │     MorphoMarketAdapter.deallocate (0x4e45f1ff) → MorphoBlue.withdraw (0x5c2bea49)
      │   …run against the api3 / kpk / sky Morpho markets…
      ├─ FleetCommander_B.deposit → BufferArk_B.board (0x2db6d399)
      ├─ FleetCommander_B.withdrawFromArks (0xa039e944) → MorphoV2Ark.disembark (0x13c408f8)
      ├─ Strategy.deposit → Strategy.deployFunds (0x503160d9) → FleetCommander_A.deposit → BufferArk_A.board
      ├─ FleetCommander_A.deposit  → BufferArk_A.board       // the 64.83M deposit
      ├─ FleetCommander_A.redeem   → redeemFromArks:         // the 70.96M redeem
      │     MorphoV2Ark2.disembark, SparkArk.disembark, MorphoV2Ark3.disembark, BufferArk_A.disembark
      ├─ FleetCommander_B.deposit  → BufferArk_B.board       // the 29.52M deposit
      └─ FleetCommander_B.withdrawFromBuffer (0x5f538f6f) → BufferArk_B.disembark   // 29.92M out
   (repay both flash loans)
CurveRouter.exchange  → Curve 3pool  (USDC → DAI, the profit)
```

Selectors match the verified `FleetCommander` source (`board(uint256,bytes)`→`0x2db6d399`, `disembark(uint256,bytes)`→`0x13c408f8`, `deposit(uint256,address)`→`0x6e553f65`, `redeem(uint256,address,address)`→`0xba087652`, `withdrawFromArks(uint256,address,address)`→`0xa039e944`, `withdrawFromBuffer(...)`→`0x5f538f6f`).

### 3.4 The core round-trip — deposit low, redeem high, same transaction

The load-bearing evidence is the share mint/burn against the USDC moved, on FleetCommander_A:

| Step | USDC | Shares (6-dec) | Effective price (USDC/share) |
|---|---|---|---|
| Deposit (log #207–208) | 64,828,534.99 in | 60,787,156.81 minted | **1.06648** |
| Redeem (log #270–271) | 70,959,584.46 out | 60,766,209.13 burned | **1.16775** |

The attacker kept the ~20,947-share difference (worth a few thousand USDC) and sent it to the EOA afterward. The share price the vault used moved from 1.0665 at their deposit to 1.1678 at their redeem — **+9.49% inside one transaction** — which on the ~$65M principal is the ~$6.1M gross gain on this leg. A smaller repeat on FleetCommander_B (deposit 29,517,258.14, redeem 29,916,430.38) added ~$0.40M gross.

For reference, the vault's *undisturbed* share price is 0.422763 (§3.6). The attacker did not need any particular absolute price — only for the redeem price to sit above their own deposit price, which the manipulation guaranteed.

### 3.5 Root cause — a share price the caller can move between deposit and redeem

`FleetCommander.deposit` prices shares with `previewDeposit(assets)` and `redeem` with `previewRedeem(shares)`. Both derive from `totalAssets()`, and in this vault:

```
totalAssets() = Σ over arks of Ark.totalAssets()      // FleetCommanderCache._sumTotalAssets
```

`Ark.totalAssets()` is `virtual` (base `Ark.sol`), and each concrete Ark implements it by reading the *spot* value of its position in the underlying venue — e.g. a `MorphoV2VaultArk` reads what its Morpho-vault shares are currently worth. Those spot valuations are exactly what an attacker with flash-borrowed capital can inflate or deflate for the duration of a transaction, by supplying to / withdrawing from the underlying Morpho markets and forcing interest accrual (the `supply` / `accrueInterest` / `deallocate`→`withdraw` cycles in §3.3). Move the Arks' reported worth and you move the `FleetCommander` share price directly.

**Why the cache does not save it.** Summer.fi anticipated that `totalAssets()` gets read several times per operation and built `FleetCommanderCache` to snapshot the summed value into transient storage at the start of each deposit/withdraw and flush it at the end (`useCache` / `useWithdrawCache` modifiers). The contract's own comment states the assumption baldly: *"Assumes no changes in total assets throughout the execution of function that use this cache."* That assumption only makes a **single** call self-consistent. It does nothing across calls: the deposit call caches and flushes one snapshot, and the later redeem call — a separate top-level call in the same transaction — caches and flushes a fresh, higher snapshot. The cache is a gas optimization, not a manipulation guard, and there is no TWAP, no oracle, and no per-account price memory to stop a deposit and a redeem in the same transaction from clearing at two different NAVs.

**Why the paper gain becomes cash.** `redeem` → `redeemFromArks` computes `totalAssetsToWithdraw = previewRedeem(shares)` from the inflated NAV, then calls `_forceDisembarkFromSortedArks(totalAssetsToWithdraw)`, which withdraws that many assets from the Arks in ascending-balance order. The Arks satisfy it by pulling USDC out of the underlying markets at the manipulated rates. So the vault realizes the inflated number against pooled liquidity and pays it to the redeemer. This matches the public description of the flaw — "abused trust between the parent vault Fleet Commander and an Ark strategy contract," with the Ark's reported assets inflated to ~$7.14M *(reported figure; the chain shows ~$5.58M of USDC pulled from the yield Arks into the vault during the redeem, on top of ~$65.32M returned by the buffer)*.

**In one line:** the vault honors deposits and redemptions at a share price computed from spot, manipulable, cross-call-inconsistent Ark valuations, and its redeem path force-realizes that manipulated price against shared market liquidity.

### 3.6 What the chain proves about *where* the money came from

FleetCommander_A's resting state at the block boundaries (no transient cache in play):

| | block 25,471,347 (before) | block 25,471,348 (after) |
|---|---|---|
| `totalAssets()` | 4,041,039.91 USDC | 4,041,039.98 USDC |
| `totalSupply()` | 9,558,641.05 shares | 9,558,641.09 shares |
| price | 0.422763 | 0.422763 |

The vault's resting balance and share price are unchanged; the manipulation was fully unwound by the end of the transaction, and its BufferArk held ~0 USDC on both sides (the Arks hold value as underlying-vault share tokens, not raw USDC). So the ~$6M did **not** come out of FleetCommander_A's standing assets. Netting every stablecoin (USDC/DAI/USDS/USDT ≈ $1) across the transaction by address shows where it did come from:

| Net (USD-equiv.) | Address |
|---|---|
| **+6,016,755** | Attacker EOA `0x7BF716…BDCa` (realized as DAI) |
| −4,601,853 | Morpho Blue markets |
| −1,294,221 | Spark / `spUSDC` position `0x377c3b…4815` |
| −140,644 / −140,569 | two `sUSDS`-linked positions |
| small | buffer seed dust, Curve swap fee |

The extracted value was net-withdrawn from the shared underlying lending markets, realized through the redeem's force-disembark at manipulated rates. This is consistent with Summer.fi pausing *all* Lazy Summer vaults (the exploited flaw is in the shared `FleetCommander` accounting, and other vaults/Arks supply the same markets), while also explaining why FleetCommander_A's own NAV did not visibly drop. What this transaction's logs cannot settle is the split of the −$6M between other Summer-operated Arks that supply those markets and unrelated third-party suppliers; that needs each market's full supplier set, not just this transaction. The exploited *flaw*, however, is unambiguously in the `FleetCommander` share-price accounting.

### 3.7 Ruled out (on-chain evidence)

- **Admin/keeper compromise:** none. Only permissionless functions were called (`deposit`, `redeem`→`redeemFromArks`, `withdrawFromArks`, `withdrawFromBuffer`, and the `Strategy.deployFunds` wrapper). The keeper-gated `rebalance`/`forceRebalance` never appear.
- **A broken/forged verifier or math bug in ERC-4626:** none. The mint/burn amounts (§3.4) are internally consistent with the NAV the vault held at each moment. The math did what it should; the input NAV was manipulated.
- **Loss from FleetCommander_A's standing TVL:** ruled out by §3.6 (NAV unchanged).
- **Oracle-price manipulation of USDC itself:** not involved; the manipulation was of the Arks' spot position valuations in the underlying lending markets, not of a price feed.

---

## 4. On-chain accounting (independently verified)

> All figures below are on-chain values from the exploit transaction — its 305 emitted events and the ERC-20 `Transfer` flows across it, with contract identities from their verified source. As of 2026-07-07.

### 4.1 The USDC round-trip (log order, ≥ $100k)

- Flash loan in: Morpho Blue → attack contract **65,419,171.88 USDC** (log #5); repaid exactly (log #293), zero fee.
- Seed the underlying markets (flash capital → Morpho market adapters → Morpho vault tokens): ~0.97M into `Api3CoreUSDC`, ~3.03M into `KPK_USDC_Prime`, ~0.28M into `skyMoneyUsdcRiskCapital`.
- **FleetCommander_A deposit:** attack → FleetCommander_A **64,828,534.99 USDC** → BufferArk_A (logs #207–211).
- Arks disgorge into FleetCommander_A ahead of the payout: ~5.58M from `gtUSDC`/`Api3CoreUSDC`/`spUSDC`/`KPK_USDC_Prime`-backed arks + 65.32M returned by BufferArk_A (logs #243–268).
- **FleetCommander_A redeem:** FleetCommander_A → attack **70,959,584.46 USDC** (log #271).
- **FleetCommander_B leg:** deposit 29,517,258.14, redeem 29,916,430.38 (logs #275–286).
- Profit out: attack → CurveRouter **6,018,729.94 USDC** → Curve 3pool → DAI (logs #296–297).

### 4.2 Net result

| Leg | Gross |
|---|---|
| FleetCommander_A: redeem − deposit | +6,131,049.47 USDC |
| FleetCommander_B: redeem − deposit | +399,172.24 USDC |
| Subtotal (gross vault extraction) | +6,530,221.71 USDC |
| less cost of seeding/unwinding the underlying markets + Curve swap slippage | ≈ −513,000 |
| **Net to attacker EOA (realized)** | **≈ 6,016,755 DAI (≈ $6.0M)** |

The realized figure (6,016,755 DAI leaving to the EOA) is the firm number; the leg breakdown reconciles to it within the manipulation's frictional cost.

---

## 5. Laundering

In-transaction, the ~6.02M USDC profit was swapped to DAI through a Curve router into the Curve 3pool, so the attack transaction ended with the attacker holding DAI rather than USDC (a common freeze-avoidance move, since USDC issuer blocklisting is faster than DAI). Over the next day (2026-07-07, 01:38–03:47 UTC) the attacker EOA approved DAI and made a long run of `swapExactTokensForETH` calls through the Uniswap V2 router `0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D`, converting the DAI to ETH in many small tranches (a few reverted, consistent with slippage-bounded scripted swaps). Onward movement past ETH is out of scope here.

---

## 6. Root-cause summary and remediation

**Root cause.** An ERC-4626 vault (`FleetCommander`) whose share price is the sum of its Arks' *spot* valuations of positions in shared, flash-manipulable lending markets, with no defense against a caller moving that price between a deposit and a redeem in the same transaction. The `FleetCommanderCache` only enforces intra-call consistency (and says so), not intra-transaction consistency across separate deposit and redeem calls.

**What would harden it (standard mitigations for this class):**

- **Break the atomic deposit↔redeem round-trip.** A minimum holding period / same-block deposit-then-withdraw guard removes the entire primitive: you cannot redeem at a repriced NAV in the transaction you deposited.
- **Do not price shares off spot Ark valuations.** Value Arks at a manipulation-resistant measure — a smoothed/TWAP NAV, or "book" values that only move on keeper-driven rebalances/harvests rather than on live underlying exchange rates — so a flash loan cannot move the vault's share price at all.
- **Bound single-transaction NAV movement / large redemptions.** Reject a deposit or redemption when the vault's computed NAV has moved beyond a small tolerance versus a trusted reference, or cap the redeemable fraction per block.
- **Re-examine the redeem realization path.** `_forceDisembarkFromSortedArks` realizes the *reported* payout against pooled liquidity; it should reconcile requested vs. actually-realized assets and refuse to pay out more than the position genuinely yields on withdrawal.

**Broader lesson.** A per-transaction cache built for gas can read like a safety mechanism. It is not one. "Consistent within a call" and "not manipulable within a transaction" are different properties; only the second protects an ERC-4626 vault whose inputs are live, shared market prices.

---

## 7. Indicators (addresses & identifiers)

### 7.1 Attack

| Role | Address / value | Controlled by |
|---|---|---|
| Exploit transaction | `0x0db528c44f23fc7fa4544684a2fab81096450a14aae8bc89f42cd0592d43da12` | attacker-executed |
| Block | 25,471,348 (tx index 0), 2026-07-06 05:17:59 UTC | — |
| Attacker EOA | `0x7BF716167B48CF527725722C6d79494b45B3BDCa` | attacker-exclusive |
| Attack contract (unverified) | `0x0514F827C129C16418a0933E03C99A6AF982FC61` | attacker-exclusive |
| FleetCommander_A (primary) | `0x98C49e13bf99D7CAd8069faa2A370933EC9EcF17` | Summer.fi vault (victim) |
| FleetCommander_B | `0xE9cDA459bED6dcfb8AC61CD8cE08E2D52370cB06` | Summer.fi vault (victim) |
| Strategy wrapper | `0xA9ca4909700505585B1ad2a1579DA3b670FFA9c4` | third-party wrapper, used as a deposit path |
| BufferArk_A / _B | `0x106cbb1f445f0bffa7894f4199ee940bf7f6dd2b` / `0xeb60a8e747d73c58ccc320bcdabb166f8a0c0d9d` | Summer.fi Arks (victim) |
| MorphoV2VaultArks | `0xd00c168451fddd8ef839e5c0f5b9666143d9400b`, `0x81f025c87367033d87b6d3a95289b36106770b25`, `0xd0aadde147b6d683cbb80bfe0fb9e8db9de1958f` | Summer.fi Arks (victim) |
| SparkArk / SiloManagedVaultArk / ERC4626Ark | `0x8948a5f3d24f7a6d50ff36064e8cff33b2af062f` / `0x61d7063041d83c8ca3e42c39181dfd14b3bc76c2` / `0xfd899321b1fd8d75e255119766d9097c98568519` | Summer.fi Arks (victim) |
| Morpho market adapters manipulated | `0x9414a42eab4580c042b18def4d37372a7881e001`, `0x1d511811aca9d8817a3e50f29cadff6243a02902`, `0xcc0f95e65d2ce7fb715bfb418bf61314d0878b41` | shared Morpho infrastructure |
| Flash-loan source | Morpho Blue `0xBBBBBbbBBb9cC5e90e3b3Af64bdAF62C37EEFFCb` | shared Morpho infrastructure |

### 7.2 Cash-out / fund movement

| Role | Address / value | Note |
|---|---|---|
| In-transaction profit swap (USDC→DAI) | Curve 3pool `0xbEbc44782C7dB0a1A60Cb6fe97d0b483032FF1C7` | public AMM, commingled; converted the ~6.02M USDC profit to DAI inside the exploit transaction |
| DAI→ETH cash-out (next day) | Uniswap V2 router `0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D` | public router, commingled; the attacker EOA cashed the ~6M DAI out to ETH in small tranches on 2026-07-07 (01:38–03:47 UTC) |

The proceeds moved back to the same attacker EOA (`0x7BF716…BDCa`) as ETH. No bridge, mixer, consolidation wallet, or exchange deposit endpoint was traced; onward movement past ETH is out of scope.

## 8. Sources

Public reporting (figures and attribution as reported; re-verify before external citation):

- The Block — "Summer Finance exploited for $6 million; analysts point to flash loan attack": https://www.theblock.co/post/407198/summer-finance-exploited
- CoinDesk — "DeFi protocol Summer.fi halts Lazy Summer vaults after $6 million exploit": https://www.coindesk.com/web3/2026/07/06/defi-protocol-summer-fi-halts-lazy-summer-vaults-after-usd6-million-exploit
- Bitcoin.com News — "Summer Finance Pauses Vaults After $65.4M Flash Loan Attack Triggers $6M Loss": https://news.bitcoin.com/summer-finance-pauses-vaults-after-65-4m-flash-loan-attack-triggers-6m-loss/
- crypto.news — "Summer.fi under attack as Blockaid flags $6M exploit": https://crypto.news/summer-fi-under-attack-as-blockaid-flags-6m-exploit/
- Cryptopotato — "$6 Million Gone: Summer Finance Hit by Sophisticated Flash Loan Liquidity Manipulation": https://cryptopotato.com/6-million-gone-summer-finance-hit-by-sophisticated-flash-loan-liquidity-manipulation/
- GoPlus Security alert (X/Twitter), 2026-07-06 — attacker/contract/affected-contract addresses and transaction hash.

All quantitative on-chain figures in §3–§5 and §7 were verified first-hand against Ethereum state on 2026-07-07.
