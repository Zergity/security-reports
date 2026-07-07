# Security Reports

Incident reports and forensic analyses of DeFi / blockchain exploits.

Files follow a uniform `YYYY-MM-DD-<target>.md` scheme, prefixed by **incident date** so they sort chronologically.

## Index

| Date | Target | Loss (reported) | Vector | Report |
|---|---|---|---|---|
| 2026-06-20 | JaredFromSubway MEV bot | ~$7.5M (Blockaid/PeckShield); operator claims ~$15M | Counter-MEV honeypot: fake token/pool decoys collected standing ERC-20 approvals, swept in one `transferFrom` | [report](2026-06-20-jaredfromsubway.md) |
| 2026-06-25 | Polymarket | ~$3.1M | Frontend / supply-chain: compromised third-party JS vendor injected a script that prompted unintended wallet signatures | [report](2026-06-25-polymarket.md) |
| 2026-07-03 | Hinkal Protocol | ~$772K net on-chain (~$800K–$820K reported gross) | ZK circuit soundness flaw via `prooflessDeposit`: one 25,000-USDC note (leaf binds the amount) spent 32× for distinct valid nullifiers, no change notes, one `NewCommitment` in vs 32 `Nullified` out — an under-constrained nullifier. Verifier (standard snarkjs Groth16), nullifier-uniqueness check, and deposit accounting all executed correctly; confirmed by decoding all 94 `transact` calls and the event logs | [report](2026-07-03-hinkal.md) |
| 2026-07-06 | Summer.fi (Lazy Summer Protocol) | ~$6.0M (attacker netted ≈6,016,755 DAI; ~$65.4M flash loan) | ERC-4626 share-price manipulation: `FleetCommander` prices shares off the spot valuations its Arks report for positions in shared Morpho/Spark lending markets. A Morpho Blue flash loan distorted those markets, so a same-transaction deposit at 1.0665 and redeem at 1.1678 cleared ~9.5% apart on ~$65M; the redeem force-disembarked Arks at manipulated rates. Verified: deposit 64.83M / redeem 70.96M, and FleetCommander_A's resting NAV was unchanged before/after — the ~$6M came out of the shared underlying markets, not the vault's standing TVL | [report](2026-07-06-summerfinance.md) |
| 2026-07-06 | BonkDAO (Solana) | 4.4261T BONK (~$19.3M at transfer; ~$20M reported) | Governance capture, not a code bug: attacker bought ~$4M of BONK to clear a 1%-of-supply quorum (on-chain 879.95B), passed proposal "BIP #76 - Sowellian BonkDAO" whose executable instruction sent the treasury's entire BONK balance to its wallet. Verified first-hand on Solana: realm/governance/proposal accounts decoded, "Approve" weight 882.38B vs quorum 879.95B (~0.28% margin), executed 49s after vote close (no timelock). ~$19M still parked at a second-hop wallet | [report](2026-07-06-bonkdao.md) |

## Notes

- Figures are **as reported by public sources** unless a report states otherwise; some include on-chain-verified reconciliations (see individual reports).
- Re-verify amounts and attribution against on-chain data before citing externally.
