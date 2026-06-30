# Security Reports

Incident reports and forensic analyses of DeFi / blockchain exploits.

Files follow a uniform `YYYY-MM-DD-<target>.md` scheme, prefixed by **incident date** so they sort chronologically.

## Index

| Date | Target | Loss (reported) | Vector | Report |
|---|---|---|---|---|
| 2026-06-20 | JaredFromSubway MEV bot | ~$7.5M (Blockaid/PeckShield); operator claims ~$15M | Counter-MEV honeypot — fake token/pool decoys collected standing ERC-20 approvals, swept in one `transferFrom` | [report](2026-06-20-jaredfromsubway.md) |
| 2026-06-25 | Polymarket | ~$3.1M | Frontend / supply-chain — compromised third-party JS vendor injected a script that prompted unintended wallet signatures | [report](2026-06-25-polymarket.md) |

## Notes

- Figures are **as reported by public sources** unless a report states otherwise; some include on-chain-verified reconciliations (see individual reports).
- Re-verify amounts and attribution against on-chain data before citing externally.
