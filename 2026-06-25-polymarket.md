# Polymarket Frontend Supply-Chain Hack — June 2026

**Report date:** 2026-06-30
**Incident date:** 2026-06-25
**Target:** Polymarket (decentralized prediction market)
**Loss:** ~$3.1M (initially reported ~$2.9M, revised within days)
**Category:** Frontend / software supply-chain attack (not a smart-contract exploit)
**Status:** Contained; full reimbursement pledged by Polymarket

> Scope note: This is an internal reference report for security analysis. Figures and event details are **as reported by the cited public sources** and have not been independently verified on-chain. Items that are inferred or unconfirmed are flagged explicitly.

---

## 1. Executive summary

On 2026-06-25, attackers drained approximately **$3.1 million in pUSD** (Polymarket's USDC-backed, dollar-pegged settlement token) from **11 user wallets**. The attack was **not** a smart-contract vulnerability in Polymarket's on-chain protocol. Instead, a **third-party vendor that supplies front-end code** to the Polymarket website was compromised, and the attacker injected a **malicious JavaScript payload** into the page served to a subset of users.

When affected users loaded the site and connected their wallets, the injected script prompted them to **sign wallet transactions they did not intend to authorize**. Because the signature requests appeared routine, victims approved them without obvious red flags. The stolen pUSD was then **swapped to ETH (~1,893 ETH)** and **bridged from Polygon to Ethereum mainnet**, where it was consolidated into attacker-controlled address(es) and reportedly sat idle as of initial reporting.

This incident is a textbook case of the dominant 2026 attack trend: **the security boundary failing at the intersection of systems, people, and permissions** rather than in audited contract code.

---

## 2. Timeline (as reported)

| Date (2026) | Event |
|---|---|
| (prior, ~6 yrs) | Unrelated context: a separate **May 22, 2026** incident drained ~$520K–$700K from internal payout wallets via an exposed private key that had been active for ~6 years (user funds unaffected in that case). |
| Jun 25 | Frontend supply-chain attack executed; malicious script served to a subset of users; 11 wallets drained of pUSD. |
| Jun 25 (post-disclosure) | Polymarket states it **contained** the incident, **removed the affected vendor dependency**, and publicly **pledged full refunds** to affected pUSD holders. |
| ~Jun 27 | Loss estimate **revised upward** from ~$2.9M to ~$3.1M (CoinDesk). |
| (concurrent) | Polymarket reported to be facing a **CFTC probe** (separate regulatory matter, per PYMNTS). |

---

## 3. Attack vector & root cause

### 3.1 Attack chain
1. **Vendor compromise** — Attackers breached a third-party vendor that supplies front-end code/dependencies to Polymarket. *(The specific vendor was not publicly disclosed in the cited sources.)*
2. **Code injection** — A rogue script was inserted into the front-end dependency.
3. **Delivery** — The compromised code was served to legitimate Polymarket users through the normal website load path (affecting only a subset of users).
4. **Exploitation** — In the victim's browser, the script abused the user's wallet/transaction-approval flow, prompting **unintended signatures** that authorized transfers of pUSD.

### 3.2 Why it worked
- The malicious prompts **looked like routine signing requests**, so they bypassed user suspicion.
- The trust model of a dApp front end means **whatever code reaches the browser is implicitly trusted by the wallet flow** — a compromised dependency inherits the site's trust.
- The on-chain contracts were never the weak point; **the off-chain delivery pipeline was**.

### 3.3 Unconfirmed / open technical questions
- **Signing primitive abused:** Public sources describe "unintended signatures" but do **not** confirm whether the script abused `permit` / ERC-20 `approve` / EIP-712 typed-data signing, a direct transfer, or private-key extraction. Halborn's writeup notes the script leveraged "the user's view of the site" to either extract keys *or* manipulate signing — i.e., **not definitively pinned down**. **(Unverified — needs on-chain tx analysis to confirm.)**
- **Vendor identity & breach method:** Not disclosed. **(Unknown.)**
- **Exact subset of affected users / how targeting was scoped:** Not disclosed. **(Unknown.)**

---

## 4. On-chain fund flow (as reported)
- **Asset stolen:** pUSD (Polymarket's dollar-pegged token, backed by USDC).
- **Source chain:** Polygon.
- **Laundering steps:** pUSD → swapped to **~1,893 ETH** → **bridged Polygon → Ethereum mainnet** → consolidated into attacker-controlled address(es); reportedly stationary as of initial reporting.
- **Peg stability:** The **pUSD peg remained steady** throughout — the breach did not destabilize the stablecoin itself.

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
- Use wallets with **transaction simulation / signature decoding**; scrutinize what is actually being signed, especially `approve`/`permit`-style requests.
- Consider **per-session spending limits** and revoking stale token approvals.

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

---
*Prepared for internal security review. Reported figures may be revised as investigation continues; re-verify amounts and attribution against on-chain data before citing externally.*
