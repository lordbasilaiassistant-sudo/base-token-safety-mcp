# base-token-safety-mcp

```json
{
  "state": "OK",
  "verdict": "pass",
  "address": "0x4200000000000000000000000000000000000006",
  "chain": "base",
  "chainId": 8453,
  "checks": {
    "isContract": true,
    "honeypotIs": {
      "reachable": true,
      "hasData": true,
      "isHoneypot": false,
      "honeypotReason": null,
      "buyTaxPct": 0,
      "sellTaxPct": 0,
      "simulationSuccess": true,
      "risk": "low",
      "openSource": true,
      "apiFlags": []
    },
    "goPlus": {
      "reachable": true,
      "indexed": true,
      "isHoneypot": false,
      "buyTaxPct": null,
      "sellTaxPct": null,
      "sourceVerified": true,
      "holderCount": 5188511,
      "signals": []
    },
    "sourceVerified": true,
    "topHolderConcentration": {
      "topHolderPct": 26.93,
      "top10Pct": 53.07,
      "basis": "goplus_holders (burn addresses excluded)"
    }
  },
  "flags": [],
  "explain": [
    "contract: 2041 bytes of deployed bytecode at 0x4200000000000000000000000000000000000006 on base (chainId 8453) via eth_getCode — confirmed on-chain contract.",
    "honeypot.is: simulation succeeded — not flagged as honeypot (buy tax 0%, sell tax 0%), risk rating \"low\".",
    "goplus: indexed — source verified, 5188511 holders; no risk fields raised.",
    "source: contract source code is verified.",
    "holders: top non-burn holder 26.93%, top 10 hold 53.07%.",
    "verdict: pass — deployed contract, no honeypot signals from the consulted sources. Signals, not a guarantee."
  ],
  "checkedAt": "2026-07-03T19:10:09.751Z",
  "elapsedMs": 370
}
```

That is one real `check_token` call on WETH (Base) — no API key, no signup, 370 ms. A keyless MCP server (and plain CLI) that gives agents a structured pre-buy safety verdict for any token address on **Base** (plus Ethereum and BSC).

## Why it's different

- **Chain-truth first, explicit states always.** Security APIs answer "no flags found" even for addresses that aren't contracts at all. This server asks the chain first — raw `eth_getCode` against a public RPC — so a wallet address, a wrong-chain paste, or a fake listing comes back as an explicit **`NOT_A_CONTRACT`**, never an ambiguous empty result. It even distinguishes EIP-7702 delegated EOAs from real contracts.
- **Cross-checked signals.** [honeypot.is](https://honeypot.is) and [GoPlus](https://gopluslabs.io) free APIs queried in parallel: honeypot flags, buy/sell tax (worst of both sources), source verification, top-holder concentration.
- **Never a silent OK.** A dead upstream degrades the verdict to **`UPSTREAM_DEGRADED`** with the partial checks attached — it does not crash, and it does not pretend the check passed.
- **Zero keys, zero signup, `npx -y` runnable.** Typical check completes in well under 5 seconds (all upstream calls run in parallel with timeouts).

## Install

**Claude Code**

```sh
claude mcp add base-token-safety -- npx -y @broketobuilt/base-token-safety-mcp
```

**Cursor** (`~/.cursor/mcp.json`)

```json
{
  "mcpServers": {
    "base-token-safety": {
      "command": "npx",
      "args": ["-y", "@broketobuilt/base-token-safety-mcp"]
    }
  }
}
```

**VS Code** (`.vscode/mcp.json`)

```json
{
  "servers": {
    "base-token-safety": {
      "type": "stdio",
      "command": "npx",
      "args": ["-y", "@broketobuilt/base-token-safety-mcp"]
    }
  }
}
```

**Plain CLI — no MCP client needed**

```sh
npx -y @broketobuilt/base-token-safety-mcp check 0x4200000000000000000000000000000000000006
npx -y @broketobuilt/base-token-safety-mcp check 0x... --chain ethereum
```

Exit codes: `0` = check completed (read `verdict` in the JSON), `2` = invalid input.

## Tool: `check_token`

| Argument  | Type   | Notes                                              |
| --------- | ------ | -------------------------------------------------- |
| `address` | string | required — `0x` + 40 hex chars                     |
| `chain`   | string | optional — `base` (default), `ethereum`, or `bsc` |

### States

| `state`             | Meaning                                                                                          | Typical `verdict` |
| ------------------- | ------------------------------------------------------------------------------------------------ | ----------------- |
| `OK`                | Deployed contract, security sources responded; `pass` if no flags, `caution` if soft flags raised | `pass` / `caution` |
| `NOT_A_CONTRACT`    | No deployed code at the address (wallet/EOA, empty address, or wrong chain) — nothing to buy      | `fail`            |
| `HONEYPOT_SIGNALS`  | Honeypot-grade signal from any source (honeypot flag, cannot-sell, extreme tax)                   | `fail`            |
| `UNVERIFIED_RISK`   | Contract exists but source is unverified, or no security source knows it — unknown ≠ safe          | `caution`         |
| `UPSTREAM_DEGRADED` | One or more upstreams unreachable — partial check only, never a silent OK                          | `caution`         |

Every result carries machine-readable `flags` (e.g. `sell_tax_extreme`, `top_holder_gt_50pct`, `eip7702_delegated_eoa`, `upstream_unreachable:goplus`) and plain-English `explain` lines saying exactly what was observed and why the verdict is what it is.

## Data sources & configuration

All keyless and free: public RPC `eth_getCode` (Base default `https://mainnet.base.org` with automatic fallback), honeypot.is v2 API, GoPlus token_security v1 API.

| Env var        | Purpose                              |
| -------------- | ------------------------------------ |
| `BASE_RPC_URL` | Override the Base RPC endpoint       |
| `ETH_RPC_URL`  | Override the Ethereum RPC endpoint   |
| `BSC_RPC_URL`  | Override the BSC RPC endpoint        |

## Honest limits

These are **signals, not guarantees, and not financial advice**. A `pass` means the consulted free sources raised no red flags *at check time* — not that the token is safe. Upgradeable contracts can turn hostile after you check; brand-new tokens are often unindexed (`UNVERIFIED_RISK`); holder data can lag; simulations can miss trap logic that activates later or under different conditions. Use this to reject obvious garbage cheaply, not to bless anything. Never risk money you can't afford to lose.

---

Built by the [Broke to Built](https://broke2builtai.com) machine. MIT.
