/**
 * base-token-safety core — keyless token safety checks for Base (plus Ethereum and BSC).
 *
 * Ground truth first: raw eth_getCode against a public RPC. An address with no
 * deployed code is reported as an explicit NOT_A_CONTRACT — never an ambiguous
 * empty result. Risk signals come from the honeypot.is and GoPlus free APIs,
 * queried in parallel and cross-checked. A dead upstream degrades the verdict
 * (UPSTREAM_DEGRADED); it never crashes the check and never yields a silent OK.
 */
export const SUPPORTED_CHAINS = ["base", "ethereum", "bsc"];
const CHAINS = {
    base: {
        chainId: 8453,
        envVar: "BASE_RPC_URL",
        rpcs: ["https://mainnet.base.org", "https://base-rpc.publicnode.com"],
    },
    ethereum: {
        chainId: 1,
        envVar: "ETH_RPC_URL",
        rpcs: ["https://ethereum-rpc.publicnode.com", "https://cloudflare-eth.com"],
    },
    bsc: {
        chainId: 56,
        envVar: "BSC_RPC_URL",
        rpcs: ["https://bsc-dataseed.bnbchain.org", "https://bsc-rpc.publicnode.com"],
    },
};
const RPC_TIMEOUT_MS = 3500;
const API_TIMEOUT_MS = 4500;
const BURN_ADDRESSES = new Set([
    "0x0000000000000000000000000000000000000000",
    "0x000000000000000000000000000000000000dead",
]);
export class InvalidInputError extends Error {
}
export function validateAddress(raw) {
    const addr = String(raw ?? "").trim();
    if (!/^0x[0-9a-fA-F]{40}$/.test(addr)) {
        const shown = addr.length > 60 ? addr.slice(0, 60) + "…" : addr;
        throw new InvalidInputError(`not a valid EVM address: "${shown}" — expected 0x followed by 40 hex characters`);
    }
    return addr.toLowerCase();
}
export function validateChain(raw) {
    const chain = String(raw ?? "base").trim().toLowerCase();
    if (!SUPPORTED_CHAINS.includes(chain)) {
        throw new InvalidInputError(`unsupported chain "${chain}" — supported: ${SUPPORTED_CHAINS.join(", ")}`);
    }
    return chain;
}
async function fetchJson(url, init, timeoutMs) {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), timeoutMs);
    try {
        const res = await fetch(url, { ...init, signal: ctrl.signal });
        const text = await res.text();
        let json = null;
        try {
            json = JSON.parse(text);
        }
        catch {
            throw new Error(`non-JSON response (HTTP ${res.status})`);
        }
        return { status: res.status, json };
    }
    finally {
        clearTimeout(timer);
    }
}
async function getCode(cfg, address) {
    const override = process.env[cfg.envVar];
    const endpoints = override ? [override, ...cfg.rpcs] : cfg.rpcs;
    let lastError = "no endpoints";
    for (const endpoint of endpoints) {
        try {
            const { status, json } = await fetchJson(endpoint, {
                method: "POST",
                headers: { "content-type": "application/json" },
                body: JSON.stringify({
                    jsonrpc: "2.0",
                    id: 1,
                    method: "eth_getCode",
                    params: [address, "latest"],
                }),
            }, RPC_TIMEOUT_MS);
            if (status === 200 && typeof json?.result === "string") {
                return { reachable: true, code: json.result, endpoint };
            }
            lastError = json?.error?.message ?? `HTTP ${status}`;
        }
        catch (e) {
            lastError = e?.name === "AbortError" ? "timeout" : String(e?.message ?? e);
        }
    }
    return { reachable: false, error: lastError };
}
function num(v) {
    const n = typeof v === "string" ? parseFloat(v) : typeof v === "number" ? v : NaN;
    return Number.isFinite(n) ? n : null;
}
function round2(n) {
    return Math.round(n * 100) / 100;
}
/** GoPlus reports taxes as fractions of 1 (0.05 = 5%); normalize to percent. */
function fracToPct(v) {
    const n = num(v);
    return n === null ? null : round2(n * 100);
}
async function queryHoneypotIs(chainId, address) {
    const url = `https://api.honeypot.is/v2/IsHoneypot?address=${address}&chainID=${chainId}`;
    let status, json;
    try {
        ({ status, json } = await fetchJson(url, {}, API_TIMEOUT_MS));
    }
    catch (e) {
        return {
            reachable: false,
            hasData: false,
            error: e?.name === "AbortError" ? "timeout" : String(e?.message ?? e),
        };
    }
    if (status >= 500) {
        return { reachable: false, hasData: false, error: `HTTP ${status}` };
    }
    // 4xx or an error field is a business-level answer ("no pair", "not a token"),
    // not an outage — the upstream is alive, it just has nothing to simulate.
    if (status >= 400 || json?.error) {
        return { reachable: true, hasData: false, note: String(json?.error ?? `HTTP ${status}`) };
    }
    const apiFlags = Array.isArray(json?.flags)
        ? json.flags.map((f) => (typeof f === "string" ? f : String(f?.flag ?? JSON.stringify(f))))
        : [];
    return {
        reachable: true,
        hasData: true,
        isHoneypot: !!json?.honeypotResult?.isHoneypot,
        honeypotReason: json?.honeypotResult?.honeypotReason ?? null,
        buyTaxPct: num(json?.simulationResult?.buyTax),
        sellTaxPct: num(json?.simulationResult?.sellTax),
        simulationSuccess: json?.simulationSuccess !== false,
        risk: json?.summary?.risk ?? null,
        openSource: json?.contractCode?.openSource ?? json?.contractCode?.rootOpenSource ?? null,
        apiFlags,
    };
}
/** GoPlus boolean-string fields worth surfacing, with our flag names and severity. */
const GOPLUS_SIGNAL_FIELDS = [
    { field: "cannot_sell_all", flag: "cannot_sell_all", severity: "fail" },
    { field: "transfer_pausable", flag: "transfer_pausable", severity: "caution" },
    { field: "is_blacklisted", flag: "has_blacklist_function", severity: "caution" },
    { field: "hidden_owner", flag: "hidden_owner", severity: "caution" },
    { field: "can_take_back_ownership", flag: "can_take_back_ownership", severity: "caution" },
    { field: "owner_change_balance", flag: "owner_can_change_balances", severity: "caution" },
    { field: "selfdestruct", flag: "selfdestruct_in_contract", severity: "caution" },
    { field: "is_mintable", flag: "mintable", severity: "info" },
    { field: "is_proxy", flag: "upgradeable_proxy", severity: "info" },
    { field: "external_call", flag: "external_calls_present", severity: "info" },
];
async function queryGoPlus(chainId, address) {
    const url = `https://api.gopluslabs.io/api/v1/token_security/${chainId}?contract_addresses=${address}`;
    let status, json;
    try {
        ({ status, json } = await fetchJson(url, {}, API_TIMEOUT_MS));
    }
    catch (e) {
        return {
            check: {
                reachable: false,
                indexed: false,
                error: e?.name === "AbortError" ? "timeout" : String(e?.message ?? e),
            },
            concentration: null,
        };
    }
    if (status >= 500) {
        return { check: { reachable: false, indexed: false, error: `HTTP ${status}` }, concentration: null };
    }
    const data = json?.result?.[address.toLowerCase()];
    if (!data) {
        return {
            check: {
                reachable: true,
                indexed: false,
                note: json?.message && json.message !== "OK" ? String(json.message) : "token not in GoPlus index",
            },
            concentration: null,
        };
    }
    const signals = [];
    for (const { field } of GOPLUS_SIGNAL_FIELDS) {
        if (data[field] === "1")
            signals.push(field);
    }
    if (data.is_honeypot === "1")
        signals.push("is_honeypot");
    let concentration = null;
    if (Array.isArray(data.holders) && data.holders.length > 0) {
        const holders = data.holders.filter((h) => h?.address && !BURN_ADDRESSES.has(String(h.address).toLowerCase()));
        const pcts = holders.map((h) => fracToPct(h.percent)).filter((p) => p !== null);
        concentration = {
            topHolderPct: pcts.length ? pcts[0] : null,
            top10Pct: pcts.length ? round2(pcts.slice(0, 10).reduce((a, b) => a + b, 0)) : null,
            basis: "goplus_holders (burn addresses excluded)",
        };
    }
    return {
        check: {
            reachable: true,
            indexed: true,
            isHoneypot: data.is_honeypot === "1",
            buyTaxPct: fracToPct(data.buy_tax),
            sellTaxPct: fracToPct(data.sell_tax),
            sourceVerified: data.is_open_source === "1" ? true : data.is_open_source === "0" ? false : null,
            holderCount: num(data.holder_count),
            signals,
        },
        concentration,
    };
}
export async function checkToken(addressRaw, chainRaw) {
    const started = Date.now();
    const address = validateAddress(addressRaw);
    const chain = validateChain(chainRaw);
    const cfg = CHAINS[chain];
    const [codeR, hp, gpInternal] = await Promise.all([
        getCode(cfg, address),
        queryHoneypotIs(cfg.chainId, address),
        queryGoPlus(cfg.chainId, address),
    ]);
    const gp = gpInternal.check;
    const concentration = gpInternal.concentration;
    const flags = [];
    const explain = [];
    let failSignals = 0;
    let cautionSignals = 0;
    const caution = (flag) => {
        flags.push(flag);
        cautionSignals++;
    };
    const fail = (flag) => {
        flags.push(flag);
        failSignals++;
    };
    // --- ground truth: is there deployed code at this address? ---
    let isContract = null;
    let codeBytes = 0;
    if (codeR.reachable && typeof codeR.code === "string") {
        const code = codeR.code;
        codeBytes = code.length >= 2 ? (code.length - 2) / 2 : 0;
        if (code === "0x" || codeBytes === 0) {
            isContract = false;
            explain.push(`contract: NO code at ${address} on ${chain} (eth_getCode returned 0x) — this is a wallet (EOA) or an empty address, not a token contract. If you expected a token here, check the chain and re-copy the address.`);
        }
        else if (code.startsWith("0xef0100") && codeBytes === 23) {
            isContract = false;
            flags.push("eip7702_delegated_eoa");
            explain.push(`contract: ${address} is an EOA with an EIP-7702 delegation designator, not a token contract — there is no token to buy at this address.`);
        }
        else {
            isContract = true;
            explain.push(`contract: ${codeBytes} bytes of deployed bytecode at ${address} on ${chain} (chainId ${cfg.chainId}) via eth_getCode — confirmed on-chain contract.`);
        }
    }
    else {
        flags.push("upstream_unreachable:rpc");
        explain.push(`contract: could not reach any ${chain} RPC endpoint (${codeR.error}) — cannot confirm the address holds deployed code.`);
    }
    // --- honeypot flags from either source ---
    if (hp.reachable && hp.hasData) {
        if (hp.isHoneypot) {
            fail("honeypotis_flags_honeypot");
            explain.push(`honeypot.is: FLAGGED AS HONEYPOT${hp.honeypotReason ? ` — ${hp.honeypotReason}` : ""}.`);
        }
        else if (hp.simulationSuccess === false) {
            caution("sell_simulation_failed");
            explain.push(`honeypot.is: sell simulation FAILED — could not prove this token can be sold${hp.risk ? ` (risk rating "${hp.risk}")` : ""}. An unproven exit is not the same as a safe one.`);
        }
        else {
            const taxes = [
                hp.buyTaxPct !== null && hp.buyTaxPct !== undefined ? `buy tax ${round2(hp.buyTaxPct)}%` : null,
                hp.sellTaxPct !== null && hp.sellTaxPct !== undefined ? `sell tax ${round2(hp.sellTaxPct)}%` : null,
            ].filter(Boolean);
            explain.push(`honeypot.is: simulation succeeded — not flagged as honeypot${taxes.length ? ` (${taxes.join(", ")})` : ""}${hp.risk ? `, risk rating "${hp.risk}"` : ""}.`);
        }
    }
    else if (hp.reachable) {
        flags.push("honeypotis_no_data");
        explain.push(`honeypot.is: no simulation data for this address (${hp.note ?? "no pair found"}).`);
    }
    else {
        flags.push("upstream_unreachable:honeypotis");
        explain.push(`honeypot.is: unreachable (${hp.error}) — honeypot simulation unavailable for this check.`);
    }
    if (gp.reachable && gp.indexed) {
        if (gp.isHoneypot) {
            fail("goplus_flags_honeypot");
            explain.push("goplus: is_honeypot = 1 — GoPlus flags this token as a honeypot.");
        }
        for (const { field, flag, severity } of GOPLUS_SIGNAL_FIELDS) {
            if (gp.signals?.includes(field)) {
                if (severity === "fail")
                    fail(flag);
                else if (severity === "caution")
                    caution(flag);
                else
                    flags.push(flag);
            }
        }
        const gpBits = [
            gp.sourceVerified === true ? "source verified" : gp.sourceVerified === false ? "source NOT verified" : "source verification unknown",
            gp.sellTaxPct !== null ? `sell tax ${gp.sellTaxPct}%` : null,
            gp.holderCount !== null ? `${gp.holderCount} holders` : null,
        ].filter(Boolean);
        explain.push(`goplus: indexed — ${gpBits.join(", ")}${gp.signals && gp.signals.length ? `; raised: ${gp.signals.join(", ")}` : "; no risk fields raised"}.`);
    }
    else if (gp.reachable) {
        flags.push("goplus_not_indexed");
        explain.push("goplus: token not in the GoPlus index — no security data from this source (common for very new tokens).");
    }
    else {
        flags.push("upstream_unreachable:goplus");
        explain.push(`goplus: unreachable (${gp.error}) — GoPlus security data unavailable for this check.`);
    }
    // --- taxes, cross-checked (worst of both sources) ---
    const sellCandidates = [hp.sellTaxPct, gp.sellTaxPct].filter((v) => typeof v === "number");
    const buyCandidates = [hp.buyTaxPct, gp.buyTaxPct].filter((v) => typeof v === "number");
    const effSell = sellCandidates.length ? Math.max(...sellCandidates) : null;
    const effBuy = buyCandidates.length ? Math.max(...buyCandidates) : null;
    if (effSell !== null && effSell >= 40) {
        fail("sell_tax_extreme");
        explain.push(`tax: effective sell tax ${round2(effSell)}% — at this level selling is effectively blocked.`);
    }
    else if (effSell !== null && effSell >= 10) {
        caution("sell_tax_high");
        explain.push(`tax: effective sell tax ${round2(effSell)}% — high; expect real losses on exit.`);
    }
    if (effBuy !== null && effBuy >= 40) {
        fail("buy_tax_extreme");
    }
    else if (effBuy !== null && effBuy >= 10) {
        caution("buy_tax_high");
    }
    // --- source verification, aggregated across sources ---
    let sourceVerified = null;
    if (gp.sourceVerified === true || hp.openSource === true)
        sourceVerified = true;
    else if (gp.sourceVerified === false || hp.openSource === false)
        sourceVerified = false;
    if (isContract === true) {
        if (sourceVerified === false) {
            flags.push("source_not_verified");
            explain.push("source: contract source code is NOT verified on any consulted source — the code doing whatever it does cannot be read.");
        }
        else if (sourceVerified === true) {
            explain.push("source: contract source code is verified.");
        }
    }
    // --- holder concentration ---
    if (concentration?.topHolderPct !== null && concentration?.topHolderPct !== undefined) {
        if (concentration.topHolderPct > 50) {
            caution("top_holder_gt_50pct");
            explain.push(`holders: top non-burn holder controls ${concentration.topHolderPct}% of supply — one address can nuke the price.`);
        }
        else {
            explain.push(`holders: top non-burn holder ${concentration.topHolderPct}%, top 10 hold ${concentration.top10Pct}%.`);
        }
    }
    const bothSecuritySourcesEmpty = hp.reachable && !hp.hasData && gp.reachable && !gp.indexed;
    if (isContract === true && bothSecuritySourcesEmpty) {
        flags.push("no_security_source_data");
    }
    const degraded = !codeR.reachable || !hp.reachable || !gp.reachable;
    // --- verdict ---
    let state;
    let verdict;
    if (isContract === false) {
        state = "NOT_A_CONTRACT";
        verdict = "fail";
        explain.push("verdict: fail — there is no contract at this address, so there is no token to buy here. Any listing pointing at it is wrong or fake.");
    }
    else if (failSignals > 0) {
        state = "HONEYPOT_SIGNALS";
        verdict = "fail";
        explain.push(`verdict: fail — ${failSignals} honeypot-grade signal(s) raised. Do not buy; you are unlikely to be able to sell.`);
    }
    else if (degraded) {
        state = "UPSTREAM_DEGRADED";
        verdict = "caution";
        explain.push("verdict: caution — one or more upstream sources were unreachable, so this is a PARTIAL check, not a clean bill of health. Re-run later or verify manually.");
    }
    else if (sourceVerified === false || bothSecuritySourcesEmpty) {
        state = "UNVERIFIED_RISK";
        verdict = "caution";
        explain.push(bothSecuritySourcesEmpty
            ? "verdict: caution — the contract exists but neither security source has any data on it. Unknown ≠ safe; treat as unvetted."
            : "verdict: caution — the contract exists but its source is unverified; behavior cannot be audited.");
    }
    else {
        state = "OK";
        verdict = cautionSignals > 0 ? "caution" : "pass";
        explain.push(verdict === "pass"
            ? "verdict: pass — deployed contract, no honeypot signals from the consulted sources. Signals, not a guarantee."
            : `verdict: caution — no honeypot-grade signals, but ${cautionSignals} caution flag(s) deserve a look before committing funds.`);
    }
    return {
        state,
        verdict,
        address,
        chain,
        chainId: cfg.chainId,
        checks: {
            isContract,
            honeypotIs: hp,
            goPlus: gp,
            sourceVerified,
            topHolderConcentration: concentration,
        },
        flags,
        explain,
        checkedAt: new Date(started).toISOString(),
        elapsedMs: Date.now() - started,
    };
}
