/**
 * base-token-safety core — keyless token safety checks for Base (plus Ethereum and BSC).
 *
 * Ground truth first: raw eth_getCode against a public RPC. An address with no
 * deployed code is reported as an explicit NOT_A_CONTRACT — never an ambiguous
 * empty result. Risk signals come from the honeypot.is and GoPlus free APIs,
 * queried in parallel and cross-checked. A dead upstream degrades the verdict
 * (UPSTREAM_DEGRADED); it never crashes the check and never yields a silent OK.
 */
export type Chain = "base" | "ethereum" | "bsc";
export type State = "OK" | "NOT_A_CONTRACT" | "UNVERIFIED_RISK" | "HONEYPOT_SIGNALS" | "UPSTREAM_DEGRADED";
export type Verdict = "pass" | "caution" | "fail";
export declare const SUPPORTED_CHAINS: readonly Chain[];
export declare class InvalidInputError extends Error {
}
export interface HoneypotIsCheck {
    reachable: boolean;
    hasData: boolean;
    isHoneypot?: boolean;
    honeypotReason?: string | null;
    buyTaxPct?: number | null;
    sellTaxPct?: number | null;
    simulationSuccess?: boolean;
    risk?: string | null;
    openSource?: boolean | null;
    apiFlags?: string[];
    note?: string;
    error?: string;
}
export interface GoPlusCheck {
    reachable: boolean;
    indexed: boolean;
    isHoneypot?: boolean;
    buyTaxPct?: number | null;
    sellTaxPct?: number | null;
    sourceVerified?: boolean | null;
    holderCount?: number | null;
    signals?: string[];
    note?: string;
    error?: string;
}
export interface TopHolderConcentration {
    topHolderPct: number | null;
    top10Pct: number | null;
    basis: string;
}
export interface CheckResult {
    state: State;
    verdict: Verdict;
    address: string;
    chain: Chain;
    chainId: number;
    checks: {
        isContract: boolean | null;
        honeypotIs: HoneypotIsCheck | null;
        goPlus: GoPlusCheck | null;
        sourceVerified: boolean | null;
        topHolderConcentration?: TopHolderConcentration | null;
    };
    flags: string[];
    explain: string[];
    checkedAt: string;
    elapsedMs: number;
}
export declare function validateAddress(raw: string): string;
export declare function validateChain(raw: string | undefined): Chain;
export declare function checkToken(addressRaw: string, chainRaw?: string): Promise<CheckResult>;
