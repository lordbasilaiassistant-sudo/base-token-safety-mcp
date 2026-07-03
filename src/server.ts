import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { checkToken, InvalidInputError, SUPPORTED_CHAINS } from "./core.js";

export const SERVER_NAME = "base-token-safety";
export const SERVER_VERSION = "0.1.0";

const TOOL_DESCRIPTION = [
  "Pre-buy / pre-approval safety check for a token contract on Base (also Ethereum and BSC).",
  "Keyless and free. Ground truth first: raw eth_getCode via public RPC returns an explicit",
  "NOT_A_CONTRACT state when the address holds no code — never an ambiguous empty result.",
  "Then cross-checks the honeypot.is and GoPlus free APIs for honeypot flags, buy/sell tax,",
  "source verification, and top-holder concentration. Returns a structured verdict",
  "(pass | caution | fail) with an explicit state, machine-readable flags, and plain-English",
  "explanations. A dead upstream degrades the verdict (UPSTREAM_DEGRADED) instead of failing.",
  "Signals, not guarantees — not financial advice.",
].join(" ");

export function buildServer(): McpServer {
  const server = new McpServer({ name: SERVER_NAME, version: SERVER_VERSION });

  server.registerTool(
    "check_token",
    {
      title: "Token safety check (Base)",
      description: TOOL_DESCRIPTION,
      inputSchema: {
        address: z
          .string()
          .describe("Token contract address to check (0x-prefixed, 40 hex characters)"),
        chain: z
          .enum(SUPPORTED_CHAINS as [string, ...string[]])
          .optional()
          .describe('Chain to check on: "base" (default), "ethereum", or "bsc"'),
      },
      outputSchema: {
        state: z.enum(["OK", "NOT_A_CONTRACT", "UNVERIFIED_RISK", "HONEYPOT_SIGNALS", "UPSTREAM_DEGRADED"]),
        verdict: z.enum(["pass", "caution", "fail"]),
        address: z.string(),
        chain: z.string(),
        chainId: z.number(),
        checks: z.object({
          isContract: z.boolean().nullable(),
          honeypotIs: z.record(z.string(), z.unknown()).nullable(),
          goPlus: z.record(z.string(), z.unknown()).nullable(),
          sourceVerified: z.boolean().nullable(),
          topHolderConcentration: z.record(z.string(), z.unknown()).nullable().optional(),
        }),
        flags: z.array(z.string()),
        explain: z.array(z.string()),
        checkedAt: z.string(),
        elapsedMs: z.number(),
      },
      annotations: {
        readOnlyHint: true,
        openWorldHint: true,
        idempotentHint: true,
      },
    },
    async ({ address, chain }) => {
      try {
        const result = await checkToken(address, chain);
        return {
          content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }],
          structuredContent: result as unknown as Record<string, unknown>,
        };
      } catch (e) {
        if (e instanceof InvalidInputError) {
          const err = {
            error: "invalid_input",
            message: e.message,
            hint: "address must be a 0x-prefixed 40-hex-character EVM address; chain must be base, ethereum, or bsc",
          };
          return {
            isError: true,
            content: [{ type: "text" as const, text: JSON.stringify(err, null, 2) }],
          };
        }
        throw e;
      }
    },
  );

  return server;
}
