#!/usr/bin/env node
/**
 * Entry point. No arguments (or "serve") starts the MCP stdio server.
 * "check <address> [--chain base|ethereum|bsc]" runs a one-shot check and
 * prints the verdict JSON to stdout — same core, no MCP client required.
 */
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { buildServer, SERVER_NAME, SERVER_VERSION } from "./server.js";
import { checkToken, InvalidInputError } from "./core.js";

const HELP = `${SERVER_NAME} v${SERVER_VERSION} — keyless token safety checks for Base (and Ethereum/BSC)

usage:
  base-token-safety-mcp                       start the MCP stdio server
  base-token-safety-mcp check <address> [--chain base|ethereum|bsc]
  base-token-safety-mcp <address>             shorthand for "check"

exit codes: 0 = check completed (read "verdict" in the JSON), 2 = invalid input

env: BASE_RPC_URL / ETH_RPC_URL / BSC_RPC_URL override the default public RPCs`;

async function runCheck(args: string[]): Promise<void> {
  let address: string | undefined;
  let chain: string | undefined;
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--chain") chain = args[++i];
    else if (!address) address = args[i];
  }
  if (!address) {
    console.log(JSON.stringify({ error: "invalid_input", message: "no address given", hint: HELP }, null, 2));
    process.exit(2);
  }
  try {
    const result = await checkToken(address, chain);
    console.log(JSON.stringify(result, null, 2));
  } catch (e) {
    if (e instanceof InvalidInputError) {
      console.log(
        JSON.stringify(
          {
            error: "invalid_input",
            message: e.message,
            hint: "address must be a 0x-prefixed 40-hex-character EVM address; chain must be base, ethereum, or bsc",
          },
          null,
          2,
        ),
      );
      process.exit(2);
    }
    throw e;
  }
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  if (args[0] === "--help" || args[0] === "-h" || args[0] === "help") {
    console.log(HELP);
    return;
  }
  if (args[0] === "--version" || args[0] === "-v") {
    console.log(SERVER_VERSION);
    return;
  }
  if (args[0] === "check") {
    await runCheck(args.slice(1));
    return;
  }
  if (args[0] && args[0] !== "serve") {
    // bare address shorthand; anything else non-hex is a usage error
    if (/^0x/i.test(args[0])) {
      await runCheck(args);
      return;
    }
    console.error(HELP);
    process.exit(2);
  }
  const server = buildServer();
  await server.connect(new StdioServerTransport());
  // stdout is reserved for the MCP protocol; status goes to stderr
  console.error(`${SERVER_NAME} v${SERVER_VERSION}: MCP stdio server ready`);
}

main().catch((e) => {
  console.error(String(e?.stack ?? e));
  process.exit(1);
});
