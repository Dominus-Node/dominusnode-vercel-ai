# @dominusnode/ai-tools

Vercel AI SDK tools for the [Dominus Node](https://dominusnode.com) rotating proxy-as-a-service platform. Gives AI agents the ability to make proxied HTTP requests, check wallet balance, monitor usage, and manage proxy sessions.

## Installation

```bash
npm install @dominusnode/ai-tools ai zod @dominusnode/sdk
```

## Quick Start

### Next.js Route Handler

```ts
// app/api/chat/route.ts
import { streamText } from "ai";
import { openai } from "@ai-sdk/openai";
import { createDominusNodeTools } from "@dominusnode/ai-tools";

export async function POST(req: Request) {
  const { messages } = await req.json();

  const tools = await createDominusNodeTools({
    apiKey: process.env.DOMINUSNODE_API_KEY!,
    baseUrl: process.env.DOMINUSNODE_BASE_URL, // optional
  });

  const result = streamText({
    model: openai("gpt-4o"),
    messages,
    tools,
    maxSteps: 5,
  });

  return result.toDataStreamResponse();
}
```

### Standalone with `generateText`

```ts
import { generateText } from "ai";
import { openai } from "@ai-sdk/openai";
import { createDominusNodeTools } from "@dominusnode/ai-tools";

const tools = await createDominusNodeTools({
  apiKey: "dn_live_your_api_key_here",
});

const { text } = await generateText({
  model: openai("gpt-4o"),
  tools,
  maxSteps: 10,
  prompt: "Fetch https://httpbin.org/ip through a US datacenter proxy and tell me the IP",
});

console.log(text);
```

## Tools

### `proxiedFetch`

Make HTTP requests through Dominus Node's rotating proxy network with geo-targeting support.

| Parameter   | Type                                    | Required | Description                                  |
|-------------|-----------------------------------------|----------|----------------------------------------------|
| `url`       | `string` (URL)                          | Yes      | The URL to fetch through the proxy           |
| `method`    | `"GET" \| "HEAD" \| "OPTIONS"` | No       | HTTP method (default: `GET`)                 |
| `country`   | `string` (2-letter ISO)                 | No       | Country code for geo-targeting               |
| `proxyType` | `"dc" \| "residential"`                 | No       | Proxy type (default: `dc`)                   |
| `headers`   | `Record<string, string>`                | No       | Additional HTTP headers                      |
| `body`      | `string`                                | No       | Not used (read-only methods only)            |

**Returns:** `{ status, statusText, headers, body, proxyType, country }`

**Security:** URLs are validated to prevent SSRF attacks. Blocked targets include localhost, private IP ranges (10.x, 172.16-31.x, 192.168.x), link-local (169.254.x), IPv6 loopback/ULA, and non-HTTP protocols. Response bodies are truncated to 4,000 characters. API keys are scrubbed from error messages.

### `checkBalance`

Check the current Dominus Node wallet balance.

**Parameters:** None

**Returns:** `{ balanceCents, balanceUsd, currency, lastToppedUp }`

### `checkUsage`

Check proxy usage statistics for a given time period.

| Parameter | Type                            | Required | Description              |
|-----------|---------------------------------|----------|--------------------------|
| `period`  | `"day" \| "week" \| "month"`   | No       | Time window for stats    |

**Returns:** `{ summary: { totalBytes, totalGB, totalCostCents, totalCostUsd, requestCount }, period, recordCount }`

### `getProxyConfig`

Get proxy endpoint configuration and supported countries.

**Parameters:** None

**Returns:** `{ endpoints: { http, socks5 }, supportedCountries, blockedCountries, geoTargeting }`

### `listSessions`

List all active proxy sessions.

**Parameters:** None

**Returns:** `{ sessions: [{ id, startedAt, status }], count }`

## Advanced Usage

### Using an Existing Client

If you already manage a `DominusNodeClient` instance:

```ts
import { DominusNodeClient } from "@dominusnode/sdk";
import { createDominusNodeToolsFromClient } from "@dominusnode/ai-tools";

const client = new DominusNodeClient({ baseUrl: "http://localhost:3000" });
await client.connectWithKey("dn_live_your_key");

const tools = createDominusNodeToolsFromClient(client, "dn_live_your_key");
```

### Using Individual Tool Creators

For fine-grained control, import individual tool factory functions:

```ts
import {
  createProxiedFetchTool,
  createCheckBalanceTool,
} from "@dominusnode/ai-tools";
import { DominusNodeClient } from "@dominusnode/sdk";

const client = new DominusNodeClient();
await client.connectWithKey("dn_live_your_key");

// Only expose the tools you need
const tools = {
  proxiedFetch: createProxiedFetchTool(client, "dn_live_your_key"),
  checkBalance: createCheckBalanceTool(client),
};
```

### With Anthropic Claude

```ts
import { generateText } from "ai";
import { anthropic } from "@ai-sdk/anthropic";
import { createDominusNodeTools } from "@dominusnode/ai-tools";

const tools = await createDominusNodeTools({
  apiKey: process.env.DOMINUSNODE_API_KEY!,
});

const { text } = await generateText({
  model: anthropic("claude-sonnet-4-20250514"),
  tools,
  maxSteps: 5,
  prompt: "Check my balance, then fetch https://example.com through a German proxy",
});
```

## Environment Variables

| Variable                | Description                           | Default                         |
|-------------------------|---------------------------------------|---------------------------------|
| `DOMINUSNODE_API_KEY`   | Dominus Node API key                      | Required                        |
| `DOMINUSNODE_BASE_URL`  | Dominus Node API base URL                 | `https://api.dominusnode.com`   |

## Pricing

Proxy usage is billed from your Dominus Node wallet:

- **Datacenter (dc):** $3.00/GB
- **Residential:** $5.00/GB

Check your balance with the `checkBalance` tool before heavy usage.

## License

MIT
