import { describe, it, expect, vi, beforeEach } from "vitest";
import { EventEmitter } from "events";
import {
  createProxiedFetchTool,
  createCheckBalanceTool,
  createCheckUsageTool,
  createGetProxyConfigTool,
  createListSessionsTool,
} from "../src/tools.js";
import { validateUrl, isPrivateIp, truncateBody, filterHeaders } from "../src/tools.js";
import {
  createDominusNodeTools,
  createDominusNodeToolsFromClient,
} from "../src/create-tools.js";

// ---------------------------------------------------------------------------
// Mock node:http for proxy routing tests
// ---------------------------------------------------------------------------
const mockHttpBehavior: { mode: "error" | "respond" | "passthrough"; errorMsg?: string; responseBody?: string } = { mode: "passthrough" };

vi.mock("node:http", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:http")>();
  return {
    ...actual,
    request: (...args: any[]) => {
      if (mockHttpBehavior.mode === "error") {
        const mockReq = Object.assign(new EventEmitter(), { end: vi.fn() });
        setTimeout(() => mockReq.emit("error", new Error(mockHttpBehavior.errorMsg || "Mock error")), 5);
        return mockReq as any;
      }
      if (mockHttpBehavior.mode === "respond") {
        const mockRes = Object.assign(new EventEmitter(), {
          statusCode: 200,
          statusMessage: "OK",
          headers: { "content-type": "text/plain" } as Record<string, string | string[]>,
        });
        const mockReq = Object.assign(new EventEmitter(), { end: vi.fn() });
        const cb = typeof args[1] === "function" ? args[1] : args[0]?.callback;
        setTimeout(() => {
          if (cb) cb(mockRes);
          setTimeout(() => {
            mockRes.emit("data", Buffer.from(mockHttpBehavior.responseBody || ""));
            mockRes.emit("end");
          }, 5);
        }, 5);
        return mockReq as any;
      }
      // passthrough to real implementation
      return actual.request(...(args as [any]));
    },
  };
});

// ---------------------------------------------------------------------------
// Mock the DominusNodeClient
// ---------------------------------------------------------------------------

function createMockClient() {
  return {
    proxy: {
      buildUrl: vi.fn().mockReturnValue("http://user:dn_live_test@proxy.dominusnode.com:8080"),
      getConfig: vi.fn().mockResolvedValue({
        httpProxy: { host: "proxy.dominusnode.com", port: 8080 },
        socks5Proxy: { host: "proxy.dominusnode.com", port: 1080 },
        supportedCountries: ["US", "GB", "DE", "JP"],
        blockedCountries: ["CU", "IR", "KP", "RU", "SY"],
        geoTargeting: {
          stateSupport: true,
          citySupport: true,
          asnSupport: false,
        },
      }),
    },
    wallet: {
      getBalance: vi.fn().mockResolvedValue({
        balanceCents: 5000,
        balanceUsd: 50.0,
        currency: "USD",
        lastToppedUp: "2026-02-15T10:00:00Z",
      }),
      topupPaypal: vi.fn(),
      topupStripe: vi.fn(),
      topupCrypto: vi.fn(),
    },
    usage: {
      get: vi.fn().mockResolvedValue({
        summary: {
          totalBytes: 1073741824,
          totalGB: 1.0,
          totalCostCents: 300,
          totalCostUsd: 3.0,
          requestCount: 1500,
        },
        records: [
          {
            id: "rec-1",
            sessionId: "sess-1",
            bytesIn: 500000,
            bytesOut: 1000000,
            totalBytes: 1500000,
            costCents: 1,
            proxyType: "dc",
            targetHost: "httpbin.org",
            createdAt: "2026-02-18T12:00:00Z",
          },
        ],
        pagination: { limit: 100, offset: 0, total: 1 },
        period: {
          since: "2026-02-12T00:00:00Z",
          until: "2026-02-19T00:00:00Z",
        },
      }),
    },
    sessions: {
      getActive: vi.fn().mockResolvedValue({
        sessions: [
          {
            id: "sess-abc",
            startedAt: "2026-02-19T08:00:00Z",
            status: "active",
          },
          {
            id: "sess-def",
            startedAt: "2026-02-19T08:30:00Z",
            status: "active",
          },
        ],
      }),
    },
    auth: {
      verifyKey: vi.fn().mockResolvedValue({
        token: "jwt-access-token",
        refreshToken: "jwt-refresh-token",
      }),
    },
    connectWithKey: vi.fn().mockResolvedValue(undefined),
  } as any;
}

// ---------------------------------------------------------------------------
// URL validation tests
// ---------------------------------------------------------------------------

describe("validateUrl", () => {
  it("accepts valid http URLs", () => {
    const result = validateUrl("https://httpbin.org/ip");
    expect(result.valid).toBe(true);
  });

  it("accepts valid http URL", () => {
    const result = validateUrl("http://example.com/path?q=1");
    expect(result.valid).toBe(true);
  });

  it("rejects invalid URL format", () => {
    const result = validateUrl("not-a-url");
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.error).toMatch(/Invalid URL/i);
    }
  });

  it("rejects file:// protocol", () => {
    const result = validateUrl("file:///etc/passwd");
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.error).toMatch(/Unsupported protocol/);
    }
  });

  it("rejects ftp:// protocol", () => {
    const result = validateUrl("ftp://ftp.example.com/file");
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.error).toMatch(/Unsupported protocol/);
    }
  });

  it("rejects localhost", () => {
    const result = validateUrl("http://localhost/secret");
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.error).toMatch(/localhost/);
    }
  });

  it("rejects localhost with port", () => {
    const result = validateUrl("http://localhost:3000/api");
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.error).toMatch(/localhost/);
    }
  });

  it("rejects 127.0.0.1", () => {
    const result = validateUrl("http://127.0.0.1/secret");
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.error).toMatch(/private/i);
    }
  });

  it("rejects 10.x.x.x", () => {
    const result = validateUrl("http://10.0.0.1/internal");
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.error).toMatch(/private/i);
    }
  });

  it("rejects 172.16.x.x", () => {
    const result = validateUrl("http://172.16.0.1/internal");
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.error).toMatch(/private/i);
    }
  });

  it("rejects 192.168.x.x", () => {
    const result = validateUrl("http://192.168.1.1/admin");
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.error).toMatch(/private/i);
    }
  });

  it("rejects ::1 (IPv6 loopback)", () => {
    const result = validateUrl("http://[::1]/secret");
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.error).toMatch(/private/i);
    }
  });

  it("rejects fd00:: (IPv6 ULA)", () => {
    const result = validateUrl("http://[fd12::1]/internal");
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.error).toMatch(/private/i);
    }
  });

  it("rejects URLs with embedded credentials", () => {
    const result = validateUrl("http://user:pass@example.com/");
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.error).toMatch(/credentials/i);
    }
  });

  it("rejects URLs exceeding max length", () => {
    const longUrl = "https://example.com/" + "a".repeat(2100);
    const result = validateUrl(longUrl);
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.error).toMatch(/length/i);
    }
  });

  it("rejects hex-encoded IP addresses", () => {
    const result = validateUrl("http://0x7f000001/secret");
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.error).toMatch(/private/i);
    }
  });

  it("rejects decimal-encoded IP addresses", () => {
    const result = validateUrl("http://2130706433/secret");
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.error).toMatch(/private/i);
    }
  });

  it("rejects 169.254.x.x (link-local)", () => {
    const result = validateUrl("http://169.254.169.254/latest/meta-data/");
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.error).toMatch(/private/i);
    }
  });
});

describe("isPrivateIp", () => {
  it("returns true for 127.0.0.1", () => {
    expect(isPrivateIp("127.0.0.1")).toBe(true);
  });

  it("returns true for 127.0.0.2", () => {
    expect(isPrivateIp("127.0.0.2")).toBe(true);
  });

  it("returns true for 10.0.0.0", () => {
    expect(isPrivateIp("10.0.0.0")).toBe(true);
  });

  it("returns true for 172.31.255.255", () => {
    expect(isPrivateIp("172.31.255.255")).toBe(true);
  });

  it("returns true for 192.168.0.1", () => {
    expect(isPrivateIp("192.168.0.1")).toBe(true);
  });

  it("returns true for ::1", () => {
    expect(isPrivateIp("::1")).toBe(true);
  });

  it("returns true for fe80::1", () => {
    expect(isPrivateIp("fe80::1")).toBe(true);
  });

  it("returns true for ::ffff:127.0.0.1", () => {
    expect(isPrivateIp("::ffff:127.0.0.1")).toBe(true);
  });

  it("returns true for 0.0.0.0", () => {
    expect(isPrivateIp("0.0.0.0")).toBe(true);
  });

  it("returns false for 8.8.8.8", () => {
    expect(isPrivateIp("8.8.8.8")).toBe(false);
  });

  it("returns false for 203.0.113.1", () => {
    expect(isPrivateIp("203.0.113.1")).toBe(false);
  });

  it("strips IPv6 zone IDs", () => {
    expect(isPrivateIp("fe80::1%eth0")).toBe(true);
  });

  it("handles bracketed IPv6", () => {
    expect(isPrivateIp("[::1]")).toBe(true);
  });
});

describe("truncateBody", () => {
  it("returns short strings unchanged", () => {
    expect(truncateBody("hello")).toBe("hello");
  });

  it("truncates strings at 4000 chars", () => {
    const long = "x".repeat(5000);
    const result = truncateBody(long);
    expect(result.length).toBeLessThan(5000);
    expect(result).toContain("...[truncated");
    expect(result).toContain("1000 chars omitted");
  });

  it("does not truncate strings at exactly 4000 chars", () => {
    const exact = "x".repeat(4000);
    expect(truncateBody(exact)).toBe(exact);
  });
});

describe("filterHeaders", () => {
  it("keeps safe headers", () => {
    const headers = {
      "Content-Type": "application/json",
      "Date": "Thu, 19 Feb 2026 00:00:00 GMT",
      "Server": "nginx",
    };
    const filtered = filterHeaders(headers);
    expect(filtered["content-type"]).toBe("application/json");
    expect(filtered["date"]).toBeDefined();
    expect(filtered["server"]).toBe("nginx");
  });

  it("strips sensitive headers", () => {
    const headers = {
      "Content-Type": "text/html",
      "Set-Cookie": "session=abc123; HttpOnly",
      "Authorization": "Bearer xyz",
      "X-Internal-Secret": "s3cr3t",
    };
    const filtered = filterHeaders(headers);
    expect(filtered["content-type"]).toBe("text/html");
    expect(filtered["set-cookie"]).toBeUndefined();
    expect(filtered["authorization"]).toBeUndefined();
    expect(filtered["x-internal-secret"]).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// proxiedFetch tool tests
// ---------------------------------------------------------------------------

describe("proxiedFetch tool", () => {
  let mockClient: ReturnType<typeof createMockClient>;
  let proxiedFetch: ReturnType<typeof createProxiedFetchTool>;

  beforeEach(() => {
    mockClient = createMockClient();
    proxiedFetch = createProxiedFetchTool(mockClient, "dn_live_testkey123");
  });

  it("has correct description", () => {
    expect(proxiedFetch.description).toContain("proxy");
    expect(proxiedFetch.description).toContain("HTTP");
  });

  it("rejects localhost URLs", async () => {
    const result = await proxiedFetch.execute(
      {
        url: "http://localhost:3000/api",
        method: "GET",
        proxyType: "dc",
      },
      { toolCallId: "call-1", messages: [], abortSignal: undefined as any },
    );
    expect(result).toHaveProperty("error");
    expect((result as any).error).toMatch(/localhost/);
  });

  it("rejects private IP URLs", async () => {
    const result = await proxiedFetch.execute(
      {
        url: "http://192.168.1.1/admin",
        method: "GET",
        proxyType: "dc",
      },
      { toolCallId: "call-2", messages: [], abortSignal: undefined as any },
    );
    expect(result).toHaveProperty("error");
    expect((result as any).error).toMatch(/private/i);
  });

  it("rejects file:// protocol", async () => {
    const result = await proxiedFetch.execute(
      {
        url: "file:///etc/passwd",
        method: "GET",
        proxyType: "dc",
      },
      { toolCallId: "call-3", messages: [], abortSignal: undefined as any },
    );
    expect(result).toHaveProperty("error");
    expect((result as any).error).toMatch(/protocol/i);
  });

  it("rejects cloud metadata endpoint", async () => {
    const result = await proxiedFetch.execute(
      {
        url: "http://169.254.169.254/latest/meta-data/",
        method: "GET",
        proxyType: "dc",
      },
      { toolCallId: "call-4", messages: [], abortSignal: undefined as any },
    );
    expect(result).toHaveProperty("error");
    expect((result as any).error).toMatch(/private/i);
  });

  it("builds proxy URL with country geo-targeting", async () => {
    // Use mock HTTP to prevent real connections
    mockHttpBehavior.mode = "respond";
    mockHttpBehavior.responseBody = '{"origin": "1.2.3.4"}';

    try {
      await proxiedFetch.execute(
        {
          url: "http://httpbin.org/ip",
          method: "GET",
          country: "US",
          proxyType: "dc",
        },
        { toolCallId: "call-5", messages: [], abortSignal: undefined as any },
      );

      expect(mockClient.proxy.buildUrl).toHaveBeenCalledWith("dn_live_testkey123", {
        protocol: "http",
        country: "US",
      });
    } finally {
      mockHttpBehavior.mode = "passthrough";
    }
  });

  it("sanitizes API keys from error messages", async () => {
    mockHttpBehavior.mode = "error";
    mockHttpBehavior.errorMsg = "Connection failed to dn_live_testkey123@proxy.dominusnode.com";

    try {
      const result = await proxiedFetch.execute(
        {
          url: "https://httpbin.org/ip",
          method: "GET",
          proxyType: "dc",
        },
        { toolCallId: "call-6", messages: [], abortSignal: undefined as any },
      );
      expect(result).toHaveProperty("error");
      expect((result as any).error).not.toContain("dn_live_testkey123");
      expect((result as any).error).toContain("***");
    } finally {
      mockHttpBehavior.mode = "passthrough";
    }
  });

  it("truncates large response bodies", async () => {
    mockHttpBehavior.mode = "respond";
    mockHttpBehavior.responseBody = "x".repeat(8000);

    try {
      const result = await proxiedFetch.execute(
        {
          url: "http://example.com/big",
          method: "GET",
          proxyType: "dc",
        },
        { toolCallId: "call-7", messages: [], abortSignal: undefined as any },
      );
      expect(result).toHaveProperty("body");
      expect((result as any).body.length).toBeLessThan(8000);
      expect((result as any).body).toContain("[truncated");
    } finally {
      mockHttpBehavior.mode = "passthrough";
    }
  });
});

// ---------------------------------------------------------------------------
// checkBalance tool tests
// ---------------------------------------------------------------------------

describe("checkBalance tool", () => {
  let mockClient: ReturnType<typeof createMockClient>;
  let checkBalance: ReturnType<typeof createCheckBalanceTool>;

  beforeEach(() => {
    mockClient = createMockClient();
    checkBalance = createCheckBalanceTool(mockClient);
  });

  it("has correct description", () => {
    expect(checkBalance.description).toContain("balance");
  });

  it("returns wallet balance", async () => {
    const result = await checkBalance.execute(
      {},
      { toolCallId: "call-1", messages: [], abortSignal: undefined as any },
    );
    expect(result).toEqual({
      balanceCents: 5000,
      balanceUsd: 50.0,
      currency: "USD",
      lastToppedUp: "2026-02-15T10:00:00Z",
    });
    expect(mockClient.wallet.getBalance).toHaveBeenCalledOnce();
  });

  it("returns error on failure", async () => {
    mockClient.wallet.getBalance.mockRejectedValue(new Error("Unauthorized"));
    const result = await checkBalance.execute(
      {},
      { toolCallId: "call-2", messages: [], abortSignal: undefined as any },
    );
    expect(result).toHaveProperty("error");
    expect((result as any).error).toContain("Unauthorized");
  });
});

// ---------------------------------------------------------------------------
// checkUsage tool tests
// ---------------------------------------------------------------------------

describe("checkUsage tool", () => {
  let mockClient: ReturnType<typeof createMockClient>;
  let checkUsage: ReturnType<typeof createCheckUsageTool>;

  beforeEach(() => {
    mockClient = createMockClient();
    checkUsage = createCheckUsageTool(mockClient);
  });

  it("has correct description", () => {
    expect(checkUsage.description).toContain("usage");
  });

  it("returns usage summary without period", async () => {
    const result = await checkUsage.execute(
      {},
      { toolCallId: "call-1", messages: [], abortSignal: undefined as any },
    );
    expect(result).toHaveProperty("summary");
    expect((result as any).summary.totalGB).toBe(1.0);
    expect((result as any).summary.requestCount).toBe(1500);
    expect(mockClient.usage.get).toHaveBeenCalledOnce();
  });

  it("passes day period as date range", async () => {
    await checkUsage.execute(
      { period: "day" },
      { toolCallId: "call-2", messages: [], abortSignal: undefined as any },
    );
    const callArgs = mockClient.usage.get.mock.calls[0][0];
    expect(callArgs).toHaveProperty("from");
    expect(callArgs).toHaveProperty("to");
    // "from" should be approximately 24 hours ago
    const from = new Date(callArgs.from);
    const to = new Date(callArgs.to);
    const diffMs = to.getTime() - from.getTime();
    const diffHours = diffMs / (1000 * 60 * 60);
    expect(diffHours).toBeCloseTo(24, 0);
  });

  it("passes week period as date range", async () => {
    await checkUsage.execute(
      { period: "week" },
      { toolCallId: "call-3", messages: [], abortSignal: undefined as any },
    );
    const callArgs = mockClient.usage.get.mock.calls[0][0];
    const from = new Date(callArgs.from);
    const to = new Date(callArgs.to);
    const diffDays = (to.getTime() - from.getTime()) / (1000 * 60 * 60 * 24);
    expect(diffDays).toBeCloseTo(7, 0);
  });

  it("passes month period as date range", async () => {
    await checkUsage.execute(
      { period: "month" },
      { toolCallId: "call-4", messages: [], abortSignal: undefined as any },
    );
    const callArgs = mockClient.usage.get.mock.calls[0][0];
    const from = new Date(callArgs.from);
    const to = new Date(callArgs.to);
    const diffDays = (to.getTime() - from.getTime()) / (1000 * 60 * 60 * 24);
    expect(diffDays).toBeCloseTo(30, 0);
  });

  it("returns error on failure", async () => {
    mockClient.usage.get.mockRejectedValue(new Error("Server error"));
    const result = await checkUsage.execute(
      {},
      { toolCallId: "call-5", messages: [], abortSignal: undefined as any },
    );
    expect(result).toHaveProperty("error");
    expect((result as any).error).toContain("Server error");
  });
});

// ---------------------------------------------------------------------------
// getProxyConfig tool tests
// ---------------------------------------------------------------------------

describe("getProxyConfig tool", () => {
  let mockClient: ReturnType<typeof createMockClient>;
  let getProxyConfig: ReturnType<typeof createGetProxyConfigTool>;

  beforeEach(() => {
    mockClient = createMockClient();
    getProxyConfig = createGetProxyConfigTool(mockClient);
  });

  it("has correct description", () => {
    expect(getProxyConfig.description).toContain("proxy");
    expect(getProxyConfig.description).toContain("countries");
  });

  it("returns proxy configuration", async () => {
    const result = await getProxyConfig.execute(
      {},
      { toolCallId: "call-1", messages: [], abortSignal: undefined as any },
    );
    expect(result).toEqual({
      endpoints: {
        http: "proxy.dominusnode.com:8080",
        socks5: "proxy.dominusnode.com:1080",
      },
      supportedCountries: ["US", "GB", "DE", "JP"],
      blockedCountries: ["CU", "IR", "KP", "RU", "SY"],
      geoTargeting: {
        stateSupport: true,
        citySupport: true,
        asnSupport: false,
      },
    });
    expect(mockClient.proxy.getConfig).toHaveBeenCalledOnce();
  });

  it("provides default geoTargeting when missing", async () => {
    mockClient.proxy.getConfig.mockResolvedValue({
      httpProxy: { host: "proxy.dominusnode.com", port: 8080 },
      socks5Proxy: { host: "proxy.dominusnode.com", port: 1080 },
      supportedCountries: ["US"],
      blockedCountries: [],
      // No geoTargeting field
    });
    const result = await getProxyConfig.execute(
      {},
      { toolCallId: "call-2", messages: [], abortSignal: undefined as any },
    );
    expect((result as any).geoTargeting).toEqual({
      stateSupport: false,
      citySupport: false,
      asnSupport: false,
    });
  });

  it("returns error on failure", async () => {
    mockClient.proxy.getConfig.mockRejectedValue(new Error("Network failure"));
    const result = await getProxyConfig.execute(
      {},
      { toolCallId: "call-3", messages: [], abortSignal: undefined as any },
    );
    expect(result).toHaveProperty("error");
    expect((result as any).error).toContain("Network failure");
  });
});

// ---------------------------------------------------------------------------
// listSessions tool tests
// ---------------------------------------------------------------------------

describe("listSessions tool", () => {
  let mockClient: ReturnType<typeof createMockClient>;
  let listSessions: ReturnType<typeof createListSessionsTool>;

  beforeEach(() => {
    mockClient = createMockClient();
    listSessions = createListSessionsTool(mockClient);
  });

  it("has correct description", () => {
    expect(listSessions.description).toContain("sessions");
  });

  it("returns active sessions", async () => {
    const result = await listSessions.execute(
      {},
      { toolCallId: "call-1", messages: [], abortSignal: undefined as any },
    );
    expect(result).toEqual({
      sessions: [
        {
          id: "sess-abc",
          startedAt: "2026-02-19T08:00:00Z",
          status: "active",
        },
        {
          id: "sess-def",
          startedAt: "2026-02-19T08:30:00Z",
          status: "active",
        },
      ],
      count: 2,
    });
    expect(mockClient.sessions.getActive).toHaveBeenCalledOnce();
  });

  it("returns empty list when no sessions", async () => {
    mockClient.sessions.getActive.mockResolvedValue({ sessions: [] });
    const result = await listSessions.execute(
      {},
      { toolCallId: "call-2", messages: [], abortSignal: undefined as any },
    );
    expect((result as any).sessions).toEqual([]);
    expect((result as any).count).toBe(0);
  });

  it("returns error on failure", async () => {
    mockClient.sessions.getActive.mockRejectedValue(new Error("Timeout"));
    const result = await listSessions.execute(
      {},
      { toolCallId: "call-3", messages: [], abortSignal: undefined as any },
    );
    expect(result).toHaveProperty("error");
    expect((result as any).error).toContain("Timeout");
  });
});

// ---------------------------------------------------------------------------
// createDominusNodeTools factory tests
// ---------------------------------------------------------------------------

describe("createDominusNodeTools", () => {
  it("rejects empty API key", async () => {
    await expect(
      createDominusNodeTools({ apiKey: "" }),
    ).rejects.toThrow("apiKey is required");
  });

  it("rejects API key with wrong prefix", async () => {
    await expect(
      createDominusNodeTools({ apiKey: "sk_live_abc123" }),
    ).rejects.toThrow('must start with "dn_live_" or "dn_test_"');
  });
});

describe("createDominusNodeToolsFromClient", () => {
  it("creates all tools from an existing client", () => {
    const mockClient = createMockClient();
    const tools = createDominusNodeToolsFromClient(mockClient, "dn_live_abc123");
    expect(tools).toHaveProperty("proxiedFetch");
    expect(tools).toHaveProperty("checkBalance");
    expect(tools).toHaveProperty("checkUsage");
    expect(tools).toHaveProperty("getProxyConfig");
    expect(tools).toHaveProperty("listSessions");
    expect(tools).toHaveProperty("topupPaypal");
    expect(tools).toHaveProperty("topupStripe");
    expect(tools).toHaveProperty("topupCrypto");
  });

  it("rejects empty API key", () => {
    const mockClient = createMockClient();
    expect(() => createDominusNodeToolsFromClient(mockClient, "")).toThrow(
      "apiKey is required",
    );
  });
});
