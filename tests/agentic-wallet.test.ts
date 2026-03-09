import { describe, it, expect, vi, beforeEach } from "vitest";

// Mock the 'ai' module
vi.mock("ai", () => ({
  tool: (config: any) => config,
}));

// We need to mock fetch globally
const mockFetch = vi.fn();
vi.stubGlobal("fetch", mockFetch);

import {
  createCreateAgenticWalletTool,
  createFundAgenticWalletTool,
  createAgenticWalletBalanceTool,
  createListAgenticWalletsTool,
  createAgenticTransactionsTool,
  createFreezeAgenticWalletTool,
  createUnfreezeAgenticWalletTool,
  createDeleteAgenticWalletTool,
  createUpdateWalletPolicyTool,
  validateUrl,
  isPrivateIp,
} from "../src/tools.js";

// Mock client
function createMockClient() {
  return {
    baseUrl: "https://api.dominusnode.com",
    apiKey: "dn_live_testkey123",
    proxy: {
      buildUrl: vi.fn().mockReturnValue("http://user:pass@proxy:8080"),
      getConfig: vi.fn(),
    },
    wallet: {
      getBalance: vi.fn(),
      topupPaypal: vi.fn(),
      topupStripe: vi.fn(),
      topupCrypto: vi.fn(),
    },
    usage: { get: vi.fn() },
    sessions: { getActive: vi.fn() },
    x402: { getInfo: vi.fn() },
  } as any;
}

function mockJsonResponse(data: any, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: () => Promise.resolve(data),
    text: () => Promise.resolve(JSON.stringify(data)),
  };
}

describe("Agentic Wallet Tools", () => {
  let client: any;

  beforeEach(() => {
    client = createMockClient();
    mockFetch.mockReset();
  });

  // ── Create Agentic Wallet ──────────────────────────────────────────

  describe("createCreateAgenticWalletTool", () => {
    it("creates a wallet with valid inputs", async () => {
      mockFetch.mockResolvedValueOnce(mockJsonResponse({ id: "abc-123", label: "My Agent", status: "active" }));
      const toolDef = createCreateAgenticWalletTool(client);
      const result = await toolDef.execute({ label: "My Agent", spending_limit_cents: 5000 });
      expect(result.id).toBe("abc-123");
      expect(result.label).toBe("My Agent");
      expect(mockFetch).toHaveBeenCalledOnce();
    });

    it("rejects control characters in label", async () => {
      const toolDef = createCreateAgenticWalletTool(client);
      const result = await toolDef.execute({ label: "test\x00wallet", spending_limit_cents: 5000 });
      expect(result.error).toContain("control characters");
    });

    it("passes optional daily_limit_cents and allowed_domains", async () => {
      mockFetch.mockResolvedValueOnce(mockJsonResponse({ id: "def-456" }));
      const toolDef = createCreateAgenticWalletTool(client);
      await toolDef.execute({
        label: "Agent", spending_limit_cents: 1000,
        daily_limit_cents: 500, allowed_domains: ["example.com"],
      });
      const callBody = JSON.parse(mockFetch.mock.calls[0][1].body);
      expect(callBody.dailyLimitCents).toBe(500);
      expect(callBody.allowedDomains).toEqual(["example.com"]);
    });

    it("handles API error", async () => {
      mockFetch.mockResolvedValueOnce(mockJsonResponse({ error: "Unauthorized" }, 401));
      const toolDef = createCreateAgenticWalletTool(client);
      const result = await toolDef.execute({ label: "Test", spending_limit_cents: 1000 });
      expect(result.error).toBeDefined();
    });

    it("scrubs credentials from errors", async () => {
      mockFetch.mockRejectedValueOnce(new Error("Auth failed for dn_live_secret123"));
      const toolDef = createCreateAgenticWalletTool(client);
      const result = await toolDef.execute({ label: "Test", spending_limit_cents: 1000 });
      expect(result.error).toBeDefined();
      expect(result.error).not.toContain("dn_live_secret123");
      expect(result.error).toContain("***");
    });
  });

  // ── Fund Agentic Wallet ────────────────────────────────────────────

  describe("createFundAgenticWalletTool", () => {
    it("funds a wallet successfully", async () => {
      mockFetch.mockResolvedValueOnce(mockJsonResponse({ balanceCents: 1500 }));
      const toolDef = createFundAgenticWalletTool(client);
      const result = await toolDef.execute({
        wallet_id: "12345678-1234-1234-1234-123456789012",
        amount_cents: 1000,
      });
      expect(result.balanceCents).toBe(1500);
    });

    it("handles API error", async () => {
      mockFetch.mockResolvedValueOnce(mockJsonResponse({ error: "Not found" }, 404));
      const toolDef = createFundAgenticWalletTool(client);
      const result = await toolDef.execute({
        wallet_id: "12345678-1234-1234-1234-123456789012",
        amount_cents: 1000,
      });
      expect(result.error).toBeDefined();
    });
  });

  // ── Balance ────────────────────────────────────────────────────────

  describe("createAgenticWalletBalanceTool", () => {
    it("returns wallet details", async () => {
      mockFetch.mockResolvedValueOnce(mockJsonResponse({
        id: "12345678-1234-1234-1234-123456789012",
        label: "Test", balanceCents: 2500, status: "active",
      }));
      const toolDef = createAgenticWalletBalanceTool(client);
      const result = await toolDef.execute({ wallet_id: "12345678-1234-1234-1234-123456789012" });
      expect(result.balanceCents).toBe(2500);
      expect(result.label).toBe("Test");
    });
  });

  // ── List ───────────────────────────────────────────────────────────

  describe("createListAgenticWalletsTool", () => {
    it("lists wallets", async () => {
      mockFetch.mockResolvedValueOnce(mockJsonResponse({
        wallets: [{ id: "a", label: "W1" }, { id: "b", label: "W2" }],
      }));
      const toolDef = createListAgenticWalletsTool(client);
      const result = await toolDef.execute({});
      expect(result.wallets).toHaveLength(2);
    });
  });

  // ── Transactions ───────────────────────────────────────────────────

  describe("createAgenticTransactionsTool", () => {
    it("lists transactions", async () => {
      mockFetch.mockResolvedValueOnce(mockJsonResponse({
        transactions: [{ type: "fund", amountCents: 500 }],
      }));
      const toolDef = createAgenticTransactionsTool(client);
      const result = await toolDef.execute({ wallet_id: "12345678-1234-1234-1234-123456789012" });
      expect(result.transactions).toHaveLength(1);
    });

    it("passes limit as query param", async () => {
      mockFetch.mockResolvedValueOnce(mockJsonResponse({ transactions: [] }));
      const toolDef = createAgenticTransactionsTool(client);
      await toolDef.execute({ wallet_id: "12345678-1234-1234-1234-123456789012", limit: 10 });
      expect(mockFetch.mock.calls[0][0]).toContain("?limit=10");
    });
  });

  // ── Freeze ─────────────────────────────────────────────────────────

  describe("createFreezeAgenticWalletTool", () => {
    it("freezes a wallet", async () => {
      mockFetch.mockResolvedValueOnce(mockJsonResponse({ status: "frozen" }));
      const toolDef = createFreezeAgenticWalletTool(client);
      const result = await toolDef.execute({ wallet_id: "12345678-1234-1234-1234-123456789012" });
      expect(result.status).toBe("frozen");
    });
  });

  // ── Unfreeze ───────────────────────────────────────────────────────

  describe("createUnfreezeAgenticWalletTool", () => {
    it("unfreezes a wallet", async () => {
      mockFetch.mockResolvedValueOnce(mockJsonResponse({ status: "active" }));
      const toolDef = createUnfreezeAgenticWalletTool(client);
      const result = await toolDef.execute({ wallet_id: "12345678-1234-1234-1234-123456789012" });
      expect(result.status).toBe("active");
    });
  });

  // ── Delete ─────────────────────────────────────────────────────────

  describe("createDeleteAgenticWalletTool", () => {
    it("deletes a wallet", async () => {
      mockFetch.mockResolvedValueOnce(mockJsonResponse({ deleted: true }));
      const toolDef = createDeleteAgenticWalletTool(client);
      const result = await toolDef.execute({ wallet_id: "12345678-1234-1234-1234-123456789012" });
      expect(result.deleted).toBe(true);
    });

    it("handles delete error", async () => {
      mockFetch.mockResolvedValueOnce(mockJsonResponse({ error: "Forbidden" }, 403));
      const toolDef = createDeleteAgenticWalletTool(client);
      const result = await toolDef.execute({ wallet_id: "12345678-1234-1234-1234-123456789012" });
      expect(result.error).toBeDefined();
    });
  });

  // ── Update Policy ──────────────────────────────────────────────────

  describe("createUpdateWalletPolicyTool", () => {
    it("updates daily limit", async () => {
      mockFetch.mockResolvedValueOnce(mockJsonResponse({ dailyLimitCents: 5000 }));
      const toolDef = createUpdateWalletPolicyTool(client);
      const result = await toolDef.execute({
        wallet_id: "12345678-1234-1234-1234-123456789012",
        daily_limit_cents: 5000,
      });
      expect(result.dailyLimitCents).toBe(5000);
    });

    it("updates allowed domains", async () => {
      mockFetch.mockResolvedValueOnce(mockJsonResponse({ allowedDomains: ["example.com"] }));
      const toolDef = createUpdateWalletPolicyTool(client);
      const result = await toolDef.execute({
        wallet_id: "12345678-1234-1234-1234-123456789012",
        allowed_domains: ["example.com"],
      });
      expect(result.allowedDomains).toEqual(["example.com"]);
    });

    it("rejects empty body", async () => {
      const toolDef = createUpdateWalletPolicyTool(client);
      const result = await toolDef.execute({
        wallet_id: "12345678-1234-1234-1234-123456789012",
      });
      expect(result.error).toContain("At least one");
    });
  });

  // ── API Request Auth ───────────────────────────────────────────────

  describe("apiRequest authentication", () => {
    it("sends Bearer token in Authorization header", async () => {
      mockFetch.mockResolvedValueOnce(mockJsonResponse({ wallets: [] }));
      const toolDef = createListAgenticWalletsTool(client);
      await toolDef.execute({});
      const headers = mockFetch.mock.calls[0][1].headers;
      expect(headers.Authorization).toBe("Bearer dn_live_testkey123");
    });

    it("sends correct URL path", async () => {
      mockFetch.mockResolvedValueOnce(mockJsonResponse({}));
      const toolDef = createAgenticWalletBalanceTool(client);
      await toolDef.execute({ wallet_id: "12345678-1234-1234-1234-123456789012" });
      expect(mockFetch.mock.calls[0][0]).toBe(
        "https://api.dominusnode.com/api/agent-wallet/12345678-1234-1234-1234-123456789012"
      );
    });
  });
});
