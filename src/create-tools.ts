import { DominusNodeClient } from "@dominusnode/sdk";
import {
  createProxiedFetchTool,
  createCheckBalanceTool,
  createCheckUsageTool,
  createGetProxyConfigTool,
  createListSessionsTool,
  createTopupPaypalTool,
  createTopupStripeTool,
  createTopupCryptoTool,
  createX402InfoTool,
  createCreateAgenticWalletTool,
  createFundAgenticWalletTool,
  createAgenticWalletBalanceTool,
  createListAgenticWalletsTool,
  createAgenticTransactionsTool,
  createFreezeAgenticWalletTool,
  createUnfreezeAgenticWalletTool,
  createDeleteAgenticWalletTool,
  createUpdateWalletPolicyTool,
  // Account lifecycle
  createRegisterTool,
  createLoginTool,
  createGetAccountInfoTool,
  createVerifyEmailTool,
  createResendVerificationTool,
  createUpdatePasswordTool,
  // API keys
  createListKeysTool,
  createCreateKeyTool,
  createRevokeKeyTool,
  // Wallet extended
  createGetTransactionsTool,
  createGetForecastTool,
  createCheckPaymentTool,
  // Usage extended
  createGetDailyUsageTool,
  createGetTopHostsTool,
  // Plans
  createGetPlanTool,
  createListPlansTool,
  createChangePlanTool,
  // Proxy extended
  createGetProxyStatusTool,
  // Teams (full 17-tool suite)
  createCreateTeamTool,
  createListTeamsTool,
  createTeamDetailsTool,
  createUpdateTeamTool,
  createTeamDeleteTool,
  createTeamFundTool,
  createTeamCreateKeyTool,
  createTeamRevokeKeyTool,
  createTeamListKeysTool,
  createTeamUsageTool,
  createTeamListMembersTool,
  createTeamAddMemberTool,
  createTeamRemoveMemberTool,
  createUpdateTeamMemberRoleTool,
  createTeamInviteMemberTool,
  createTeamListInvitesTool,
  createTeamCancelInviteTool,
} from "./tools.js";

/**
 * Configuration for creating Dominus Node AI tools.
 */
export interface DominusNodeToolsConfig {
  /**
   * Dominus Node API key for authentication.
   * Must start with "dn_live_" or "dn_test_".
   */
  apiKey: string;

  /**
   * Base URL for the Dominus Node API.
   * @default "https://api.dominusnode.com"
   */
  baseUrl?: string;

  /**
   * Proxy host override.
   * @default "proxy.dominusnode.com"
   */
  proxyHost?: string;

  /**
   * HTTP proxy port override.
   * @default 8080
   */
  httpProxyPort?: number;

  /**
   * SOCKS5 proxy port override.
   * @default 1080
   */
  socks5ProxyPort?: number;

  /**
   * Optional agent secret for MCP agent auto-verification (bypasses reCAPTCHA).
   * Falls back to DOMINUSNODE_AGENT_SECRET environment variable if not set.
   */
  agentSecret?: string;
}

/**
 * The full set of Dominus Node tools for use with the Vercel AI SDK.
 * Provides 53 tools covering the complete DomiNode API surface.
 */
export interface DominusNodeTools {
  // --- Proxy & Fetch ---
  /** Make HTTP requests through Dominus Node's rotating proxy network. */
  proxiedFetch: ReturnType<typeof createProxiedFetchTool>;
  /** Get proxy endpoint configuration and supported countries. */
  getProxyConfig: ReturnType<typeof createGetProxyConfigTool>;
  /** Get proxy health and status information. */
  getProxyStatus: ReturnType<typeof createGetProxyStatusTool>;

  // --- Sessions ---
  /** List all active proxy sessions. */
  listSessions: ReturnType<typeof createListSessionsTool>;

  // --- Wallet & Billing ---
  /** Check the current wallet balance. */
  checkBalance: ReturnType<typeof createCheckBalanceTool>;
  /** Get wallet transaction history. */
  getTransactions: ReturnType<typeof createGetTransactionsTool>;
  /** Get wallet balance forecast. */
  getForecast: ReturnType<typeof createGetForecastTool>;
  /** Top up wallet balance via PayPal. */
  topupPaypal: ReturnType<typeof createTopupPaypalTool>;
  /** Top up wallet balance via Stripe. */
  topupStripe: ReturnType<typeof createTopupStripeTool>;
  /** Top up wallet balance via cryptocurrency. */
  topupCrypto: ReturnType<typeof createTopupCryptoTool>;
  /** Check crypto payment invoice status. */
  checkPayment: ReturnType<typeof createCheckPaymentTool>;
  /** Get x402 micropayment protocol information. */
  x402Info: ReturnType<typeof createX402InfoTool>;

  // --- Usage ---
  /** Check proxy usage statistics for a given period. */
  checkUsage: ReturnType<typeof createCheckUsageTool>;
  /** Get daily usage breakdown. */
  getDailyUsage: ReturnType<typeof createGetDailyUsageTool>;
  /** Get top accessed hosts. */
  getTopHosts: ReturnType<typeof createGetTopHostsTool>;

  // --- Account Lifecycle ---
  /** Register a new account. */
  register: ReturnType<typeof createRegisterTool>;
  /** Log into an existing account. */
  login: ReturnType<typeof createLoginTool>;
  /** Get current account information. */
  getAccountInfo: ReturnType<typeof createGetAccountInfoTool>;
  /** Verify email with token. */
  verifyEmail: ReturnType<typeof createVerifyEmailTool>;
  /** Resend email verification. */
  resendVerification: ReturnType<typeof createResendVerificationTool>;
  /** Change account password. */
  updatePassword: ReturnType<typeof createUpdatePasswordTool>;

  // --- API Keys ---
  /** List all API keys. */
  listKeys: ReturnType<typeof createListKeysTool>;
  /** Create a new API key. */
  createKey: ReturnType<typeof createCreateKeyTool>;
  /** Revoke an API key. */
  revokeKey: ReturnType<typeof createRevokeKeyTool>;

  // --- Plans ---
  /** Get current user's plan. */
  getPlan: ReturnType<typeof createGetPlanTool>;
  /** List all available plans. */
  listPlans: ReturnType<typeof createListPlansTool>;
  /** Change plan. */
  changePlan: ReturnType<typeof createChangePlanTool>;

  // --- Agentic Wallets ---
  /** Create a new agentic sub-wallet. */
  createAgenticWallet: ReturnType<typeof createCreateAgenticWalletTool>;
  /** Fund an agentic sub-wallet. */
  fundAgenticWallet: ReturnType<typeof createFundAgenticWalletTool>;
  /** Check agentic wallet balance. */
  agenticWalletBalance: ReturnType<typeof createAgenticWalletBalanceTool>;
  /** List all agentic sub-wallets. */
  listAgenticWallets: ReturnType<typeof createListAgenticWalletsTool>;
  /** List agentic wallet transactions. */
  agenticTransactions: ReturnType<typeof createAgenticTransactionsTool>;
  /** Freeze an agentic wallet. */
  freezeAgenticWallet: ReturnType<typeof createFreezeAgenticWalletTool>;
  /** Unfreeze an agentic wallet. */
  unfreezeAgenticWallet: ReturnType<typeof createUnfreezeAgenticWalletTool>;
  /** Delete an agentic wallet. */
  deleteAgenticWallet: ReturnType<typeof createDeleteAgenticWalletTool>;
  /** Update agentic wallet policy. */
  updateWalletPolicy: ReturnType<typeof createUpdateWalletPolicyTool>;

  // --- Teams (full 17-tool suite) ---
  /** Create a new team. */
  createTeam: ReturnType<typeof createCreateTeamTool>;
  /** List all teams. */
  listTeams: ReturnType<typeof createListTeamsTool>;
  /** Get team details. */
  teamDetails: ReturnType<typeof createTeamDetailsTool>;
  /** Update team settings. */
  updateTeam: ReturnType<typeof createUpdateTeamTool>;
  /** Delete a team. */
  teamDelete: ReturnType<typeof createTeamDeleteTool>;
  /** Fund a team wallet. */
  teamFund: ReturnType<typeof createTeamFundTool>;
  /** Create a team API key. */
  teamCreateKey: ReturnType<typeof createTeamCreateKeyTool>;
  /** Revoke a team API key. */
  teamRevokeKey: ReturnType<typeof createTeamRevokeKeyTool>;
  /** List team API keys. */
  teamListKeys: ReturnType<typeof createTeamListKeysTool>;
  /** Get team usage stats. */
  teamUsage: ReturnType<typeof createTeamUsageTool>;
  /** List team members. */
  teamListMembers: ReturnType<typeof createTeamListMembersTool>;
  /** Add a member to team. */
  teamAddMember: ReturnType<typeof createTeamAddMemberTool>;
  /** Remove a member from team. */
  teamRemoveMember: ReturnType<typeof createTeamRemoveMemberTool>;
  /** Update a member's role. */
  updateTeamMemberRole: ReturnType<typeof createUpdateTeamMemberRoleTool>;
  /** Invite a member via email. */
  teamInviteMember: ReturnType<typeof createTeamInviteMemberTool>;
  /** List pending invitations. */
  teamListInvites: ReturnType<typeof createTeamListInvitesTool>;
  /** Cancel a pending invitation. */
  teamCancelInvite: ReturnType<typeof createTeamCancelInviteTool>;
}

/**
 * Create a full set of Vercel AI SDK tools for interacting with the Dominus Node
 * rotating proxy service. Provides 53 tools covering account lifecycle, proxy usage,
 * billing, teams, agentic wallets, plans, and more.
 *
 * @example
 * ```ts
 * import { createDominusNodeTools } from "@dominusnode/ai-tools";
 * import { generateText } from "ai";
 * import { openai } from "@ai-sdk/openai";
 *
 * const tools = await createDominusNodeTools({
 *   apiKey: process.env.DOMINUSNODE_API_KEY!,
 * });
 *
 * const result = await generateText({
 *   model: openai("gpt-4o"),
 *   tools,
 *   prompt: "Check my proxy balance, create a team, and fetch https://httpbin.org/ip through a US proxy",
 * });
 * ```
 */
export async function createDominusNodeTools(
  config: DominusNodeToolsConfig,
): Promise<DominusNodeTools> {
  // Validate API key format
  if (!config.apiKey || typeof config.apiKey !== "string") {
    throw new Error("apiKey is required and must be a non-empty string");
  }
  if (!config.apiKey.startsWith("dn_live_") && !config.apiKey.startsWith("dn_test_")) {
    throw new Error('apiKey must start with "dn_live_" or "dn_test_"');
  }

  // Resolve agent secret from config or environment
  const agentSecret = config.agentSecret || process.env.DOMINUSNODE_AGENT_SECRET;

  // Create and authenticate the client
  const client = new DominusNodeClient({
    apiKey: config.apiKey,
    baseUrl: config.baseUrl,
    proxyHost: config.proxyHost,
    agentSecret,
  } as any);

  await client.connectWithKey(config.apiKey);

  return buildTools(client, config.apiKey, agentSecret);
}

/**
 * Create Dominus Node AI tools from an already-authenticated client instance.
 * Use this when you manage the DominusNodeClient lifecycle yourself.
 *
 * @param client - An already-authenticated DominusNodeClient.
 * @param apiKey - The API key (needed for building proxy URLs).
 * @param agentSecret - Optional agent secret for MCP agent auto-verification.
 */
export function createDominusNodeToolsFromClient(
  client: DominusNodeClient,
  apiKey: string,
  agentSecret?: string,
): DominusNodeTools {
  if (!apiKey || typeof apiKey !== "string") {
    throw new Error("apiKey is required and must be a non-empty string");
  }

  const resolvedAgentSecret = agentSecret || process.env.DOMINUSNODE_AGENT_SECRET;
  return buildTools(client, apiKey, resolvedAgentSecret);
}

function buildTools(
  client: DominusNodeClient,
  apiKey: string,
  agentSecret?: string,
): DominusNodeTools {
  return {
    // Proxy & Fetch
    proxiedFetch: createProxiedFetchTool(client, apiKey),
    getProxyConfig: createGetProxyConfigTool(client),
    getProxyStatus: createGetProxyStatusTool(client, agentSecret),

    // Sessions
    listSessions: createListSessionsTool(client),

    // Wallet & Billing
    checkBalance: createCheckBalanceTool(client),
    getTransactions: createGetTransactionsTool(client, agentSecret),
    getForecast: createGetForecastTool(client, agentSecret),
    topupPaypal: createTopupPaypalTool(client),
    topupStripe: createTopupStripeTool(client),
    topupCrypto: createTopupCryptoTool(client),
    checkPayment: createCheckPaymentTool(client, agentSecret),
    x402Info: createX402InfoTool(client),

    // Usage
    checkUsage: createCheckUsageTool(client),
    getDailyUsage: createGetDailyUsageTool(client, agentSecret),
    getTopHosts: createGetTopHostsTool(client, agentSecret),

    // Account lifecycle
    register: createRegisterTool(agentSecret),
    login: createLoginTool(agentSecret),
    getAccountInfo: createGetAccountInfoTool(client, agentSecret),
    verifyEmail: createVerifyEmailTool(agentSecret),
    resendVerification: createResendVerificationTool(client, agentSecret),
    updatePassword: createUpdatePasswordTool(client, agentSecret),

    // API Keys
    listKeys: createListKeysTool(client, agentSecret),
    createKey: createCreateKeyTool(client, agentSecret),
    revokeKey: createRevokeKeyTool(client, agentSecret),

    // Plans
    getPlan: createGetPlanTool(client, agentSecret),
    listPlans: createListPlansTool(client, agentSecret),
    changePlan: createChangePlanTool(client, agentSecret),

    // Agentic Wallets
    createAgenticWallet: createCreateAgenticWalletTool(client, agentSecret),
    fundAgenticWallet: createFundAgenticWalletTool(client, agentSecret),
    agenticWalletBalance: createAgenticWalletBalanceTool(client, agentSecret),
    listAgenticWallets: createListAgenticWalletsTool(client, agentSecret),
    agenticTransactions: createAgenticTransactionsTool(client, agentSecret),
    freezeAgenticWallet: createFreezeAgenticWalletTool(client, agentSecret),
    unfreezeAgenticWallet: createUnfreezeAgenticWalletTool(client, agentSecret),
    deleteAgenticWallet: createDeleteAgenticWalletTool(client, agentSecret),
    updateWalletPolicy: createUpdateWalletPolicyTool(client, agentSecret),

    // Teams (full 17-tool suite)
    createTeam: createCreateTeamTool(client, agentSecret),
    listTeams: createListTeamsTool(client, agentSecret),
    teamDetails: createTeamDetailsTool(client, agentSecret),
    updateTeam: createUpdateTeamTool(client, agentSecret),
    teamDelete: createTeamDeleteTool(client, agentSecret),
    teamFund: createTeamFundTool(client, agentSecret),
    teamCreateKey: createTeamCreateKeyTool(client, agentSecret),
    teamRevokeKey: createTeamRevokeKeyTool(client, agentSecret),
    teamListKeys: createTeamListKeysTool(client, agentSecret),
    teamUsage: createTeamUsageTool(client, agentSecret),
    teamListMembers: createTeamListMembersTool(client, agentSecret),
    teamAddMember: createTeamAddMemberTool(client, agentSecret),
    teamRemoveMember: createTeamRemoveMemberTool(client, agentSecret),
    updateTeamMemberRole: createUpdateTeamMemberRoleTool(client, agentSecret),
    teamInviteMember: createTeamInviteMemberTool(client, agentSecret),
    teamListInvites: createTeamListInvitesTool(client, agentSecret),
    teamCancelInvite: createTeamCancelInviteTool(client, agentSecret),
  };
}
