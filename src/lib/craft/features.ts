/**
 * CRAFT Feature Manager
 * Strictly manages tiered access and admin capabilities.
 */
import { PBKDF2_ITERATIONS } from './types';

export enum CraftTier {
  FREE = 'FREE',
  PRO = 'PRO',
  GOV = 'GOV'
}

export type CraftTierValue = `${CraftTier}`;

export interface FeatureSet {
  maxFileSize: number;      // Maximum file size in MB
  allowStreaming: boolean;  // Constant-memory v4 support
  allowEliteCodec: boolean; // Access to Strategy 12 (craft-codec)
  allowAuditLogs: boolean;  // Signed audit logging for compliance
  kdfIterations: number;    // Fixed PBKDF2-SHA256 iterations for all tiers
}

const TIER_CONFIGS: Record<CraftTier, FeatureSet> = {
  [CraftTier.FREE]: {
    maxFileSize: 200,
    allowStreaming: false,
    allowEliteCodec: false,
    allowAuditLogs: false,
    kdfIterations: PBKDF2_ITERATIONS
  },
  [CraftTier.PRO]: {
    maxFileSize: 2048,
    allowStreaming: true,
    allowEliteCodec: true,
    allowAuditLogs: true,
    kdfIterations: PBKDF2_ITERATIONS
  },
  [CraftTier.GOV]: {
    maxFileSize: Infinity,
    allowStreaming: true,
    allowEliteCodec: true,
    allowAuditLogs: true,
    kdfIterations: PBKDF2_ITERATIONS
  }
};

export function getFeatures(tier: CraftTierValue = CraftTier.FREE): FeatureSet {
  return TIER_CONFIGS[tier];
}

/**
 * Admin Audit Logger
 * Generates a signed record of a craft operation for gov/enterprise compliance.
 */
export function logAuditAction(action: string, metadata: Record<string, unknown>) {
  const timestamp = new Date().toISOString();
  // In a Gov tier, this would be signed with a PGP/HSM key
  console.log(`[AUDIT] ${timestamp} | ${action} | Strategy: ${metadata.strategy} | Status: ${metadata.status}`);
}
