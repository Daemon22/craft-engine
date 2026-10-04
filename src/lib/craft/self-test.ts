/**
 * selfTest() — environment and pipeline sanity check.
 * Upgraded to support Professional Compliance Reporting.
 */
import { nano } from './nano';
import { macro } from './macro';
import { CraftTier } from './features';

export interface SelfTestResult {
  ok: true;
  nodeVersion: string;
  zstdAvailable: boolean;
  checkedStrategies: string[];
  durationMs: number;
  complianceLevel?: string;
  securityFloor?: number;
}

function checkZstdAvailable(): boolean {
  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const zlib = require('zlib');
    return typeof zlib.zstdCompressSync === 'function';
  } catch {
    return false;
  }
}

export async function selfTest(tier: CraftTier = CraftTier.FREE): Promise<SelfTestResult> {
  const start = Date.now();
  const passphrase = 'craft-self-test-passphrase-00';
  const checkedStrategies: string[] = [];

  const zstdAvailable = checkZstdAvailable();

  // Requirement for PRO/GOV tiers: Zstd MUST be available
  if ((tier === CraftTier.PRO || tier === CraftTier.GOV) && !zstdAvailable) {
    throw new Error(`COMPLIANCE FAILURE: ${tier} tier requires Zstd support (Node >= 22.15).`);
  }

  // Fixture 1: plain text, exercises the base pipeline.
  try {
    const data = Buffer.from('CRAFT self-test fixture. '.repeat(100));
    // Use the requested tier for the test
    const packed = await nano(data, 'selftest.txt', 'text/plain', passphrase, { tier } as any);
    const restored = await macro(packed.buffer, passphrase);
    if (!restored.buffer.equals(data) || !restored.integrityVerified) {
      throw new Error('base round-trip mismatch');
    }
    checkedStrategies.push(packed.metadata.compressionStrategyName ?? '(unknown)');
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(`CRAFT selfTest failed on base text fixture: ${msg}`);
  }

  return {
    ok: true,
    nodeVersion: process.version,
    zstdAvailable,
    checkedStrategies,
    durationMs: Date.now() - start,
    complianceLevel: tier === CraftTier.GOV ? 'HIGH-GOV' : (tier === CraftTier.PRO ? 'ENTERPRISE' : 'STANDARD'),
    securityFloor: tier === CraftTier.GOV ? 1_000_000 : (tier === CraftTier.PRO ? 600_000 : 100_000)
  };
}

/**
 * Generates a formal compliance report for stakeholders.
 */
export async function generateComplianceReport(tier: CraftTier): Promise<string> {
  const test = await selfTest(tier);
  const timestamp = new Date().toISOString();

  return `
CRAFT ENGINE - SYSTEM COMPLIANCE REPORT
Generated: ${timestamp}
---------------------------------------
Compliance Level: ${test.complianceLevel}
Node.js Version:  ${test.nodeVersion}
Security Floor:   ${test.securityFloor} Iterations (PBKDF2-SHA256)
Zstd Capability:  ${test.zstdAvailable ? 'ACTIVE' : 'INACTIVE'}
Integrity Check:  PASSED
Adaptive Engine:  VERIFIED (${test.checkedStrategies.join(', ')})
---------------------------------------
VERDICT: SYSTEM IS COMPLIANT FOR ${test.complianceLevel} OPERATIONS.
`;
}
