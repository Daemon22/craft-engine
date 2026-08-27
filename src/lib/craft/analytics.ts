/**
 * Compatibility exports for the legacy compression analytics implementation.
 *
 * Analytics is implemented once in ../analytics.ts and re-exported here to
 * preserve the hardened barrel's declared API without creating divergent state.
 */
export { CompressionAnalytics, globalAnalytics } from '../analytics.js';
export type { CompressionObservation, StrategyStats, AnalyticsReport } from '../analytics.js';
