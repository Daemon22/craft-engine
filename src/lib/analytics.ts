/**
 * @craft/analytics — Compression Strategy Analytics
 *
 * Tracks which compression strategies win most often across operations
 * and provides optimization hints for different data patterns.
 * Helps users understand what works best for their data.
 */

/** A single compression observation record */
export interface CompressionObservation {
  /** Original data size in bytes */
  inputSize: number;
  /** The winning strategy ID (0-7) */
  winningStrategy: number;
  /** Name of the winning strategy */
  winningStrategyName: string;
  /** Best compressed size */
  bestSize: number;
  /** All strategy results */
  allResults: Array<{ strategy: number; name: string; size: number }>;
  /** Timestamp of the observation */
  timestamp: number;
  /** Optional data type hint (text, json, binary, image, etc.) */
  dataType?: string;
}

/** Aggregated statistics for a strategy */
export interface StrategyStats {
  strategy: number;
  name: string;
  wins: number;
  totalEntries: number;
  winRate: number;
  avgCompressionRatio: number;
  bestCompressionRatio: number;
  worstCompressionRatio: number;
}

/** Overall analytics report */
export interface AnalyticsReport {
  /** Total observations recorded */
  totalObservations: number;
  /** Strategy stats sorted by win rate (descending) */
  strategies: StrategyStats[];
  /** Most common winner */
  topStrategy: StrategyStats | null;
  /** Average compression ratio across all observations */
  avgOverallRatio: number;
  /** Size distribution: percentage of observations in each size bucket */
  sizeDistribution: {
    small: number;   // < 1KB
    medium: number;  // 1KB - 100KB
    large: number;   // 100KB - 1MB
    xlarge: number;  // > 1MB
  };
  /** Optimization hints based on observed patterns */
  hints: string[];
}

/** In-memory analytics tracker */
export class CompressionAnalytics {
  private observations: CompressionObservation[] = [];
  private maxObservations: number;

  constructor(maxObservations: number = 10000) {
    this.maxObservations = maxObservations;
  }

  /** Record a new compression observation */
  record(observation: CompressionObservation): void {
    if (this.observations.length >= this.maxObservations) {
      this.observations.shift(); // Remove oldest
    }
    this.observations.push(observation);
  }

  /** Convenience: record from a compress7 result */
  recordFromResult(
    result: { strategy: number; strategyName: string; originalSize: number; compressedSize: number; allResults: Array<{ strategy: number; name: string; size: number }> },
    dataType?: string
  ): void {
    this.record({
      inputSize: result.originalSize,
      winningStrategy: result.strategy,
      winningStrategyName: result.strategyName,
      bestSize: result.compressedSize,
      allResults: result.allResults,
      timestamp: Date.now(),
      dataType,
    });
  }

  /** Get all recorded observations */
  getObservations(): CompressionObservation[] {
    return [...this.observations];
  }

  /** Clear all observations */
  clear(): void {
    this.observations = [];
  }

  /** Generate analytics report from recorded observations */
  report(): AnalyticsReport {
    const total = this.observations.length;

    if (total === 0) {
      return {
        totalObservations: 0,
        strategies: [],
        topStrategy: null,
        avgOverallRatio: 0,
        sizeDistribution: { small: 0, medium: 0, large: 0, xlarge: 0 },
        hints: ['No observations recorded yet. Run compressions to build analytics.'],
      };
    }

    // Aggregate per-strategy stats
    const strategyMap = new Map<number, { wins: number; ratios: number[]; name: string }>();

    for (const obs of this.observations) {
      // Track the winner
      if (!strategyMap.has(obs.winningStrategy)) {
        strategyMap.set(obs.winningStrategy, { wins: 0, ratios: [], name: obs.winningStrategyName });
      }
      strategyMap.get(obs.winningStrategy)!.wins++;

      // Track ratios for all strategies in this observation
      for (const r of obs.allResults) {
        if (!strategyMap.has(r.strategy)) {
          const name = r.name;
          strategyMap.set(r.strategy, { wins: 0, ratios: [], name });
        }
        const entry = strategyMap.get(r.strategy)!;
        const ratio = obs.inputSize > 0 ? r.size / obs.inputSize : 1;
        entry.ratios.push(ratio);
      }
    }

    // Build StrategyStats array
    const strategies: StrategyStats[] = [];
    for (const [strategy, data] of strategyMap) {
      const sortedRatios = [...data.ratios].sort((a, b) => a - b);
      strategies.push({
        strategy,
        name: data.name,
        wins: data.wins,
        totalEntries: total,
        winRate: data.wins / total,
        avgCompressionRatio: data.ratios.reduce((a, b) => a + b, 0) / data.ratios.length,
        bestCompressionRatio: sortedRatios[0],
        worstCompressionRatio: sortedRatios[sortedRatios.length - 1],
      });
    }

    // Sort by win rate descending
    strategies.sort((a, b) => b.winRate - a.winRate);

    const topStrategy = strategies[0] || null;

    // Overall average ratio
    let totalRatioSum = 0;
    for (const obs of this.observations) {
      totalRatioSum += obs.inputSize > 0 ? obs.bestSize / obs.inputSize : 1;
    }
    const avgOverallRatio = totalRatioSum / total;

    // Size distribution
    let small = 0, medium = 0, large = 0, xlarge = 0;
    for (const obs of this.observations) {
      if (obs.inputSize < 1024) small++;
      else if (obs.inputSize < 100 * 1024) medium++;
      else if (obs.inputSize < 1024 * 1024) large++;
      else xlarge++;
    }
    const sizeDistribution = {
      small: small / total,
      medium: medium / total,
      large: large / total,
      xlarge: xlarge / total,
    };

    // Generate optimization hints
    const hints = this.generateHints(strategies, sizeDistribution, avgOverallRatio);

    return {
      totalObservations: total,
      strategies,
      topStrategy,
      avgOverallRatio,
      sizeDistribution,
      hints,
    };
  }

  private generateHints(
    strategies: StrategyStats[],
    sizeDistribution: AnalyticsReport['sizeDistribution'],
    avgRatio: number,
  ): string[] {
    const hints: string[] = [];

    if (strategies.length === 0) return hints;

    const top = strategies[0];

    // Strategy dominance
    if (top.winRate > 0.7) {
      hints.push(`Strategy "${top.name}" dominates at ${(top.winRate * 100).toFixed(0)}% win rate. Your data pattern strongly favors this approach.`);
    } else if (top.winRate < 0.3) {
      hints.push('No single strategy dominates. The 7-fold adaptive engine is essential for your mixed data patterns.');
    }

    // Compression ratio hints
    if (avgRatio > 1.0) {
      hints.push('Average compression ratio exceeds 1.0 — some data may be expanding rather than compressing. Consider whether encryption overhead is acceptable for small files.');
    } else if (avgRatio < 0.3) {
      hints.push(`Excellent average compression ratio (${(avgRatio * 100).toFixed(0)}% of original). Your data is highly compressible.`);
    }

    // Size distribution hints
    if (sizeDistribution.small > 0.5) {
      hints.push('Most files are small (< 1KB). Compression overhead may not justify the cost — consider storing small files uncompressed.');
    }
    if (sizeDistribution.xlarge > 0.3) {
      hints.push('Significant portion of large files (> 1MB). Consider streaming processing for better memory efficiency.');
    }

    // Runner-up strategy insight
    if (strategies.length >= 2) {
      const runnerUp = strategies[1];
      if (runnerUp.winRate > 0.15) {
        hints.push(`Strategy "${runnerUp.name}" is a strong runner-up at ${(runnerUp.winRate * 100).toFixed(0)}%. It may be optimal for specific data types.`);
      }
    }

    return hints;
  }
}

/** Global analytics instance (shared across the process) */
export const globalAnalytics = new CompressionAnalytics();
