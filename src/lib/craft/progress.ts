import { appendFile } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';

export type CraftOperation = 'nano' | 'macro';
export type CraftProgressStatus = 'started' | 'completed' | 'failed';

/**
 * Safe, content-free progress emitted by a CRAFT operation.
 * Never put passphrases, keys, filenames, file contents, or raw errors here.
 */
export interface CraftProgressEvent {
  readonly version: 1;
  readonly operation_id: string;
  readonly operation: CraftOperation;
  readonly step: string;
  readonly status: CraftProgressStatus;
  readonly timestamp: string;
  readonly duration_ms?: number;
  readonly details?: Readonly<Record<string, string | number | boolean | null>>;
}

export type CraftProgressObserver = (
  event: CraftProgressEvent,
) => void | Promise<void>;
export type CraftProgressDetails = Readonly<Record<string, string | number | boolean | null>>;

export interface CraftProgressOptions {
  /** Receives content-free lifecycle events. Callback errors stop the operation. */
  onProgress?: CraftProgressObserver;
  /** Reuse an ID when several CRAFT calls belong to one monitored process. */
  operationId?: string;
}

export class CraftProgressObserverError extends Error {
  constructor() {
    super('The CRAFT progress observer failed. The operation was stopped.');
    this.name = 'CraftProgressObserverError';
  }
}

/**
 * Create an observer that appends one safe JSON event per line.
 * The file is an event stream, not an artifact store; Vault can own artifacts
 * independently without coupling CRAFT to its storage policy.
 */
export function jsonlProgressObserver(filePath: string): CraftProgressObserver {
  return async (event) => {
    await appendFile(filePath, `${JSON.stringify(event)}\n`, {
      encoding: 'utf8',
      mode: 0o600,
    });
  };
}

export class CraftProgressReporter {
  readonly operationId: string;

  private readonly observer?: CraftProgressObserver;
  private readonly prefix: string;

  constructor(
    readonly operation: CraftOperation,
    options: CraftProgressOptions = {},
    prefix = '',
  ) {
    this.operationId = options.operationId || randomUUID();
    this.observer = options.onProgress;
    this.prefix = prefix;
  }

  scope(prefix: string): CraftProgressReporter {
    return new CraftProgressReporter(
      this.operation,
      { operationId: this.operationId, onProgress: this.observer },
      `${this.prefix}${prefix}.`,
    );
  }

  async lifecycle(
    status: CraftProgressStatus,
    durationMs?: number,
    details?: Readonly<Record<string, string | number | boolean | null>>,
  ): Promise<void> {
    await this.emit('operation', status, durationMs, details);
  }

  async step<T>(
    name: string,
    action: () => T | Promise<T>,
    details?: CraftProgressDetails | ((result: T) => CraftProgressDetails),
  ): Promise<T> {
    const step = `${this.prefix}${name}`;
    const startedAt = Date.now();
    const startedDetails = typeof details === 'function' ? undefined : details;
    await this.emit(step, 'started', undefined, startedDetails);

    let result: T;
    try {
      result = await action();
    } catch (error) {
      const errorType = safeErrorType(error);
      await this.emit(step, 'failed', Date.now() - startedAt, { error_type: errorType });
      throw error;
    }

    const completedDetails = typeof details === 'function' ? details(result) : details;
    await this.emit(step, 'completed', Date.now() - startedAt, completedDetails);
    return result;
  }

  private async emit(
    step: string,
    status: CraftProgressStatus,
    durationMs?: number,
    details?: Readonly<Record<string, string | number | boolean | null>>,
  ): Promise<void> {
    if (!this.observer) return;
    const safeDetails = details ? filterSafeDetails(details) : undefined;
    const event: CraftProgressEvent = Object.freeze({
      version: 1,
      operation_id: this.operationId,
      operation: this.operation,
      step,
      status,
      timestamp: new Date().toISOString(),
      ...(durationMs === undefined ? {} : { duration_ms: durationMs }),
      ...(safeDetails === undefined ? {} : { details: Object.freeze(safeDetails) }),
    });
    try {
      await this.observer(event);
    } catch {
      throw new CraftProgressObserverError();
    }
  }
}

export async function monitorCraftOperation<T>(
  operation: CraftOperation,
  options: CraftProgressOptions | undefined,
  action: (progress: CraftProgressReporter) => Promise<T>,
  details?: CraftProgressDetails,
): Promise<T> {
  const progress = new CraftProgressReporter(operation, options);
  const startedAt = Date.now();
  await progress.lifecycle('started', undefined, details);
  let result: T;
  try {
    result = await action(progress);
  } catch (error) {
    const errorType = safeErrorType(error);
    await progress.lifecycle('failed', Date.now() - startedAt, { error_type: errorType });
    throw error;
  }
  await progress.lifecycle('completed', Date.now() - startedAt);
  return result;
}

const SAFE_DETAIL_KEYS = new Set([
  'algorithm',
  'compression_mode',
  'compression_strategy',
  'compressed_size_bytes',
  'error_type',
  'input_size_bytes',
  'iterations',
  'metadata_encrypted',
  'operation_mode',
  'package_payload_size_bytes',
  'package_size_bytes',
  'restored_size_bytes',
  'strategy_number',
]);

function filterSafeDetails(
  details: CraftProgressDetails,
): Record<string, string | number | boolean | null> {
  const safe: Record<string, string | number | boolean | null> = {};
  for (const [key, value] of Object.entries(details)) {
    if (!SAFE_DETAIL_KEYS.has(key)) continue;
    if (key === 'error_type') {
      safe[key] = typeof value === 'string' && /^[A-Za-z][A-Za-z0-9]{0,63}$/.test(value)
        ? value
        : 'Error';
    } else if (typeof value === 'string') {
      safe[key] = value.slice(0, 80);
    } else if (typeof value === 'number' && Number.isFinite(value)) {
      safe[key] = value;
    } else if (typeof value === 'boolean' || value === null) {
      safe[key] = value;
    }
  }
  return safe;
}

function safeErrorType(error: unknown): string {
  const name = error instanceof Error ? error.name : typeof error;
  return /^[A-Za-z][A-Za-z0-9]{0,63}$/.test(name) ? name : 'Error';
}
