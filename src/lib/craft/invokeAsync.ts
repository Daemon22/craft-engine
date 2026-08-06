/**
 * ═══════════════════════════════════════════════════════════════
 *  @craft/invokeAsync — worker_threads offload for the async engine
 * ═══════════════════════════════════════════════════════════════
 *
 *  The async compress7 engine runs Brotli/Zstd on the libuv threadpool, but a
 *  few operations are synchronous pure JS with no threadpool variant:
 *    • Craft-Codec compress/decompress  (@manya/craft-codec — order-1 range coder)
 *    • RLE / BPE pre-processing transforms (allocation-heavy on multi-MB input)
 *
 *  This module moves those off the main thread with ONE lazily-created,
 *  process-lifetime worker_threads eval worker. Spawning a worker thread costs
 *  tens-to-hundreds of ms (measured up to ~1s for the first spawn on Windows),
 *  so per-call spawning would dwarf the work being offloaded — the single
 *  reused worker amortizes that cost, serializing requests through a promise
 *  chain. The worker is:
 *    • ref()'d while a request is in flight (so the process can't exit before
 *      the reply) and unref()'d when idle (so CLI runs exit immediately).
 *    • terminated after IDLE_TERMINATE_MS of disuse so long-lived servers
 *      don't keep a sleeping thread around; the next call respawns it.
 *
 *  The worker is a SELF-CONTAINED source string (no file on disk, no relative
 *  imports), assembled at module load from the actual transform functions via
 *  `fn.toString()`, so it works identically whether the library is consumed
 *  from `dist/cjs` (compiled), from `src` under vitest, or bundled by Next —
 *  there is no file-path resolution to get wrong and no dual CJS/ESM build
 *  divergence.
 *
 *  The worker receives the command + a Buffer (structured-cloned), requires
 *  @manya/craft-codec by the absolute path passed in `workerData`, and posts
 *  back the result Buffer. Everything is byte-identical to running the same
 *  functions synchronously — the transforms are pure functions of their input
 *  and Craft-Codec is deterministic.
 *
 *  Offload policy:
 *    • RLE/BPE transforms: only offloaded at/above WORKER_OFFLOAD_MIN_SIZE —
 *      below that the synchronous cost (microseconds to low ms) is less than
 *      the serialization overhead, so running them inline is faster.
 *    • Craft-Codec: always offloaded (its compute dominates even at the async
 *      engine's small gate, and legacy sync-engine payloads can be multi-MB).
 *  If the worker cannot be spawned (e.g. bundled contexts without node_modules),
 *  every call falls back to the synchronous equivalent, so the async engine
 *  degrades gracefully rather than failing.
 */

import { Worker } from 'worker_threads';
import { createRequire } from 'module';
import { join } from 'path';
import { existsSync } from 'fs';
import {
  rleEncode,
  rleDecode,
  bpeEncode,
  bpeDecode,
} from './transforms';
import {
  compress as craftCodecCompressSync,
  decompress as craftCodecDecompressSync,
} from '@manya/craft-codec';

/** Transforms worth shipping to a worker thread. (Delta/MTF stay on the main
 *  thread — they're ~1GB/s O(n) passes already chunked with `setImmediate`
 *  yields, so offloading would cost more than the work itself.) */
export type OffloadableTransform = 'rleEncode' | 'rleDecode' | 'bpeEncode' | 'bpeDecode';

/** Every command the worker understands. */
export type WorkerCommand = OffloadableTransform | 'craftCodecCompress' | 'craftCodecDecompress';

/** Below this size an RLE/BPE transform runs synchronously (faster than the
 *  worker round-trip); at/above it is offloaded so the event loop never stalls
 *  on a multi-MB allocation-heavy pass. */
export const WORKER_OFFLOAD_MIN_SIZE = 256 * 1024;

/** Generous upper bound for one offloaded call (legacy multi-MB craft-codec
 *  payloads are ~1s/MB in the worst case). */
const WORKER_TIMEOUT_MS = 120_000;

/** How long an idle worker is kept around before its thread is released. */
const IDLE_TERMINATE_MS = 30_000;

interface WorkerRequest {
  id: string;
  cmd: WorkerCommand;
  input: Uint8Array;
}

interface WorkerResponse {
  id: string;
  result?: Uint8Array;
  error?: string;
}

// ─────────────────────────────────────────────────────────────
// Worker source assembly
// ─────────────────────────────────────────────────────────────

/**
 * The transform functions are serialized into the worker source verbatim.
 * They must stay pure standalone functions (no closures over module state) —
 * that constraint is documented at the top of ./transforms.
 */
const WORKER_SOURCE = `
'use strict';
const { parentPort, workerData } = require('worker_threads');

const rleEncode = (${rleEncode.toString()});
const rleDecode = (${rleDecode.toString()});
const bpeEncode = (${bpeEncode.toString()});
const bpeDecode = (${bpeDecode.toString()});

// Craft-Codec is required lazily so RLE/BPE-only workers never touch it (and
// a missing codec path never breaks the pure transforms).
let codec = null;
function getCodec() {
  if (codec === null) codec = require(workerData.codecPath);
  return codec;
}

const handlers = {
  rleEncode,
  rleDecode,
  bpeEncode,
  bpeDecode,
  craftCodecCompress: (input) => getCodec().compress(input),
  craftCodecDecompress: (input) => getCodec().decompress(input),
};

parentPort.on('message', (msg) => {
  const { id, cmd, input } = msg;
  try {
    const fn = handlers[cmd];
    if (typeof fn !== 'function') throw new Error('Unknown worker command: ' + cmd);
    const result = fn(Buffer.from(input));
    parentPort.postMessage({ id, result });
  } catch (e) {
    parentPort.postMessage({ id, error: e instanceof Error ? e.message : String(e) });
  }
});
`;

// ─────────────────────────────────────────────────────────────
// Craft-Codec path resolution
// ─────────────────────────────────────────────────────────────

let cachedCodecPath: string | null | undefined;

/** Resolve the on-disk location of @manya/craft-codec so the worker can
 *  `require` it. Tries the caller's module resolution first (CJS builds),
 *  then a `createRequire` rooted at the process cwd (ESM/vitest/Next). Returns
 *  null when unresolvable — callers then fall back to the sync equivalent. */
function resolveCodecPath(): string | null {
  if (cachedCodecPath !== undefined) return cachedCodecPath;
  const candidates: string[] = [];

  // CJS builds (dist/cjs, CLI, require() consumers): resolve from this module.
  try {
    if (typeof require !== 'undefined' && typeof (require as NodeRequire).resolve === 'function') {
      candidates.push((require as NodeRequire).resolve('@manya/craft-codec'));
    }
  } catch { /* resolution failed — try the next candidate */ }

  // ESM/vitest/Next contexts: require isn't the CJS loader, so fall back to a
  // createRequire rooted at cwd (the repo root under vitest, the app root for
  // consumers).
  try {
    candidates.push(createRequire(join(process.cwd(), 'craft-noop.js')).resolve('@manya/craft-codec'));
  } catch { /* resolution failed — try the next candidate */ }

  for (const candidate of candidates) {
    try {
      if (existsSync(candidate)) {
        cachedCodecPath = candidate;
        return candidate;
      }
    } catch { /* keep searching */ }
  }

  cachedCodecPath = null;
  return null;
}

// ─────────────────────────────────────────────────────────────
// Persistent worker lifecycle
// ─────────────────────────────────────────────────────────────

let worker: Worker | null = null;
let idleTimer: NodeJS.Timeout | null = null;
let inFlight: { resolve: (value: Buffer) => void; reject: (err: Error) => void } | null = null;

/** Spawn the worker on first use (thread creation is async — no main-thread
 *  stall) and attach the process-wide error/exit handlers. */
function ensureWorker(): Worker {
  if (worker) return worker;
  worker = new Worker(WORKER_SOURCE, {
    eval: true,
    workerData: { codecPath: resolveCodecPath() },
  });
  worker.on('error', () => terminateWorker());
  worker.on('exit', () => terminateWorker());
  return worker;
}

/** Tear the worker down (idle timeout, or it crashed). Rejects any request
 *  still waiting on it — its caller falls back to the sync equivalent. */
function terminateWorker(): void {
  if (idleTimer) {
    clearTimeout(idleTimer);
    idleTimer = null;
  }
  if (inFlight) {
    const p = inFlight;
    inFlight = null;
    p.reject(new Error('Worker terminated before replying.'));
  }
  const w = worker;
  worker = null;
  if (w) {
    w.terminate().catch(() => { /* best effort */ });
  }
}

/** Release the idle worker's thread after IDLE_TERMINATE_MS of disuse. The
 *  timer is unref'd so it never keeps a CLI process alive on its own. */
function armIdleTimer(): void {
  if (idleTimer) clearTimeout(idleTimer);
  idleTimer = setTimeout(() => terminateWorker(), IDLE_TERMINATE_MS);
  idleTimer.unref();
}

// ─────────────────────────────────────────────────────────────
// Serialized one-shot invocation
// ─────────────────────────────────────────────────────────────

let requestCounter = 0;

/** Run one command on the shared worker. Requests are serialized through a
 *  promise chain (one in flight at a time — all our call sites are sequential,
 *  and the chain keeps the reply matching trivially simple). Rejects on worker
 *  error/exit/timeout — callers decide whether to fall back. */
function runInWorker(cmd: WorkerCommand, input: Buffer): Promise<Buffer> {
  const job = chain.then(() => dispatch(cmd, input));
  // Keep the chain alive through rejections so one bad job can't wedge later
  // requests.
  chain = job.then(
    () => undefined,
    () => undefined,
  );
  return job;
}

/** Wait for the previous request to finish before posting the next. */
let chain: Promise<unknown> = Promise.resolve();

function dispatch(cmd: WorkerCommand, input: Buffer): Promise<Buffer> {
  return new Promise<Buffer>((resolve, reject) => {
    let w: Worker;
    try {
      w = ensureWorker();
    } catch (err) {
      reject(err instanceof Error ? err : new Error(String(err)));
      return;
    }

    // Ref the worker while the request is in flight so the process can't exit
    // (beforeExit) before the reply arrives.
    w.ref();
    const id = `craft-${Date.now()}-${++requestCounter}`;
    inFlight = { resolve, reject };

    const timer = setTimeout(() => {
      cleanup();
      reject(new Error(`Worker timed out after ${WORKER_TIMEOUT_MS}ms for command '${cmd}'.`));
    }, WORKER_TIMEOUT_MS);
    timer.unref();

    const onMessage = (msg: WorkerResponse) => {
      if (msg.id !== id) return;
      cleanup();
      if (msg.error !== undefined) {
        reject(new Error(msg.error));
      } else if (msg.result) {
        resolve(Buffer.from(msg.result));
      } else {
        reject(new Error(`Worker returned an empty response for command '${cmd}'.`));
      }
    };
    const cleanup = () => {
      clearTimeout(timer);
      w.removeListener('message', onMessage);
      if (inFlight) inFlight = null;
      w.unref();
      armIdleTimer();
    };

    w.on('message', onMessage);
    const request: WorkerRequest = { id, cmd, input };
    w.postMessage(request);
  });
}

// ─────────────────────────────────────────────────────────────
// Public offload helpers
// ─────────────────────────────────────────────────────────────

/**
 * Run an RLE/BPE transform, offloading to the shared worker thread when the
 * input is large enough to justify the round-trip. Byte-identical to
 * `fallback` in both cases; falls back to the sync `fallback` if the worker
 * cannot run.
 */
export async function offloadTransform(
  cmd: OffloadableTransform,
  fallback: (input: Buffer) => Buffer,
  input: Buffer,
): Promise<Buffer> {
  if (input.length < WORKER_OFFLOAD_MIN_SIZE) {
    return fallback(input);
  }
  try {
    return await runInWorker(cmd, input);
  } catch {
    return fallback(input);
  }
}

/** Async Craft-Codec compress off the main thread. Falls back to the sync
 *  codec (already imported here) if the worker cannot run. */
export async function craftCodecCompressAsync(input: Buffer): Promise<Buffer> {
  try {
    return await runInWorker('craftCodecCompress', input);
  } catch {
    return craftCodecCompressSync(input);
  }
}

/** Async Craft-Codec decompress off the main thread (the legacy strategy-12
 *  restore path — unbounded payload sizes, so this is the big stall remover).
 *  Falls back to the sync codec if the worker cannot run. */
export async function craftCodecDecompressAsync(input: Buffer): Promise<Buffer> {
  try {
    return await runInWorker('craftCodecDecompress', input);
  } catch {
    return craftCodecDecompressSync(input);
  }
}
