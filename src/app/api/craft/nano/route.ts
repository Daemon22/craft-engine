/**
 * Craft Nano API — 7-Fold Compress & Encrypt endpoint
 *
 * POST /api/craft/nano
 * Accepts: multipart/form-data with file + passphrase
 * Returns: .craft package as downloadable binary
 */

import { NextRequest, NextResponse } from 'next/server';
import { nano } from '@/lib/craft/nano';
import { contentDispositionAttachment } from '@/lib/http';
import { randomUUID } from 'crypto';

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};

export async function OPTIONS() {
  return new NextResponse(null, {
    status: 204,
    headers: CORS_HEADERS,
  });
}

export async function POST(request: NextRequest) {
  const requestId = randomUUID();
  const startTime = performance.now();

  try {
    const formData = await request.formData();
    const file = formData.get('file') as File | null;
    const passphrase = formData.get('passphrase') as string | null;

    if (!file) {
      return NextResponse.json(
        { error: 'No file provided. Please upload a file to craft.' },
        { status: 400, headers: { ...CORS_HEADERS, 'X-Craft-Request-Id': requestId } }
      );
    }

    if (!passphrase || passphrase.length < 12) {
      return NextResponse.json(
        { error: 'Passphrase must be at least 12 characters for secure encryption.' },
        { status: 400, headers: { ...CORS_HEADERS, 'X-Craft-Request-Id': requestId } }
      );
    }

    // File size limit: 100MB
    const MAX_FILE_SIZE = 100 * 1024 * 1024; // 100MB
    if (file.size > MAX_FILE_SIZE) {
      return NextResponse.json(
        { error: `File size exceeds maximum allowed size of 100MB. Your file is ${(file.size / (1024 * 1024)).toFixed(1)}MB.` },
        { status: 413, headers: { ...CORS_HEADERS, 'X-Craft-Request-Id': requestId } }
      );
    }

    const arrayBuffer = await file.arrayBuffer();
    const data = Buffer.from(arrayBuffer);

    const result = nano(data, file.name, file.type || 'application/octet-stream', passphrase, {
      compressionMode: '7fold',
    });
    const processingTime = Math.round(performance.now() - startTime);

    const craftFileName = file.name.endsWith('.craft')
      ? file.name
      : `${file.name}.craft`;

    // Build strategy benchmarks JSON for the header
    const benchmarksJson = result.strategyBenchmarks
      ? JSON.stringify(result.strategyBenchmarks)
      : '';

    return new NextResponse(result.buffer, {
      status: 200,
      headers: {
        ...CORS_HEADERS,
        'Content-Type': 'application/octet-stream',
        'Content-Disposition': contentDispositionAttachment(craftFileName),
        'X-Craft-Original-Size': result.metadata.originalSize.toString(),
        'X-Craft-Crafted-Size': result.buffer.length.toString(),
        'X-Craft-Compressed-Size': result.metadata.compressedSize.toString(),
        'X-Craft-Compression-Ratio': result.compressionRatio.toFixed(4),
        'X-Craft-Space-Saved': result.spaceSaved.toString(),
        'X-Craft-Space-Saved-Percent': result.spaceSavedPercent.toFixed(2),
        'X-Craft-Checksum': result.metadata.originalChecksum,
        'X-Craft-Mode': result.metadata.compressionMode,
        'X-Craft-Strategy': result.metadata.compressionStrategyName || 'brotli',
        'X-Craft-Version': result.metadata.version.toString(),
        'X-Craft-Benchmarks': benchmarksJson,
        'X-Craft-Processing-Time': processingTime.toString(),
        'X-Craft-Request-Id': requestId,
      },
    });
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : 'An unknown error occurred during Nano crafting.';
    console.error('[Craft Nano Error]', error);
    const processingTime = Math.round(performance.now() - startTime);
    return NextResponse.json(
      { error: message },
      { status: 500, headers: { ...CORS_HEADERS, 'X-Craft-Request-Id': requestId, 'X-Craft-Processing-Time': processingTime.toString() } }
    );
  }
}
