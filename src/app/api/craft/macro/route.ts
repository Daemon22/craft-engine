/**
 * Craft Macro API — Decrypt & Decompress endpoint (supports v1 & v2)
 *
 * POST /api/craft/macro
 * Accepts: multipart/form-data with .craft file + passphrase
 * Returns: Restored original file as downloadable binary
 */

import { NextRequest, NextResponse } from 'next/server';
import { macro } from '@/lib/craft/macro';
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
        { error: 'No .craft file provided. Please upload a crafted file to restore.' },
        { status: 400, headers: { ...CORS_HEADERS, 'X-Craft-Request-Id': requestId } }
      );
    }

    if (!passphrase) {
      return NextResponse.json(
        { error: 'Passphrase is required to decrypt the .craft package.' },
        { status: 400, headers: { ...CORS_HEADERS, 'X-Craft-Request-Id': requestId } }
      );
    }

    if (passphrase.length < 12) {
      return NextResponse.json(
        { error: 'Passphrase must be at least 12 characters.' },
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
    const craftBuffer = Buffer.from(arrayBuffer);

    const result = macro(craftBuffer, passphrase);

    const processingTime = Math.round(performance.now() - startTime);

    return new NextResponse(result.buffer, {
      status: 200,
      headers: {
        ...CORS_HEADERS,
        'Content-Type': result.metadata.originalMime || 'application/octet-stream',
        'Content-Disposition': contentDispositionAttachment(result.metadata.originalName),
        'X-Craft-Restored-Size': result.buffer.length.toString(),
        // Custom headers go through the same ByteString-only Headers API as
        // Content-Disposition, so a non-ASCII original filename (any accented
        // or non-Latin name) would throw here too — percent-encode it.
        'X-Craft-Original-Name': encodeURIComponent(result.metadata.originalName),
        'X-Craft-Integrity-Verified': result.integrityVerified.toString(),
        'X-Craft-Checksum': result.metadata.originalChecksum,
        'X-Craft-Mode': result.metadata.compressionMode || 'brotli',
        'X-Craft-Strategy': result.metadata.compressionStrategyName || 'brotli',
        'X-Craft-Processing-Time': processingTime.toString(),
        'X-Craft-Request-Id': requestId,
      },
    });
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : 'An unknown error occurred during Macro extraction.';
    console.error('[Craft Macro Error]', error);
    const processingTime = Math.round(performance.now() - startTime);

    if (message.includes('INTEGRITY FAILURE')) {
      return NextResponse.json(
        { error: 'Integrity verification failed. The restored data does not match the original. This could indicate file corruption.' },
        { status: 422, headers: { ...CORS_HEADERS, 'X-Craft-Request-Id': requestId, 'X-Craft-Processing-Time': processingTime.toString() } }
      );
    }

    // Decryption failures — almost always wrong passphrase
    if (message.includes('auth tag') || message.includes('EVP_DecryptFinal') ||
        message.includes('Unsupported state') || message.includes('Unsupported')) {
      return NextResponse.json(
        { error: 'Decryption failed — the passphrase is incorrect. Please check and try again.' },
        { status: 401, headers: { ...CORS_HEADERS, 'X-Craft-Request-Id': requestId, 'X-Craft-Processing-Time': processingTime.toString() } }
      );
    }

    return NextResponse.json(
      { error: message },
      { status: 500, headers: { ...CORS_HEADERS, 'X-Craft-Request-Id': requestId, 'X-Craft-Processing-Time': processingTime.toString() } }
    );
  }
}
