/**
 * Visual identity for artifacts produced by Craft Engine.
 *
 * Source PNGs are preserved in assets/craft-icons/source using the owner's
 * filenames. The public WebP derivatives are optimized for the dashboard.
 * Encryption-only is reserved here because the current archive pipeline always
 * compresses before encrypting; do not label a production .craft as encryption-only.
 */
export const CRAFT_ARTIFACT_ICONS = {
  compressionOnly: {
    kind: 'compression-only',
    sourceFilename: 'Compressed_Only.png',
    publicPath: '/craft-icons/compressed-only.webp',
    extension: '.nano',
    label: 'Compression only',
    supported: true,
  },
  encryptionOnly: {
    kind: 'encryption-only',
    sourceFilename: 'Encrypted_Only.png',
    publicPath: '/craft-icons/encrypted-only.webp',
    extension: null,
    label: 'Encryption only',
    supported: false,
  },
  compressionAndEncryption: {
    kind: 'compression-and-encryption',
    sourceFilename: 'Compressed & Encrypted.png',
    publicPath: '/craft-icons/compressed-encrypted.webp',
    extension: '.craft',
    label: 'Compressed + encrypted',
    supported: true,
  },
} as const;

export type CraftArtifactKind = typeof CRAFT_ARTIFACT_ICONS[keyof typeof CRAFT_ARTIFACT_ICONS]['kind'];

export function getCraftArtifactIcon(kind: CraftArtifactKind) {
  return Object.values(CRAFT_ARTIFACT_ICONS).find((icon) => icon.kind === kind);
}
