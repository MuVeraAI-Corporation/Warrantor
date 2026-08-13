/**
 * Regenerate `icon.png` from source rather than committing an opaque blob.
 *
 * `node build/make-icon.mjs` — writes `build/icon.png`, 1024×1024. electron-builder derives the
 * `.ico`, the `.icns` and the Linux icon set from that one file.
 *
 * Why a generator and not just the PNG: this is a security substrate, and a binary in the source
 * tree that nobody can diff is a small version of the problem the whole product is about. Fifty
 * lines of arithmetic is reviewable; a 1 MB PNG is not. It also keeps the mark honestly
 * provisional — a ring and a diamond, geometric on purpose, claiming no brand that does not exist.
 */

import { deflateSync } from 'node:zlib';
import { writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const SIZE = 1024;
const BACKGROUND = [0x0f, 0x11, 0x15]; // the shell window's own background
const MARK = [0xd7, 0xdd, 0xe8];
const ACCENT = [0x5b, 0x8d, 0xef];

const centre = SIZE / 2;
const cornerRadius = SIZE * 0.22;
const ringOuter = SIZE * 0.36;
const ringInner = SIZE * 0.30;
const diamondRadius = SIZE * 0.105;
/** Samples per axis per pixel. Hard edges alias badly once the icon is scaled to 32 px. */
const SUPERSAMPLE = 3;

/** Is (x, y) inside the rounded square that forms the icon's body? */
function insideBody(x, y) {
  const dx = Math.max(Math.abs(x - centre) - (centre - cornerRadius), 0);
  const dy = Math.max(Math.abs(y - centre) - (centre - cornerRadius), 0);
  return Math.hypot(dx, dy) <= cornerRadius;
}

function colourAt(x, y) {
  if (!insideBody(x, y)) return null; // transparent outside the body
  const radius = Math.hypot(x - centre, y - centre);
  if (radius <= ringOuter && radius >= ringInner) return ACCENT;
  const manhattan = Math.abs(x - centre) + Math.abs(y - centre);
  if (manhattan <= diamondRadius * 2) return MARK;
  return BACKGROUND;
}

const raw = Buffer.alloc(SIZE * (SIZE * 4 + 1));
let offset = 0;
for (let y = 0; y < SIZE; y += 1) {
  raw[offset] = 0; // filter type 0 (none): the image is tiny to compress either way
  offset += 1;
  for (let x = 0; x < SIZE; x += 1) {
    let red = 0;
    let green = 0;
    let blue = 0;
    let opaque = 0;
    for (let sy = 0; sy < SUPERSAMPLE; sy += 1) {
      for (let sx = 0; sx < SUPERSAMPLE; sx += 1) {
        const colour = colourAt(
          x + (sx + 0.5) / SUPERSAMPLE,
          y + (sy + 0.5) / SUPERSAMPLE,
        );
        if (!colour) continue;
        red += colour[0];
        green += colour[1];
        blue += colour[2];
        opaque += 1;
      }
    }
    const samples = SUPERSAMPLE * SUPERSAMPLE;
    raw[offset] = opaque ? Math.round(red / opaque) : 0;
    raw[offset + 1] = opaque ? Math.round(green / opaque) : 0;
    raw[offset + 2] = opaque ? Math.round(blue / opaque) : 0;
    raw[offset + 3] = Math.round((opaque / samples) * 255);
    offset += 4;
  }
}

const CRC_TABLE = Array.from({ length: 256 }, (_, index) => {
  let value = index;
  for (let bit = 0; bit < 8; bit += 1) {
    value = value & 1 ? 0xedb88320 ^ (value >>> 1) : value >>> 1;
  }
  return value >>> 0;
});

function crc32(buffer) {
  let value = 0xffffffff;
  for (const byte of buffer) value = CRC_TABLE[(value ^ byte) & 0xff] ^ (value >>> 8);
  return (value ^ 0xffffffff) >>> 0;
}

function chunk(type, data) {
  const length = Buffer.alloc(4);
  length.writeUInt32BE(data.length);
  const body = Buffer.concat([Buffer.from(type, 'ascii'), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(body));
  return Buffer.concat([length, body, crc]);
}

const header = Buffer.alloc(13);
header.writeUInt32BE(SIZE, 0);
header.writeUInt32BE(SIZE, 4);
header[8] = 8; // bit depth
header[9] = 6; // colour type: RGBA
const png = Buffer.concat([
  Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
  chunk('IHDR', header),
  chunk('IDAT', deflateSync(raw, { level: 9 })),
  chunk('IEND', Buffer.alloc(0)),
]);

const destination = join(dirname(fileURLToPath(import.meta.url)), 'icon.png');
writeFileSync(destination, png);
process.stdout.write(`wrote ${destination} (${png.length} bytes)\n`);
