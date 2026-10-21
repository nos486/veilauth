// Renders the app icons (a keyhole on an indigo tile) as PNGs. Run once: node scripts/make-icons.mjs
import { writeFileSync } from "node:fs";
import { deflateSync } from "node:zlib";

const CRC_TABLE = Array.from({ length: 256 }, (_, n) => {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c >>> 0;
});
function crc32(buf) {
  let c = 0xffffffff;
  for (const b of buf) c = CRC_TABLE[(c ^ b) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}
function chunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length);
  const td = Buffer.concat([Buffer.from(type, "ascii"), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(td));
  return Buffer.concat([len, td, crc]);
}

function render(size, { maskable }) {
  const rows = [];
  const bg = [79, 70, 229];
  const radius = maskable ? 0 : size * 0.22;
  const cx = size / 2;
  for (let y = 0; y < size; y++) {
    const row = Buffer.alloc(1 + size * 4);
    for (let x = 0; x < size; x++) {
      const px = x + 0.5;
      const py = y + 0.5;
      // rounded tile
      const dx = Math.max(radius - px, px - (size - radius), 0);
      const dy = Math.max(radius - py, py - (size - radius), 0);
      const inside = radius === 0 || dx * dx + dy * dy <= radius * radius;
      // keyhole: circle + trapezoid, scaled into the maskable safe zone
      const s = size * 0.6;
      const hx = (px - cx) / s;
      const hy = (py - size / 2) / s;
      const head = hx * hx + (hy + 0.12) * (hy + 0.12) <= 0.16 * 0.16;
      const stemHalf = 0.06 + (hy - 0.0) * 0.12;
      const stem = hy >= -0.05 && hy <= 0.3 && Math.abs(hx) <= stemHalf;
      const white = head || stem;
      const o = 1 + x * 4;
      if (!inside) {
        row[o + 3] = 0;
        continue;
      }
      const [r, g, b] = white ? [255, 255, 255] : bg;
      row[o] = r;
      row[o + 1] = g;
      row[o + 2] = b;
      row[o + 3] = 255;
    }
    rows.push(row);
  }
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0);
  ihdr.writeUInt32BE(size, 4);
  ihdr[8] = 8;
  ihdr[9] = 6;
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk("IHDR", ihdr),
    chunk("IDAT", deflateSync(Buffer.concat(rows), { level: 9 })),
    chunk("IEND", Buffer.alloc(0)),
  ]);
}

writeFileSync("public/icon-192.png", render(192, { maskable: false }));
writeFileSync("public/icon-512.png", render(512, { maskable: false }));
writeFileSync("public/icon-maskable-512.png", render(512, { maskable: true }));
writeFileSync("public/apple-touch-icon.png", render(180, { maskable: true }));
