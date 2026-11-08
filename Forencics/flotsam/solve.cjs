const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { crc32, inflateSync } = require('node:zlib');

const disk = fs.readFileSync(process.argv[2] ?? path.join(__dirname, 'files/recorder-sectors.img'));
const output = process.argv[3] ?? 'chart.png';
const sectorSize = 512;
const sectors = (first, last) => disk.subarray(first * sectorSize, (last + 1) * sectorSize);
const png = Buffer.concat([
  sectors(52, 67),
  sectors(3, 20),
  sectors(35, 41),
  disk.subarray(44 * sectorSize, 47 * sectorSize + 159),
]);

assert.equal(png.subarray(0, 8).toString('hex'), '89504e470d0a1a0a');
const chunks = [];
const data = [];
for (let offset = 8; offset < png.length;) {
  const size = png.readUInt32BE(offset);
  const type = png.toString('ascii', offset + 4, offset + 8);
  const end = offset + 8 + size;
  assert.equal(crc32(png.subarray(offset + 4, end)), png.readUInt32BE(end), type);
  chunks.push(type);
  if (type === 'IDAT') data.push(png.subarray(offset + 8, end));
  offset = end + 4;
}
assert.deepEqual(chunks, ['IHDR', 'IDAT', 'IEND']);
assert.ok(inflateSync(Buffer.concat(data)).length > 0);
fs.writeFileSync(output, png, { flag: 'wx' });
console.log(output);
