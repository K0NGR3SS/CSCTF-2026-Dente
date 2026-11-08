const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const wav = fs.readFileSync(process.argv[2] ?? path.join(__dirname, 'files/telltale.wav'));
assert.equal(wav.toString('ascii', 36, 40), 'data');
assert.equal(wav.readUInt16LE(20), 1);
assert.equal(wav.readUInt16LE(22), 1);
assert.equal(wav.readUInt16LE(34), 16);

function high(start) {
  let sum = 0;
  for (let i = start; i < start + 24; i++) sum += wav.readInt16LE(44 + 2 * i);
  return sum / 24 > 12729;
}

let cursor = 12000;
function readByte() {
  let byte = 0;
  for (let bit = 0; bit < 8; bit++, cursor += 48) {
    const first = high(cursor);
    assert.notEqual(first, high(cursor + 24), 'Invalid Manchester pair');
    byte = (byte << 1) | Number(!first);
  }
  return byte;
}

for (let i = 0; i < 8; i++) assert.equal(readByte(), 0xaa);
assert.equal(readByte(), 0x7e);
const length = readByte();
const payload = Array.from({ length }, readByte);
let crc = 0;
for (const value of [length, ...payload]) {
  crc ^= value;
  for (let bit = 0; bit < 8; bit++) {
    crc = ((crc << 1) ^ ((crc & 0x80) ? 0x07 : 0)) & 0xff;
  }
}
assert.equal(readByte(), crc);
const flag = Buffer.from(payload).toString('ascii');
assert.match(flag, /^CSCTF\{[a-z0-9_]+\}$/);
console.log(flag);
