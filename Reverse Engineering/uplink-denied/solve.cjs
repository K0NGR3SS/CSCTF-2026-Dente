const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const verifier = fs.readFileSync(process.argv[2] ?? path.join(__dirname, 'files/cau_verify'));
assert.equal(createHash('sha256').update(verifier).digest('hex'),
  '19fc211ceda00357c70c5039dd882f11491c8bfb092b15824bc13f2bdc84990c');
const u64 = x => BigInt.asUintN(64, x);
const shiftXor = x => x ^ (x >> 33n);
const firstMultiplier = 0x9df50ad53e8f1c7bn;
const secondMultiplier = 0xc17a4b92d6e30f55n;
const inverseFirst = 0x6bfd169fb09862b3n;
const inverseSecond = 0xddb6dd747d3875fdn;

function forward(word) {
  const first = shiftXor(u64(firstMultiplier * shiftXor(word)));
  return shiftXor(u64(secondMultiplier * first));
}

function reverse(target) {
  const last = shiftXor(u64(inverseSecond * shiftXor(target)));
  return shiftXor(u64(inverseFirst * last));
}

const key = Buffer.alloc(24);
for (const [i, offset] of [0x159d, 0x15bf, 0x1608].entries()) {
  const target = verifier.readBigUInt64LE(offset);
  const word = reverse(target);
  assert.equal(forward(word), target);
  key.writeBigUInt64LE(word, i * 8);
}
const flag = 'CSCTF{' + key.toString('ascii') + '}';
assert.match(flag, /^CSCTF\{[a-z0-9_]+\}$/);
console.log(flag);
