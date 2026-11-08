const assert = require('node:assert/strict');
const { execFileSync, spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const archive = process.argv[2] ?? path.join(__dirname, 'files/command-authority-evidence.zip');
const photo = execFileSync('tar', ['-xOf', archive, 'id_photo.jpg']);
const marker = photo.lastIndexOf(Buffer.from([0xff, 0xd9]));
assert.ok(marker >= 0, 'JPEG end marker missing');
const trailer = photo.toString('ascii', marker + 2);
const key = trailer.match(/^ARCHIVE-KEY:([^\r\n]+)/);
assert.ok(key, 'Archive key missing from JPEG trailer');

const bundle = execFileSync('tar', ['-xOf', archive, 'pass_bundle.zip']);
const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'command-authority-'));
const bundlePath = path.join(temp, 'pass_bundle.zip');
fs.writeFileSync(bundlePath, bundle, { flag: 'wx' });
let verifier;
try {
  const result = spawnSync('tar', ['--passphrase', key[1], '-xOf', bundlePath, 'field_verifier']);
  if (result.error) throw result.error;
  assert.equal(result.status, 0, 'Could not extract field_verifier with the recovered key');
  verifier = result.stdout;
} finally {
  fs.unlinkSync(bundlePath);
  fs.rmdirSync(temp);
}
const flag = verifier.subarray(0x2120, 0x213f).map(byte => byte ^ 0x41).toString('ascii');
assert.match(flag, /^CSCTF\{[a-f0-9]+\}$/);
console.log(flag);
