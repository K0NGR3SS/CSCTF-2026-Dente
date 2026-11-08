const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const { createHash, createHmac } = require('node:crypto');
const path = require('node:path');
const { gunzipSync } = require('node:zlib');

const archive = process.argv[2] ?? path.join(__dirname, 'files/capability-ghost.zip');
const readZip = name => execFileSync('tar', ['-xOf', archive, name], { maxBuffer: 16 * 1024 * 1024 });
const evidence = new Map();
for (const line of readZip('manifest.sha256').toString('ascii').trim().split(/\r?\n/)) {
  const [, sha256, name] = line.match(/^([a-f0-9]{64})\s+\*?(.+)$/);
  const content = readZip(name);
  assert.equal(createHash('sha256').update(content).digest('hex'), sha256, name);
  evidence.set(name.replace(/^\.\//, ''), content);
}

function paxAttributes(body) {
  const attrs = new Map();
  for (let start = 0; start < body.length;) {
    const space = body.indexOf(0x20, start);
    const end = start + Number(body.toString('ascii', start, space));
    const equal = body.indexOf(0x3d, space + 1);
    assert.ok(space > start && equal > space && equal < end && end <= body.length);
    attrs.set(body.toString('ascii', space + 1, equal), body.subarray(equal + 1, end - 1));
    start = end;
  }
  return attrs;
}

const tar = gunzipSync(evidence.get('runner-fs.tar.gz'));
let attrs = new Map();
let sealTag;
let sealed;
for (let offset = 0; offset + 512 <= tar.length && tar[offset] !== 0;) {
  const name = tar.toString('utf8', offset, offset + 100).split('\0')[0].replace(/^\.\//, '');
  const size = parseInt(tar.toString('ascii', offset + 124, offset + 136), 8);
  const body = tar.subarray(offset + 512, offset + 512 + size);
  if (tar[offset + 156] === 0x78) {
    attrs = paxAttributes(body);
  } else {
    if (name === 'usr/local/bin/hc-probe') sealTag = attrs.get('SCHILY.xattr.user.build_seal');
    if (name === 'etc/solunet/signaling-cfg.sealed') sealed = body;
    attrs = new Map();
  }
  offset += 512 + Math.ceil(size / 512) * 512;
}

assert.ok(sealTag && sealed, 'Missing seal metadata or sealed payload');
const journal = evidence.get('runner.journal').toString('latin1');
const epochs = new Set(Array.from(journal.matchAll(/X_SEAL_EPOCH=(\d+)/g), match => match[1]));
assert.equal(epochs.size, 1, 'Expected one seal epoch');
const mask = createHmac('sha256', sealTag).update([...epochs][0], 'ascii').digest();
const flag = sealed.map((byte, i) => byte ^ mask[i % mask.length]).toString('ascii').trim();
assert.match(flag, /^CSCTF\{[a-z0-9_]+\}$/);
console.log(flag);
