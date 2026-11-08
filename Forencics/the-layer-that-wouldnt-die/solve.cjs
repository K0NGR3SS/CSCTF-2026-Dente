const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const { createHash, createHmac } = require('node:crypto');
const path = require('node:path');

const archive = process.argv[2] ?? path.join(__dirname, 'files/historian-image.zip');
const root = 'cascade-historian-config-image/';
const readZip = name => execFileSync('tar', ['-xOf', archive, name]);

function readBlob(descriptor) {
  const [algorithm, digest] = descriptor.digest.split(':');
  assert.equal(algorithm, 'sha256');
  assert.match(digest, /^[a-f0-9]{64}$/);
  const content = readZip(root + 'blobs/sha256/' + digest);
  assert.equal(content.length, descriptor.size);
  assert.equal(createHash('sha256').update(content).digest('hex'), digest);
  return content;
}

function readLayerFile(layer, name) {
  return execFileSync('tar', ['-xOf', '-', name], { input: readBlob(layer) });
}

const index = JSON.parse(readZip(root + 'index.json'));
const manifest = JSON.parse(readBlob(index.manifests[0]));
const config = JSON.parse(readBlob(manifest.config));
const marker = readLayerFile(manifest.layers[1], 'etc/cascade/.sealed_marker');
const sealed = readLayerFile(manifest.layers[2], 'etc/cascade/historian.key.sealed');
const seal = Buffer.from(config.config.Labels['build.seal'], 'hex');
const mask = createHmac('sha256', seal).update(marker).digest();
const flag = sealed.map((byte, i) => byte ^ mask[i % mask.length]).toString('ascii').trim();
assert.match(flag, /^CSCTF\{[a-z0-9_]+\}$/);
console.log(flag);
