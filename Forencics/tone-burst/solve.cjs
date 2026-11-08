const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const wav = fs.readFileSync(process.argv[2] ?? path.join(__dirname, 'files/tone-burst.wav'));
assert.equal(wav.toString('ascii', 36, 40), 'data');
assert.equal(wav.readUInt16LE(20), 1);
assert.equal(wav.readUInt16LE(22), 1);
assert.equal(wav.readUInt16LE(34), 16);
const sampleRate = wav.readUInt32LE(24);
const samplesPerBit = sampleRate / 50;
const sampleCount = wav.readUInt32LE(40) / 2;

function toneEnergy(start, frequency) {
  let real = 0;
  let imaginary = 0;
  for (let i = 0; i < samplesPerBit; i++) {
    const sample = wav.readInt16LE(44 + 2 * (start + i));
    const phase = 2 * Math.PI * frequency * i / sampleRate;
    real += sample * Math.cos(phase);
    imaginary += sample * Math.sin(phase);
  }
  return real ** 2 + imaginary ** 2;
}

const bytes = [];
for (let start = Math.round(0.24 * sampleRate); start + 8 * samplesPerBit <= sampleCount;) {
  let byte = 0;
  for (let bit = 0; bit < 8; bit++, start += samplesPerBit) {
    byte = (byte << 1) | Number(toneEnergy(start, 2000) > toneEnergy(start, 1000));
  }
  bytes.push(byte);
}
assert.deepEqual(bytes.slice(0, 5), [0xaa, 0xaa, 0xaa, 0xaa, 0x7e]);
const flag = Buffer.from(bytes.slice(5)).toString('ascii').match(/^CSCTF\{[a-z0-9_]+\}/);
assert.ok(flag, 'No flag after the frame marker');
console.log(flag[0]);
