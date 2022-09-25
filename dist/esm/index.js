// src/aes-cmac.ts
import crypto from "crypto";

// src/buffer-utils.ts
var bitShiftLeft = (buffer) => Buffer.alloc(buffer.length).map((_, i) => {
  const x = buffer[i] << 1;
  return buffer[i + 1] & 128 ? x + 1 : x;
});
var xor = (buffer1, buffer2) => {
  const length = Math.min(buffer1.length, buffer2.length);
  return Buffer.alloc(length).map((_, i) => buffer1[i] ^ buffer2[i]);
};

// src/aes-cmac.ts
var ZERO = Buffer.from("00000000000000000000000000000000", "hex");
var RB = Buffer.from("00000000000000000000000000000087", "hex");
var BLOCK_SIZE = 16;
var Ciphers = {
  aes128: 16,
  aes192: 24,
  aes256: 32
};
var aes = (key, message) => {
  const algorithm = Object.keys(Ciphers).find((cipherKey) => {
    return Ciphers[cipherKey] === key.length;
  });
  if (!algorithm) {
    throw new Error("Keys must be 128, 192, or 256 bits in length.");
  }
  const cipher = crypto.createCipheriv(algorithm, key, ZERO);
  const result = cipher.update(message);
  cipher.final();
  return result;
};
var generateSubkeys = (key) => {
  const l = aes(key, ZERO);
  const k1 = l[0] & 128 ? xor(bitShiftLeft(l), RB) : bitShiftLeft(l);
  const k2 = k1[0] & 128 ? xor(bitShiftLeft(k1), RB) : bitShiftLeft(k1);
  return [k1, k2];
};
var generateAesCmac = (key, message) => {
  const [k1, k2] = generateSubkeys(key);
  const blockCount = Math.ceil(message.length / BLOCK_SIZE);
  const lastBlockCompleteFlag = blockCount === 0 ? false : message.length % BLOCK_SIZE === 0;
  const lastBlockIndex = blockCount === 0 ? 0 : blockCount - 1;
  const lastBlock = lastBlockCompleteFlag ? xor(getMessageBlock(message, lastBlockIndex), k1) : xor(getPaddedMessageBlock(message, lastBlockIndex), k2);
  let x = Buffer.from("00000000000000000000000000000000", "hex");
  let y;
  for (let index = 0; index < lastBlockIndex; index++) {
    y = xor(x, getMessageBlock(message, index));
    x = aes(key, y);
  }
  return aes(key, xor(lastBlock, x));
};
var getMessageBlock = (message, blockIndex) => {
  const block = Buffer.alloc(BLOCK_SIZE);
  const start = blockIndex * BLOCK_SIZE;
  const end = start + BLOCK_SIZE;
  message.copy(block, 0, start, end);
  return block;
};
var getPaddedMessageBlock = (message, blockIndex) => {
  const block = Buffer.alloc(BLOCK_SIZE);
  const start = blockIndex * BLOCK_SIZE;
  const end = message.length;
  block.fill(0);
  message.copy(block, 0, start, end);
  block[end - start] = 128;
  return block;
};
export {
  generateAesCmac
};
