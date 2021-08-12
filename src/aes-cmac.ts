import crypto from "crypto";
import { bitShiftLeft, xor } from "./buffer-utils";

const ZERO = Buffer.from("00000000000000000000000000000000", "hex");
const RB = Buffer.from("00000000000000000000000000000087", "hex");
const BLOCK_SIZE = 16;

const Ciphers = {
  aes128: 16,
  aes192: 24,
  aes256: 32,
} as const;

type Cipher = typeof Ciphers[keyof typeof Ciphers];

const aes = (key: Buffer, message: Buffer): Buffer => {
  const algorithm = Object.keys(Ciphers).find((cipherKey) => {
    return (
      Ciphers[cipherKey as keyof typeof Ciphers] === (key.length as Cipher)
    );
  });

  if (!algorithm) {
    throw new Error("Keys must be 128, 192, or 256 bits in length.");
  }

  const cipher = crypto.createCipheriv(algorithm, key, ZERO);
  const result = cipher.update(message);
  cipher.final();
  return result;
};

export const generateSubkeys = (key: Buffer): [Buffer, Buffer] => {
  // Step 1.
  const l = aes(key, ZERO);
  // Step 2.
  const k1 = l[0] & 0x80 ? xor(bitShiftLeft(l), RB) : bitShiftLeft(l);
  // Step 3.
  const k2 = k1[0] & 0x80 ? xor(bitShiftLeft(k1), RB) : bitShiftLeft(k1);
  // Step 4.
  return [k1, k2];
};

export const generateAesCmac = (key: Buffer, message: Buffer): Buffer => {
  // Step 1.
  const [k1, k2] = generateSubkeys(key);
  // Step 2.
  const blockCount = Math.ceil(message.length / BLOCK_SIZE);

  // Step 3, 4.
  const lastBlockCompleteFlag =
    blockCount === 0 ? false : message.length % BLOCK_SIZE === 0;
  const lastBlockIndex = blockCount === 0 ? 0 : blockCount - 1;
  const lastBlock = lastBlockCompleteFlag
    ? xor(getMessageBlock(message, lastBlockIndex), k1)
    : xor(getPaddedMessageBlock(message, lastBlockIndex), k2);

  // Step 5.
  let x = Buffer.from("00000000000000000000000000000000", "hex");
  let y;

  // Step 6.
  for (let index = 0; index < lastBlockIndex; index++) {
    y = xor(x, getMessageBlock(message, index));
    x = aes(key, y);
  }

  // Step 7.
  return aes(key, xor(lastBlock, x));
};

export const verifyAesCmac = (
  aesCmac: Buffer,
  key: Buffer,
  message: Buffer
): boolean => {
  const expected = generateAesCmac(key, message);
  return aesCmac.equals(expected);
};

const getMessageBlock = (message: Buffer, blockIndex: number): Buffer => {
  const block = Buffer.alloc(BLOCK_SIZE);
  const start = blockIndex * BLOCK_SIZE;
  const end = start + BLOCK_SIZE;
  message.copy(block, 0, start, end);
  return block;
};

const getPaddedMessageBlock = (message: Buffer, blockIndex: number): Buffer => {
  const block = Buffer.alloc(BLOCK_SIZE);
  const start = blockIndex * BLOCK_SIZE;
  const end = message.length;

  block.fill(0);
  message.copy(block, 0, start, end);
  block[end - start] = 0x80;

  return block;
};
