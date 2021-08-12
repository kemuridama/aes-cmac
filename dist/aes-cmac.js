"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.verifyAesCmac = exports.generateAesCmac = exports.generateSubkeys = void 0;
const crypto_1 = __importDefault(require("crypto"));
const buffer_utils_1 = require("./buffer-utils");
const ZERO = Buffer.from("00000000000000000000000000000000", "hex");
const RB = Buffer.from("00000000000000000000000000000087", "hex");
const BLOCK_SIZE = 16;
const Ciphers = {
    aes128: 16,
    aes192: 24,
    aes256: 32,
};
const aes = (key, message) => {
    const algorithm = Object.keys(Ciphers).find((cipherKey) => {
        return (Ciphers[cipherKey] === key.length);
    });
    if (!algorithm) {
        throw new Error("Keys must be 128, 192, or 256 bits in length.");
    }
    const cipher = crypto_1.default.createCipheriv(algorithm, key, ZERO);
    const result = cipher.update(message);
    cipher.final();
    return result;
};
const generateSubkeys = (key) => {
    const l = aes(key, ZERO);
    const k1 = l[0] & 0x80 ? buffer_utils_1.xor(buffer_utils_1.bitShiftLeft(l), RB) : buffer_utils_1.bitShiftLeft(l);
    const k2 = k1[0] & 0x80 ? buffer_utils_1.xor(buffer_utils_1.bitShiftLeft(k1), RB) : buffer_utils_1.bitShiftLeft(k1);
    return [k1, k2];
};
exports.generateSubkeys = generateSubkeys;
const generateAesCmac = (key, message) => {
    const [k1, k2] = exports.generateSubkeys(key);
    const blockCount = Math.ceil(message.length / BLOCK_SIZE);
    const lastBlockCompleteFlag = blockCount === 0 ? false : message.length % BLOCK_SIZE === 0;
    const lastBlockIndex = blockCount === 0 ? 0 : blockCount - 1;
    const lastBlock = lastBlockCompleteFlag
        ? buffer_utils_1.xor(getMessageBlock(message, lastBlockIndex), k1)
        : buffer_utils_1.xor(getPaddedMessageBlock(message, lastBlockIndex), k2);
    let x = Buffer.from("00000000000000000000000000000000", "hex");
    let y;
    for (let index = 0; index < lastBlockIndex; index++) {
        y = buffer_utils_1.xor(x, getMessageBlock(message, index));
        x = aes(key, y);
    }
    return aes(key, buffer_utils_1.xor(lastBlock, x));
};
exports.generateAesCmac = generateAesCmac;
const verifyAesCmac = (aesCmac, key, message) => {
    const expected = exports.generateAesCmac(key, message);
    return aesCmac.equals(expected);
};
exports.verifyAesCmac = verifyAesCmac;
const getMessageBlock = (message, blockIndex) => {
    const block = Buffer.alloc(BLOCK_SIZE);
    const start = blockIndex * BLOCK_SIZE;
    const end = start + BLOCK_SIZE;
    message.copy(block, 0, start, end);
    return block;
};
const getPaddedMessageBlock = (message, blockIndex) => {
    const block = Buffer.alloc(BLOCK_SIZE);
    const start = blockIndex * BLOCK_SIZE;
    const end = message.length;
    block.fill(0);
    message.copy(block, 0, start, end);
    block[end - start] = 0x80;
    return block;
};
