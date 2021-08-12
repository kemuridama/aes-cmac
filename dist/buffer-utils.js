"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.xor = exports.bitShiftLeft = void 0;
const bitShiftLeft = (buffer) => Buffer.alloc(buffer.length).map((_, i) => {
    const x = buffer[i] << 1;
    return buffer[i + 1] & 0x80 ? x + 0x01 : x;
});
exports.bitShiftLeft = bitShiftLeft;
const xor = (buffer1, buffer2) => {
    const length = Math.min(buffer1.length, buffer2.length);
    return Buffer.alloc(length).map((_, i) => buffer1[i] ^ buffer2[i]);
};
exports.xor = xor;
