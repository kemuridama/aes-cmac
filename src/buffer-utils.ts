export const bitShiftLeft = (buffer: Buffer): Buffer =>
  Buffer.alloc(buffer.length).map((_, i) => {
    const x = buffer[i] << 1;
    return buffer[i + 1] & 0x80 ? x + 0x01 : x;
  }) as Buffer;

export const xor = (buffer1: Buffer, buffer2: Buffer): Buffer => {
  const length = Math.min(buffer1.length, buffer2.length);
  return Buffer.alloc(length).map((_, i) => buffer1[i] ^ buffer2[i]) as Buffer;
};
