/// <reference types="node" />
export declare const generateSubkeys: (key: Buffer) => [Buffer, Buffer];
export declare const generateAesCmac: (key: Buffer, message: Buffer) => Buffer;
export declare const verifyAesCmac: (aesCmac: Buffer, key: Buffer, message: Buffer) => boolean;
