import { generateAesCmac, generateSubkeys, verifyAesCmac } from "./aes-cmac";

const keys: { [length: number]: string } = {
  128: "2b7e151628aed2a6abf7158809cf4f3c",
  192: "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
  256: "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
};

const messages: { [length: number]: string } = {
  0: "",
  128: "6bc1bee22e409f96e93d7e117393172a",
  320:
    "6bc1bee22e409f96e93d7e117393172aae2d8a57" +
    "1e03ac9c9eb76fac45af8e5130c81c46a35ce411",
  512:
    "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51" +
    "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
};

describe("#generateSubkeys()", () => {
  // [length, expected K1, expected K2]
  const cases: ReadonlyArray<[number, string, string]> = [
    [
      128,
      "fbeed618357133667c85e08f7236a8de",
      "f7ddac306ae266ccf90bc11ee46d513b",
    ],
    [
      192,
      "448a5b1c93514b273ee6439dd4daa296",
      "8914b63926a2964e7dcc873ba9b5452c",
    ],
    [
      256,
      "cad1ed03299eedac2e9a99808621502f",
      "95a3da06533ddb585d3533010c42a0d9",
    ],
  ];

  cases.map(([length, expectedK1, expectedK2]) => {
    describe(`invokes with a ${length} bit key`, () => {
      it(`returns the pair of subkeys`, () => {
        const [k1, k2] = generateSubkeys(Buffer.from(keys[length], "hex"));
        expect(k1).toStrictEqual(Buffer.from(expectedK1, "hex"));
        expect(k2).toStrictEqual(Buffer.from(expectedK2, "hex"));
      });
    });
  });
});

describe("#generateAesCmac()", () => {
  // [keyLength, messageLength, expected]
  const cases: ReadonlyArray<[number, number, string]> = [
    [128, 0, "bb1d6929e95937287fa37d129b756746"],
    [192, 0, "d17ddf46adaacde531cac483de7a9367"],
    [256, 0, "028962f61b7bf89efc6b551f4667d983"],
    [128, 128, "070a16b46b4d4144f79bdd9dd04a287c"],
    [192, 128, "9e99a7bf31e710900662f65e617c5184"],
    [256, 128, "28a7023f452e8f82bd4bf28d8c37c35c"],
    [128, 320, "dfa66747de9ae63030ca32611497c827"],
    [192, 320, "8a1de5be2eb31aad089a82e6ee908b0e"],
    [256, 320, "aaf3d8f1de5640c232f5b169b9c911e6"],
    [128, 512, "51f0bebf7e3b9d92fc49741779363cfe"],
    [192, 512, "a1d5df0eed790f794d77589659f39a11"],
    [256, 512, "e1992190549f6ed5696a2c056c315410"],
  ];

  cases.forEach(([keyLength, messageLength, expected]) => {
    describe(`invokes with a length ${messageLength} message, ${keyLength} bit key`, () => {
      it(`returns the MAC for length ${messageLength} input, ${keyLength} bit key`, () => {
        const key = Buffer.from(keys[keyLength], "hex");
        const message = Buffer.from(messages[messageLength], "hex");
        const actual = generateAesCmac(key, message);
        expect(actual).toStrictEqual(Buffer.from(expected, "hex"));
      });
    });
  });

  describe("error handling", () => {
    it("throws an error if the provided key is not a valid length", () => {
      const key = Buffer.from("abcd");
      const message = Buffer.from("some message");
      expect(() => generateAesCmac(key, message)).toThrowError(
        new Error("Keys must be 128, 192, or 256 bits in length.")
      );
    });
  });
});

describe("#verifyAesCmad()", () => {
  const key = Buffer.from(keys[128], "hex");
  const message = Buffer.from(messages[128], "hex");

  describe("invokes with a valid MAC", () => {
    it("returns true", () => {
      const validMac = Buffer.from("070a16b46b4d4144f79bdd9dd04a287c", "hex");
      const actual = verifyAesCmac(validMac, key, message);
      expect(actual).toBeTruthy();
    });
  });

  describe("invokes with a invalid MAC", () => {
    it("returns false", () => {
      const invalidMac = Buffer.from("00000000000000000000000000000000", "hex");
      const actual = verifyAesCmac(invalidMac, key, message);
      expect(actual).toBeFalsy();
    });
  });
});
