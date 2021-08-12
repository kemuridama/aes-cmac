import { bitShiftLeft, xor } from "./buffer-utils";

describe("bitShiftLeft()", () => {
  const cases: ReadonlyArray<[string, string]> = [
    ["01", "02"],
    ["02", "04"],
    ["04", "08"],
    ["08", "10"],
    ["10", "20"],
    ["20", "40"],
    ["40", "80"],
    ["80", "00"],
    ["55cc33", "ab9866"],
  ];

  cases.map(([value, expected]) => {
    describe(`invokes with a buffer containing ${value} in hex`, () => {
      it(`returns a buffer containing bitshifted ${expected} in hex`, () => {
        const actual = bitShiftLeft(Buffer.from(value, "hex"));
        expect(actual).toStrictEqual(Buffer.from(expected, "hex"));
      });
    });
  });
});

describe("xor()", () => {
  const cases: ReadonlyArray<[string[], string]> = [
    [["5a", "a5"], "ff"],
    [["5a", "5a"], "00"],
    [["5a", "ff"], "a5"],
    [["5a", "00"], "5a"],
    [["5a", "c3"], "99"],
    [["5a", "99"], "c3"],
    [["abcd", "0123"], "aaee"],
    [["123456", "789abc"], "6aaeea"],
  ];

  cases.map(([[x, y], expected]) => {
    describe(`invokes with two buffer containing ${x} & ${y} in hex, respectively`, () => {
      it(`returns a buffer containing ${expected} in hex`, () => {
        const actual = xor(Buffer.from(x, "hex"), Buffer.from(y, "hex"));
        expect(actual).toStrictEqual(Buffer.from(expected, "hex"));
      });
    });
  });
});
