import {describe, expect, test} from '@jest/globals';
import { generateDisplayableCode } from '../DisplayableCode';

describe('DisplayableCode', () => {
  test('expectedOutput', () => {
    const shortData = new Uint8Array([0xaa, 0xbb, 0xcc, 0xdd, 0xee]);
    expect(generateDisplayableCode(shortData, 5, 5)).toBe('05870');

    const longDataBuffer = Buffer.from('aabbccddeebbccddeeffccddeeffaaddeeffaabbeeffaabbccffaabbccdd', 'hex');
    const longData = Uint8Array.from(longDataBuffer);
    expect(generateDisplayableCode(longData, 30, 5)).toBe('058708105556138052119572494877');
  });

  test('expectedFailure', () => {
    const tooShortData = new Uint8Array([0xaa, 0xbb, 0xcc, 0xdd]);
    expect(() => {
      generateDisplayableCode(tooShortData, 5, 5);
    }).toThrow();

    const goodData = new Uint8Array([0xaa, 0xbb, 0xcc, 0xdd]);
    expect(() => {
      generateDisplayableCode(goodData, 4, 3);
    }).toThrow();

    const randomData = new Uint8Array(1024);
    globalThis.crypto.getRandomValues(randomData);
    expect(() => {
      generateDisplayableCode(randomData, 1024, 11);
    }).toThrow();
  });
});
