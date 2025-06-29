import {describe, expect, test} from '@jest/globals';
import { generateKeyFingerprint } from '../KeyFingerprint';

describe('KeyFingerprint', () => {
  test('expectedOutput', async () => {
    const shortData = new Uint8Array(33);
    expect((await generateKeyFingerprint(0, shortData, '1234')).join('')).toBe(
      '000000000000000000000000000000000000000004210',
    );

    const longData = new Uint8Array(65);
    expect((await generateKeyFingerprint(0, longData, '12345678')).join('')).toBe(
      '0000000000000000000000000000000000000000000000000000000000000000000000001889778',
    );
  });

  test('expectedFailure', async () => {
    const data = new Uint8Array(33);
    await expect(generateKeyFingerprint(1, data, '1234')).rejects.toThrow();

    await expect(generateKeyFingerprint(0, data, 'abcd')).rejects.toThrow();

    await expect(generateKeyFingerprint(0, new Uint8Array(0), '1234')).rejects.toThrow();
  });
});
