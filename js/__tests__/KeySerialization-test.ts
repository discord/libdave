import {describe, expect, test} from '@jest/globals';
import {serializeKey} from '../src/KeySerialization';

describe('KeySerialization', () => {
  test('expectedOutput', async () => {
    const zeroData = new Uint8Array(6);
    expect(serializeKey(zeroData)).toBe('AAAAAAAA');

    const moreData = new Uint8Array([0, 1, 0xff, 0x7f, 0x80]);
    expect(serializeKey(moreData)).toBe('AAH/f4A=');
  });
});
