import { describe, expect, it } from 'vitest';

import { deriveRailgunKeysByIndex, getRailgunPathsByIndex } from '../src/utils/railgun-node';

const TEST_MNEMONIC = 'test test test test test test test test test test test junk';

describe('getRailgunPathsByIndex', () => {
  it('returns hardened spending and viewing paths', () => {
    const paths = getRailgunPathsByIndex(0);
    expect(paths.spending).toBe("m/44'/1984'/0'/0'/0'");
    expect(paths.viewing).toBe("m/420'/1984'/0'/0'/0'");
  });
});

describe('deriveRailgunKeysByIndex', () => {
  it('derives expected spending and viewing keys for the test mnemonic at index 0', () => {
    const keys = deriveRailgunKeysByIndex(TEST_MNEMONIC, 0);
    expect(keys.spending).toBe('b0958f8bc286ae0832fa83b01b719a225a07ce7b861ff311323f221667b3bd50');
    expect(keys.viewing).toBe('9da4b4f0b5493a6ba3f7df0611c3e0842f7e2bb3d640f313b235f1b75c1d80b9');
  });
});
