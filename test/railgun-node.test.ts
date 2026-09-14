import { describe, expect, it } from 'vitest';

import { deriveRailgunKeysByIndex, getRailgunPathsByIndex } from '../src/utils/railgun-node';

const TEST_MNEMONIC = 'test test test test test test test test test test test junk';
const INVALID_CHECKSUM_MNEMONIC =
  'test test test test test test test test test test test abandon';

describe('getRailgunPathsByIndex', () => {
  it('returns hardened spending and viewing paths', () => {
    const paths = getRailgunPathsByIndex(0);
    expect(paths.spending).toBe("m/44'/1984'/0'/0'/0'");
    expect(paths.viewing).toBe("m/420'/1984'/0'/0'/0'");
  });
});

describe('deriveRailgunKeysByIndex', () => {
  it('preserves the expected keys when no password is supplied', () => {
    const keys = deriveRailgunKeysByIndex(TEST_MNEMONIC, 0);
    expect(keys.spending).toBe('b0958f8bc286ae0832fa83b01b719a225a07ce7b861ff311323f221667b3bd50');
    expect(keys.viewing).toBe('9da4b4f0b5493a6ba3f7df0611c3e0842f7e2bb3d640f313b235f1b75c1d80b9');
  });

  it('derives different expected keys when a password is supplied', () => {
    const keys = deriveRailgunKeysByIndex(TEST_MNEMONIC, 0, 'secret');
    expect(keys.spending).toBe('65461f0b483b78680283b1770b5d9c6388ff86a5ef60c2a1a36ed56c51abdb9f');
    expect(keys.viewing).toBe('404663af454004f39be93b94e5e0cdcb6a0fcd91d0cb7f7dd5ac5ff50e6fa19f');
  });

  it('rejects a mnemonic with an invalid checksum', () => {
    expect(() => deriveRailgunKeysByIndex(INVALID_CHECKSUM_MNEMONIC, 0)).toThrow(
      'Invalid mnemonic',
    );
  });
});
