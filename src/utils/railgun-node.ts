import { childKeyDerivationHardened, getMasterKeyFromSeed, getPathSegments } from './bip32.js';
import type { KeyNode } from './bip32.js';
import { Mnemonic } from './bip39.js';

const HARDENED_OFFSET = 0x80000000;

const DERIVATION_PATH_PREFIXES = {
  SPENDING: "m/44'/1984'/0'/0'/",
  VIEWING: "m/420'/1984'/0'/0'/",
};

export type RailgunKeys = {
  spending: string;
  viewing: string;
};
  
export const getRailgunPathsByIndex = (index: number = 0): RailgunKeys => {
  return {
    spending: `${DERIVATION_PATH_PREFIXES.SPENDING}${index}'`,
    viewing: `${DERIVATION_PATH_PREFIXES.VIEWING}${index}'`,
  };
};

export const deriveRailgunKey = (mnemonic: string, path: string, password: string = ''): string => {
  return RailgunNode.fromMnemonic(mnemonic, password).derive(path).chainKey;
};

export const deriveRailgunKeysByIndex = (
  mnemonic: string,
  index: number,
  password: string = '',
): RailgunKeys => {
  const paths = getRailgunPathsByIndex(index);
  return {
    spending: deriveRailgunKey(mnemonic, paths.spending, password),
    viewing: deriveRailgunKey(mnemonic, paths.viewing, password),
  };
};

export class RailgunNode {  
  chainKey: string;

  chainCode: string;

  constructor(keyNode: KeyNode) {
    this.chainKey = keyNode.chainKey;
    this.chainCode = keyNode.chainCode;
  }

  /**
   * Create BIP32 node from mnemonic
   * @returns {RailgunNode}
   */
  static fromMnemonic(mnemonic: string, password: string = ''): RailgunNode {
    const seed = Mnemonic.toSeed(mnemonic, password);
    return new RailgunNode(getMasterKeyFromSeed(seed));
  }

  /**
   * Derives new BIP32Node along path
   * @param {string} path - path to derive along
   * @returns {BIP32Node} - new BIP32 implementation Node
   */
  derive(path: string): RailgunNode {
    // Get path segments
    const segments = getPathSegments(path);

    // Calculate new key node
    const keyNode = segments.reduce(
      (parentKeys: KeyNode, segment: number) =>
        childKeyDerivationHardened(parentKeys, segment, HARDENED_OFFSET),
      {
        chainKey: this.chainKey,
        chainCode: this.chainCode,
      },
    );
    return new RailgunNode(keyNode);
  }
}
