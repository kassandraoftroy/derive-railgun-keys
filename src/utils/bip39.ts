import { HDKey } from 'ethereum-cryptography/hdkey';
import * as bip39 from 'ethereum-cryptography/bip39';
import { wordlist } from 'ethereum-cryptography/bip39/wordlists/english';
import { Hex, Bytes } from 'ox';

const getWalletPath = (index = 0) => {
  return `m/44'/60'/0'/0/${index}`;
};

export class Mnemonic {
  static generate(strength: 128 | 192 | 256 = 128): string {
    return bip39.generateMnemonic(wordlist, strength);
  }

  static validate(mnemonic: string): boolean {
    return bip39.validateMnemonic(mnemonic, wordlist);
  }

  static toSeed(mnemonic: string, password: string = ''): Hex.Hex {
    return Bytes.toHex(bip39.mnemonicToSeedSync(mnemonic, password));
  }

  static toEntropy(mnemonic: string): Hex.Hex {
    return Bytes.toHex(bip39.mnemonicToEntropy(mnemonic, wordlist));
  }

  static fromEntropy(entropy: Hex.Hex): string {
    return bip39.entropyToMnemonic(Hex.toBytes(entropy), wordlist);
  }

  static to0xPrivateKey(mnemonic: string, path: string): Hex.Hex {
    const seed = bip39.mnemonicToSeedSync(mnemonic);
    const node = HDKey.fromMasterSeed(seed).derive(path);
    return Hex.fromBytes(node.privateKey as Uint8Array);
  }

  static to0xPrivateKeyByIndex(mnemonic: string, derivationIndex: number): Hex.Hex {
    const path = getWalletPath(derivationIndex);
    return this.to0xPrivateKey(mnemonic, path);
  }
}