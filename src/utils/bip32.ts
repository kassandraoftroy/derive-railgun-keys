import { Bytes, Hex } from "ox";
import { ethers } from "ethers";

export type KeyNode = {
  chainKey: string;
  chainCode: string;
};

function fromUTF8String(string: string): Hex.Hex {
  return Bytes.toHex(new TextEncoder().encode(string));
}

function pad32Bit(num: number): string {
  return (num).toString(16).padStart(8, '0');
}

function sha512HMAC(key: Hex.Hex, data: Hex.Hex): string {
  return ethers.computeHmac('sha512', Hex.toBytes(key), Hex.toBytes(data)).slice(2);
}

const CURVE_SEED = fromUTF8String('babyjubjub seed');

/**
 * Tests derivation path to see if it's valid
 * @param path - bath to test
 * @returns valid
 */
function isValidPath(path: string): boolean {
  return /^m(\/[0-9]+')+$/g.test(path);
}

/**
 * Converts path string into segments
 * @param path - path string to parse
 * @returns array of indexes
 */
export function getPathSegments(path: string): number[] {
  // Throw if path is invalid
  if (!isValidPath(path)) throw new Error('Invalid derivation path');

  // Split along '/' to get each component
  // Remove the first segment as it is the 'm'
  // Remove the ' from each segment
  // Parse each segment into an integer
  return path
    .split('/')
    .slice(1)
    .map((val) => val.replace("'", ''))
    .map((el) => parseInt(el, 10));
}

/**
 * Derive child KeyNode from KeyNode via hardened derivation
 * @param node - KeyNode to derive from
 * @param index - index of child
 */
export function childKeyDerivationHardened(
  node: KeyNode,
  index: number,
  offset: number = 0x80000000,
): KeyNode {
  // Convert index to bytes as 32bit big endian
  const indexFormatted = pad32Bit(index+offset);

  // Calculate HMAC preImage
  const preImage = `00${node.chainKey}${indexFormatted as string}`;

  // Calculate I
  const I = sha512HMAC(`0x${node.chainCode}`, `0x${preImage}`);

  // Slice 32 bytes for IL and IR values, IL = key, IR = chainCode
  const chainKey = I.slice(0, 64);
  const chainCode = I.slice(64);

  // Return node
  return {
    chainKey,
    chainCode,
  };
}

/**
 * Creates KeyNode from seed
 * @param seed - bip32 seed
 * @returns BjjNode - babyjubjub BIP32Node
 */
export function getMasterKeyFromSeed(seed: Hex.Hex): KeyNode {
  // HMAC with seed to get I
  const I = sha512HMAC(CURVE_SEED, seed);

  // Slice 32 bytes for IL and IR values, IL = key, IR = chainCode
  const chainKey = I.slice(0, 64);
  const chainCode = I.slice(64);

  // Return node
  return {
    chainKey,
    chainCode,
  };
}
