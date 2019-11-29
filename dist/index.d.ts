/// <reference types="node" />
declare type mnemonicType = string | any;
export declare const wordlists: {
    EN: any;
};
export declare function mnemonicToSeed(mnemonic: mnemonicType, password: string | any): Buffer;
export declare function mnemonicToSeedHex(mnemonic: mnemonicType, password: string): string;
export declare function mnemonicToEntropy(mnemonic: mnemonicType, wordlist?: any): string;
export declare function entropyToMnemonic(entropy: any, wordlist?: any): string;
export declare function generateMnemonic(strength: number, rng: Function, wordlist?: any): Promise<unknown>;
export declare function validateMnemonic(mnemonic: mnemonicType, wordlist?: any): boolean;
export declare function checksumBits(entropyBuffer: Buffer | any): string;
export declare function salt(password: string): string;
declare const _default: {
    mnemonicToSeed: typeof mnemonicToSeed;
    mnemonicToSeedHex: typeof mnemonicToSeedHex;
    mnemonicToEntropy: typeof mnemonicToEntropy;
    entropyToMnemonic: typeof entropyToMnemonic;
    generateMnemonic: typeof generateMnemonic;
    validateMnemonic: typeof validateMnemonic;
    wordlists: {
        EN: any;
    };
};
export default _default;
