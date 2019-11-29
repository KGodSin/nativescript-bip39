import { pbkdf2Sync } from "nativescript-pbkdf2";
import assert from "assert";
import unorm from "unorm";
import createHash from "create-hash";
const randomBytes = require("nativescript-randombytes");

type mnemonicType = string | any;

var DEFAULT_WORDLIST = require("../wordlists/en.json");

export const wordlists = {
	EN: DEFAULT_WORDLIST
};

export function mnemonicToSeed(mnemonic: mnemonicType, password: string | any) {
	var mnemonicBuffer = new Buffer(mnemonic, "utf8");
	var saltBuffer = new Buffer(salt(password), "utf8");

	return pbkdf2Sync(mnemonicBuffer, saltBuffer, 2048, 64, "sha512");
}

export function mnemonicToSeedHex(mnemonic: mnemonicType, password: string) {
	return mnemonicToSeed(mnemonic, password).toString("hex");
}

export function mnemonicToEntropy(mnemonic: mnemonicType, wordlist?: any) {
	wordlist = wordlist || DEFAULT_WORDLIST;

	var words = mnemonic.split(" ");
	assert(words.length % 3 === 0, "Invalid mnemonic");

	var belongToList = words.every(function(word: string) {
		return wordlist.indexOf(word) > -1;
	});

	assert(belongToList, "Invalid mnemonic");

	// convert word indices to 11 bit binary strings
	var bits = words
		.map(function(word: string) {
			var index = wordlist.indexOf(word);
			return lpad(index.toString(2), "0", 11);
		})
		.join("");

	// split the binary string into ENT/CS
	var dividerIndex = Math.floor(bits.length / 33) * 32;
	var entropy = bits.slice(0, dividerIndex);
	var checksum = bits.slice(dividerIndex);

	// calculate the checksum and compare
	var entropyBytes = entropy.match(/(.{1,8})/g).map(function(bin: BinaryType) {
		return parseInt(bin, 2);
	});
	var entropyBuffer = new Buffer(entropyBytes);
	var newChecksum = checksumBits(entropyBuffer);

	assert(newChecksum === checksum, "Invalid mnemonic checksum");

	return entropyBuffer.toString("hex");
}

export function entropyToMnemonic(entropy: any, wordlist?: any) {
	wordlist = wordlist || DEFAULT_WORDLIST;

	var entropyBuffer = new Buffer(entropy, "hex");
	var entropyBits = bytesToBinary(<[]>[].slice.call(entropyBuffer));
	var checksum = checksumBits(entropyBuffer);

	var bits = entropyBits + checksum;
	var chunks = <RegExpMatchArray>bits.match(/(.{1,11})/g);

	var words = chunks.map(function(binary) {
		var index = parseInt(binary, 2);

		return wordlist[index];
	});

	return words.join(" ");
}

export function generateMnemonic(
	strength: number,
	rng: Function,
	wordlist?: any
) {
	return new Promise((resolve, reject) => {
		strength = strength || 128;
		rng = rng || randomBytes;

		rng(strength / 8, (error: Error, randomBytesBuffer: Buffer | string) => {
			if (error) {
				reject(error);
			} else {
				resolve(entropyToMnemonic(randomBytesBuffer.toString("hex"), wordlist));
			}
		});
	});
}

export function validateMnemonic(mnemonic: mnemonicType, wordlist?: any) {
	try {
		mnemonicToEntropy(mnemonic, wordlist);
	} catch (e) {
		return false;
	}

	return true;
}

export function checksumBits(entropyBuffer: Buffer | any) {
	var hash = createHash("sha256")
		.update(entropyBuffer)
		.digest();

	// Calculated constants from BIP39
	var ENT = entropyBuffer.length * 8;
	var CS = ENT / 32;

	return bytesToBinary(<[]>[].slice.call(hash)).slice(0, CS);
}

export function salt(password: string) {
	return "mnemonic" + (unorm.nfkd(password) || ""); // Use unorm until String.prototype.normalize gets better browser support
}

//=========== helper methods from bitcoinjs-lib ========

function bytesToBinary(bytes: []) {
	return bytes
		.map(function(x: number) {
			return lpad(x.toString(2), "0", 8);
		})
		.join("");
}

function lpad(str: string, padString: string, length: number | string) {
	while (str.length < length) str = padString + str;
	return str;
}

export default {
	mnemonicToSeed: mnemonicToSeed,
	mnemonicToSeedHex: mnemonicToSeedHex,
	mnemonicToEntropy: mnemonicToEntropy,
	entropyToMnemonic: entropyToMnemonic,
	generateMnemonic: generateMnemonic,
	validateMnemonic: validateMnemonic,
	wordlists: {
		EN: DEFAULT_WORDLIST
	}
};
