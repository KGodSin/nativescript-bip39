"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
var nativescript_pbkdf2_1 = require("nativescript-pbkdf2");
var assert_1 = __importDefault(require("assert"));
var unorm_1 = __importDefault(require("unorm"));
var create_hash_1 = __importDefault(require("create-hash"));
var randomBytes = require("nativescript-randombytes");
var DEFAULT_WORDLIST = require("../wordlists/en.json");
exports.wordlists = {
    EN: DEFAULT_WORDLIST
};
function mnemonicToSeed(mnemonic, password) {
    var mnemonicBuffer = new Buffer(mnemonic, "utf8");
    var saltBuffer = new Buffer(salt(password), "utf8");
    return nativescript_pbkdf2_1.pbkdf2Sync(mnemonicBuffer, saltBuffer, 2048, 64, "sha512");
}
exports.mnemonicToSeed = mnemonicToSeed;
function mnemonicToSeedHex(mnemonic, password) {
    return mnemonicToSeed(mnemonic, password).toString("hex");
}
exports.mnemonicToSeedHex = mnemonicToSeedHex;
function mnemonicToEntropy(mnemonic, wordlist) {
    wordlist = wordlist || DEFAULT_WORDLIST;
    var words = mnemonic.split(" ");
    assert_1.default(words.length % 3 === 0, "Invalid mnemonic");
    var belongToList = words.every(function (word) {
        return wordlist.indexOf(word) > -1;
    });
    assert_1.default(belongToList, "Invalid mnemonic");
    // convert word indices to 11 bit binary strings
    var bits = words
        .map(function (word) {
        var index = wordlist.indexOf(word);
        return lpad(index.toString(2), "0", 11);
    })
        .join("");
    // split the binary string into ENT/CS
    var dividerIndex = Math.floor(bits.length / 33) * 32;
    var entropy = bits.slice(0, dividerIndex);
    var checksum = bits.slice(dividerIndex);
    // calculate the checksum and compare
    var entropyBytes = entropy.match(/(.{1,8})/g).map(function (bin) {
        return parseInt(bin, 2);
    });
    var entropyBuffer = new Buffer(entropyBytes);
    var newChecksum = checksumBits(entropyBuffer);
    assert_1.default(newChecksum === checksum, "Invalid mnemonic checksum");
    return entropyBuffer.toString("hex");
}
exports.mnemonicToEntropy = mnemonicToEntropy;
function entropyToMnemonic(entropy, wordlist) {
    wordlist = wordlist || DEFAULT_WORDLIST;
    var entropyBuffer = new Buffer(entropy, "hex");
    var entropyBits = bytesToBinary([].slice.call(entropyBuffer));
    var checksum = checksumBits(entropyBuffer);
    var bits = entropyBits + checksum;
    var chunks = bits.match(/(.{1,11})/g);
    var words = chunks.map(function (binary) {
        var index = parseInt(binary, 2);
        return wordlist[index];
    });
    return words.join(" ");
}
exports.entropyToMnemonic = entropyToMnemonic;
function generateMnemonic(strength, rng, wordlist) {
    return new Promise(function (resolve, reject) {
        strength = strength || 128;
        rng = rng || randomBytes;
        rng(strength / 8, function (error, randomBytesBuffer) {
            if (error) {
                reject(error);
            }
            else {
                resolve(entropyToMnemonic(randomBytesBuffer.toString("hex"), wordlist));
            }
        });
    });
}
exports.generateMnemonic = generateMnemonic;
function validateMnemonic(mnemonic, wordlist) {
    try {
        mnemonicToEntropy(mnemonic, wordlist);
    }
    catch (e) {
        return false;
    }
    return true;
}
exports.validateMnemonic = validateMnemonic;
function checksumBits(entropyBuffer) {
    var hash = create_hash_1.default("sha256")
        .update(entropyBuffer)
        .digest();
    // Calculated constants from BIP39
    var ENT = entropyBuffer.length * 8;
    var CS = ENT / 32;
    return bytesToBinary([].slice.call(hash)).slice(0, CS);
}
exports.checksumBits = checksumBits;
function salt(password) {
    return "mnemonic" + (unorm_1.default.nfkd(password) || ""); // Use unorm until String.prototype.normalize gets better browser support
}
exports.salt = salt;
//=========== helper methods from bitcoinjs-lib ========
function bytesToBinary(bytes) {
    return bytes
        .map(function (x) {
        return lpad(x.toString(2), "0", 8);
    })
        .join("");
}
function lpad(str, padString, length) {
    while (str.length < length)
        str = padString + str;
    return str;
}
exports.default = {
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
