"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.subtleCryptoStore = exports.defaultIvLength = exports.defaultSaltLength = exports.defaultIterations = void 0;
const store_1 = require("svelte/store");
/** Default value for 'iterations' in Options */
exports.defaultIterations = 100000;
/** Default value for 'saltLength' in Options */
exports.defaultSaltLength = 32;
/** Default value for 'ivLength' in Options */
exports.defaultIvLength = 96;
/**
 * Implements an encrypted Svelte writable store using the Crypto and
 * SubtleCrypto APIs with AES-GCM. The data is written to and read from a
 * supporting backend store.
 *
 * The returned store expects a string (or a promise resolving to a string) when
 * being written to, and returns a promise that resolves to the decrypted string
 * when being read from.
 *
 * The underlying backend is not written to in case of error while encrypting.
 *
 * The written format is IV + Salt + Ciphertext concatenated, and then Base64
 * encoded as a string. The data read is first processed with TextEncoder.
 *
 * The returned store also has the an extra property called `options`, which is
 * an object containing the options used to create the store. This can be used
 * to check how it was created and save them since they are necessary to decrypt
 * the data. Also note that the supplied options are treated very strictly, and
 * in case they are present but invalid values they are replaced by the
 * defaults. For example, `iterations`, `saltLength` and `ivLength` are all
 * expected to be of type number and be positive, finite integers. If you supply
 * something like '16' or 16.1 for `saltLength`, then the default will be used.
 * In the case you rely on loose inputs for these parameters, use the returned
 * `options` member of the store to assert that they were interpreted as you
 * expected them to. Your backing store will not be written to if it already has
 * a string in it so you still have the chance to check your options. Otherwise
 * use properly defined data in constants or sanitize your inputs.
 *
 * @param backend - A writable Svelte store that implements set and subscribe.
 * Data will be written to and read from this store, and is expected to hold
 * a string.
 * @param password - The encryption password.
 * @param opts - An optional object containing additional arguments.
 * @param crypto - The Crypto implementation, which is typically found as
 * window.crypto in browser contexts.
 *
 * @example
 * ```
 * import { writable } from 'svelte/store';
 * import { subtleCryptoStore } from 'svelte-subtlecrypto-store';
 *
 * const backend = writable('');
 * const store = subtleCryptoStore(window.crypto, backend, 'my super pass');
 *
 * $store = 'some secret'; // automatically encrypted
 * console.log($store); // prints the string 'some secret' to the console
 * console.log($backend); // prints the Base64 encoded IV+Salt+Ciphertext
 * ```
 */
exports.subtleCryptoStore = Object.freeze(function (backend, password, opts, cr = window.crypto) {
    if (typeof opts === 'undefined')
        opts = {};
    const o = Object.freeze({
        iterations: positiveIntOrDefault(opts, 'iterations', exports.defaultIterations),
        saltLength: positiveIntOrDefault(opts, 'saltLength', exports.defaultSaltLength),
        ivLength: positiveIntOrDefault(opts, 'ivLength', exports.defaultIvLength),
    });
    const getMemoized = newMemoized(cr.subtle, password);
    const decrypt = newDecryptFunc(cr, getMemoized, o);
    return Object.freeze({
        subscribe: Object.freeze((0, store_1.derived)(backend, decrypt, Promise.resolve('')).subscribe),
        set: Object.freeze(function (value) {
            return __awaiter(this, void 0, void 0, function* () {
                try {
                    let newVal;
                    newVal = yield encrypt(cr, getMemoized, o, value);
                    backend.set(newVal);
                    return Promise.resolve(undefined);
                }
                catch (e) {
                    return Promise.reject(e);
                }
            });
        }),
        update: Object.freeze(function (updater) {
            return __awaiter(this, void 0, void 0, function* () {
                try {
                    let newVal;
                    const cur = decrypt((0, store_1.get)(backend));
                    newVal = yield encrypt(cr, getMemoized, o, updater(cur));
                    backend.set(newVal);
                    return Promise.resolve(undefined);
                }
                catch (e) {
                    return Promise.reject(e);
                }
            });
        }),
        options: o,
    });
});
/** Returns a function that decrypts a ciphertext using AES-GCM. */
const newDecryptFunc = Object.freeze(function (crypto, getMemoized, o) {
    return Object.freeze(function (s) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                if (typeof s !== 'string' || s === '')
                    return Promise.resolve('');
                const m = yield getMemoized();
                const b64decoded = base64DecodeToBytes(s);
                if (b64decoded.byteLength < o.ivLength + o.saltLength + 1)
                    throw new Error('insufficient data');
                const iv = b64decoded.slice(0, o.ivLength);
                const salt = b64decoded.slice(o.ivLength, o.ivLength + o.saltLength);
                const ciphertext = b64decoded.slice(o.ivLength + o.saltLength);
                const key = yield getKey(crypto.subtle, m.keyMaterial, salt, o.iterations);
                const plainBytes = yield crypto.subtle.decrypt({
                    name: 'AES-GCM',
                    iv: iv,
                }, key, ciphertext);
                return Promise.resolve(m.textDecoder.decode(plainBytes));
            }
            catch (e) {
                return Promise.reject(e);
            }
        });
    });
});
/** Encrypts the givn plain text using AES-GCM. */
const encrypt = Object.freeze(function (crypto, getMemoized, o, plainText) {
    return __awaiter(this, void 0, void 0, function* () {
        if (typeof plainText === 'undefined')
            throw new Error('undefined plain text');
        const s = yield plainText;
        if (typeof s !== 'string')
            throw new Error('only strings are supported as input for encryption');
        if (s === '')
            return Promise.resolve('');
        const m = yield getMemoized();
        const iv = crypto.getRandomValues(new Uint8Array(o.ivLength));
        const salt = crypto.getRandomValues(new Uint8Array(o.saltLength));
        const key = yield getKey(crypto.subtle, m.keyMaterial, salt, o.iterations);
        const ciphertext = yield crypto.subtle.encrypt({
            name: 'AES-GCM',
            iv: iv,
        }, key, m.textEncoder.encode(s));
        return Promise.resolve(base64EncodeFromBytes(iv, salt, new Uint8Array(ciphertext)));
    });
});
/** Returns a key derived with PBKDF2 from the given key material. */
const getKey = Object.freeze(function (subtle, keyMaterial, salt, iterations) {
    return __awaiter(this, void 0, void 0, function* () {
        return subtle.deriveKey({
            name: 'PBKDF2',
            salt: salt,
            iterations: iterations,
            hash: 'SHA-384',
        }, keyMaterial, {
            name: 'AES-GCM',
            length: 256,
        }, false, ['encrypt', 'decrypt']);
    });
});
/** Lazily populates a `Memoized`, only once. */
const newMemoized = Object.freeze(function (subtle, password) {
    return memoize(Object.freeze(function () {
        return __awaiter(this, void 0, void 0, function* () {
            const enc = new TextEncoder();
            const ret = {
                textEncoder: enc,
                textDecoder: new TextDecoder(),
                keyMaterial: yield subtle.importKey('raw', enc.encode(password), { name: 'PBKDF2' }, false, ['deriveBits', 'deriveKey']),
            };
            return Promise.resolve(ret);
        });
    }));
});
/**
 * Given a function that computes a potentially expensive return value, returns
 * a new function that will call it to compute it only the first it's called,
 * store the returned value and return it. All further calls will return the
 * stored value.
 */
const memoize = Object.freeze(function (makeT) {
    let t;
    let f = makeT;
    return Object.freeze(function () {
        if (typeof f !== 'undefined') {
            t = f();
            f = undefined;
        }
        return t;
    });
});
/**
 * Attempts to get the given property of the object and returns it if it is a
 * positive, finite integer. Otherwise it returns the default value.
 */
const positiveIntOrDefault = Object.freeze(function (obj, prop, defaultValue) {
    if ((prop in obj) && positiveInt(obj.prop))
        return obj.prop;
    return defaultValue;
});
/** Returns whether the given argument is a positive, finite integer. */
const positiveInt = Object.freeze(function (n) {
    return typeof n === 'number' &&
        n === n && // discard NaN
        n > 0 && // discard non-positive
        n % 1 === 0; // discard floating point values and Infinity
});
/** Returns the Code Point at the first position of the given string. */
const toCodePoint = Object.freeze(function (s) {
    const res = s.codePointAt(0);
    if (typeof res !== 'number')
        // shouldn't happen in practice since this function is receiving the
        // output of atob
        throw new Error('invalid codepoint');
    return res;
});
/**
 * Decodes a Base64 encoded string into a binary representation. If the string
 * contains an invalid Code Point anywhere it throws.
 */
const base64DecodeToBytes = Object.freeze(function (s) {
    const binString = atob(s);
    return Uint8Array.from(binString, toCodePoint);
});
/**
 * Encodes to Base64 the concatenation of its inputs. The inputs can be any
 * iterable or array-like of number element type.
 */
const base64EncodeFromBytes = Object.freeze(function (...s) {
    let binString = '';
    for (let i = 0; i < s.length; i++)
        binString += String.fromCodePoint.apply(undefined, 
        // [typescript] Uint8Array values are not writable, so they don't
        // have push, pop, etc. But we know here we just need it for
        // readonly access, so we force-override the type to be able to call
        // `apply`.
        // See: https://github.com/microsoft/TypeScript/issues/55846
        s[i]);
    return btoa(binString);
});
