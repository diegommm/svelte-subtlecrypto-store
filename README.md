# svelte-subtlecrypto-store

This module provides an encrypted writable store for Svelte using the Crypto and
SubtleCrypto APIs.

This is mainly a proof-of-concept, and is largely based on the documentation
found at Mozilla Developer Network Web Docs:

- [Crypto](https://developer.mozilla.org/en-US/docs/Web/API/Crypto)
- [SubtleCrypto](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto)
- [Base64](https://developer.mozilla.org/en-US/docs/Glossary/Base64)

## Motivation

I'm not a cryptographer. I don't write crypto. They say: don't write crypto, but
when you do, learn why you shouldn't have.

On top of it, I'm doing it to learn JavaScript and Svelte. This should be enough
for you not to use this module for anything else but what is stated in the
introduction: a proof-of-concept, or just fun.

## Security details

Encryption is done with AES-256-GCM and key derivation with PBKDF2 with SHA-384.
The Salt and Initialization Vector are generated with `Crypto.getRandomValues`.
There are only three configurable options:

- The number of iterations for PBKDF2.
- The length of the salt for PBKDF2.
- The length of the Initialization Vector for AES-256-GCM.

All these values have very well documented defaults, and you can override any or
all of them passing the `opts` parameter. Example:

```
import { writable } from 'svelte/store';
import { subtleCryptoStore } from 'svelte-subtlecrypto-store';

const backend = writable('');
const store = subtleCryptoStore(window.crypto, backend, 'my super pass', {
    iterations: 10000,
    saltLength: 16,
    ivLength: 64
});
```

*NOTE*: these options are very strictly expected to be finite, positive
integer values of type `number`. If you supply something like `'16'` or `16.1`
that value will be dropped and a default used. Use predefined constants,
sanitize your input or check the returned `options` member, which contains the
parameters being used.

## Compatibility

Source code is written in typescript targetting es2016. By then Crypto and
SubtleCrypto APIs were already available in most major browsers.

Crypto and SubtleCrypto APIs are only available in a
[Secure Context](https://developer.mozilla.org/en-US/docs/Web/Security/Secure_Contexts).
For browsers, this means that the `Window` or `Worker` have an HTTPS origin, and
if the window belongs to an `iframe`, then all its ancestors are also delivered
through HTTPS. There are other cases as well, you can read the linked document
for more information. At runtime, the global and readonly property
[isSecureContext](https://developer.mozilla.org/en-US/docs/Web/API/isSecureContext)
can be used to easily detect the availability of these features, so if it
returns `true` then you should have access to these APIs.
