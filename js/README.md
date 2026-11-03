## libdave JS

Contains the package @discordapp/libdave. This is leveraged by Discord clients to enable out-of-band verifications of DAVE protocol call members and the MLS epoch authenticator.

### Testing

Testing uses [Jest](https://jestjs.io/). You can run the tests with `pnpm test`.

`pnpm test:wasm` runs the wasm binding tests in `__tests__/wasm`. They load `wasm/libdave.{js,wasm,d.ts}`, so build with `make wasm` in `cpp/` and copy those files into `wasm/` first.

### Dependencies

- [@noble/hashes](https://github.com/paulmillr/noble-hashes)
- [base64-js](https://www.npmjs.com/package/base64-js)