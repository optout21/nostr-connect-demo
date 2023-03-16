# nostr-connect-demo
Demo app pair for Nostr Connect NIP-46, including a client with UI.

## Warning

This a sample demo, the signer does blind signing, use only with test keys (never with personal or other keys in production)!

## How to run

- Run the client

```
cd noco-client
cargo run
```

OR

```
cd noco-client-ui
cargo run
```

- Run the server (from another session)

```
cd noco-signer
cargo run
```

- Optionally you may want to set your own relay, in `noco-client/src/main.rs` `APP_RELAY`
- You may want to use a different client app key (`APP_SECRET_KEY`)
- If you do any change like the above, you need to copy paste the Nostr Connect URI from the output of the client, to `noco-signer/src/main.rs` `SAMPLE_NOSTR_CONNECT_URL`
- You may want to use different keys for the signer (`USER_SECRET_KEY`)

## Flow

The flow of events is somthing like this:

- Signer connects to the client
- Client accepts the connection
- Client sends a Describe request
- Signer replies
- Client sends a GetPublicKey request
- Signer replies
- Client sends a SignEvent request -- on UI version this is triggered by a button
- Signer signs and replies
- Client publiches the resulting signed message

## Sample Output

```
My pubkey 79dff8f82963424e0bb02708a22e44b4980893e3a4be0fa3cb60a43b946764e3
Nostr Connect URI: nostrconnect://79dff8f82963424e0bb02708a22e44b4980893e3a4be0fa3cb60a43b946764e3?relay=wss%3A%2F%2Fnos.lol%2F&metadata=%7B%22name%22%3A%22NoConnect-Client%22%2C%22url%22%3A%22https%3A%2F%2Fexample.com%2F%22%7D
Connected to relay wss://nos.lol
Subscribed to relay events ...
Waiting for messages, first for a 'connect' from a signer ...
New message received request connect
Got connect request, from pubkey XOnlyPublicKey(8b4135cde2c3e55a723ed8208e1827c1526c64fd9ad465f6c0418c06fc874c9940491b4db10c82383841cf917588fd6d1b60dbdf3cf3bd20612a579a530efaf8)
Sending Describe ...
Message sent, request describe
New message received response
Got Describe response, ["describe", "get_public_key", "sign_event"]
Sending GetPublicKey ...
Message sent, request get_public_key
New message received response
Got PublicKey response, XOnlyPublicKey(58916740538929864c37b8afcd6a17b4a6be22f146d4031924c6cd9df42a73ae8c3d4e941ccddead0db27bb80bdd8cb8dd2ae84d57ac46f20ddef8f8f68512a3)
Sending Sign ...
Message sent, request sign_event
New message received response
Got SignEvent response, Signature(2938b74b2c66cdf565fc5acf3132c3859b6d9fd1e5d108e71a71a5bcc5cf661d4a28f2fbee5a9c2d8033075fd12a82c204c93844b61f854fa86ccb1d7dd43c3b)
Published event, count 1, id 8f9e4f0a076da48f5bf261a257e2d2fd229ad01eac8851f9995d5e6af5732a97
```

## References

- [Keystr app](https://github.com/keystr/keystr-rs) with Signer support
- [Sample](https://github.com/rust-nostr/nostr/blob/master/crates/nostr-sdk/examples/nostr_connect.rs) in [rust-nostr/nostr-sdk](https://github.com/rust-nostr/nostr) by [yukibtc](https://github.com/yukibtc)
- NIP-46 Delegations Spec https://github.com/nostr-protocol/nips/blob/master/46.md

## Contact

Nostr: optout@nostrplebs.com npub1kxgpwh80gp79j0chc925srk6rghw0akggduwau8fwdflslh9jvqqd3lecx
