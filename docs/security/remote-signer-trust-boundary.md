# Arc remote-signer trust-boundary analysis

This analysis was performed on arc-node commit
`2a3e8ab10c0ac97bf1a2628a325eb98d4a468b1a` and relates it to the reported
arc-remote-signer commit `a9e9fdb48c1e96a6c3fb875aba3d341e6a8af1a6`.

## Result

The missing call-chain exists. An arc-node validator configured with
`--signing.remote` calls both `SignerService/PublicKey` and
`SignerService/Sign`. `Sign` receives the raw Arc SSZ sign bytes, not a hash.
The client does not add a chain ID, domain separator, authentication metadata,
or client certificate. A CA certificate may optionally authenticate the server,
but this is one-way TLS. Therefore, any party that can reach an unprotected
signer and construct an Arc message can obtain a signature that the production
consensus verifier accepts for that signer's validator identity.

This repository does **not**, however, establish that a production signer is
network reachable by an attacker. It contains neither the production signer
workload nor its SecurityGroup/NetworkPolicy. The checked-in compose deployment
does not enable remote signing at all. Consequently the code proves the signing
oracle's consensus impact *conditional on network access*, but does not prove a
production exploit. Recommended HackerOne severity is **Medium** pending proof
of production reachability; raise to **High** if an untrusted tenant or Internet
client can reach a production validator signer. Critical is not supported by
the evidence here.

## Exact call-chain

1. `Node::consensus_identity` converts `SigningConfig::Remote`, creates
   `RemoteSigningProvider`, calls `public_key()`, and derives the validator
   address as the first 20 bytes of Keccak-256(public key).
2. `RemoteSigningProvider::public_key` calls
   `RemoteSignerClient::get_public_key`, which sends an empty
   `PublicKeyRequest` to `SignerServiceClient::public_key`.
3. Malachite engine effects `SignVote` and `SignProposal` call the configured
   provider's `sign_vote` and `sign_proposal` methods.
4. Those methods call `Vote::to_sign_bytes` or `Proposal::to_sign_bytes`, then
   `SigningProvider::sign_bytes`, `RemoteSignerClient::sign_message`, and
   `SignerServiceClient::sign(SignRequest { message })`.
5. The returned 64 bytes become an Ed25519 `Signature`, then
   `SignedVote::new(vote, signature)` or
   `SignedProposal::new(proposal, signature)`. Network SSZ represents a signed
   vote as the 64-byte signature plus the vote.
6. A receiving Malachite engine handles `Effect::VerifySignature` and calls
   `verify_signed_vote`/`verify_signed_proposal` using the public key selected
   from the validator set. Arc recomputes `to_sign_bytes()` and invokes
   Ed25519 `public_key.verify(bytes, signature)`. Commit-certificate checking
   reconstructs a precommit for each validator and performs the same call.

## Signed representation

Votes are SSZ containers in this field order: vote type, `u64` height, round,
nil-or-value block ID, and 20-byte validator address. Vote extensions are
removed before signing. Proposals contain height, round, 32-byte block value,
POL round, and validator address. Integers and SSZ offsets are little-endian;
the vote-type tag is `00` for prevote and `01` for precommit. The value is an
SSZ option (`00` nil, `01 || block_hash` non-nil). There is no prehash: these
raw bytes are passed to Ed25519 and to the gRPC request.

The bytes bind height, round, vote type, block hash (for a non-nil vote), and
validator address. They do **not** bind chain ID, network, a vote/proposal domain
tag beyond their different layouts, or the full validator public key. Validator
identity is nevertheless enforced at verification because the receiver looks
up and uses the validator-set public key for the claimed address.

## Reproducible local vectors

The end-to-end regression test uses only the deterministic ephemeral seed
`[0x42; 32]`. It binds a real generated `SignerService` to an OS-assigned port
on `127.0.0.1`, connects through the production `RemoteSignerClient` over
plaintext h2c without metadata, calls `PublicKey` and `Sign`, attaches the RPC
responses to production `SignedVote`/`SignedProposal` values, and invokes the
production provider verifier. It contacts no non-loopback network.

The localhost service implements the reviewed signer's two RPC handlers against
the real protobuf/tonic service contract: `PublicKey` returns the ephemeral key
and `Sign` applies Ed25519 directly to `SignRequest.message`. The external
arc-remote-signer repository is not vendored into arc-node, so this test does
not claim binary identity with its executable; it proves the complete wire-level
arc-node call-chain without assuming that a locally produced primitive signature
is equivalent to an RPC response.

* Chain ID: **absent**
* Height: `42`; round: `7`; type: `Precommit` (`01`)
* Public key: `2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12`
* Validator address: `8f02ee515a01644c9b5ad6f040be53a7918f272a`
* Block A: 32 bytes of `aa`
* Vote A: `012a00000000000000250000002a0000008f02ee515a01644c9b5ad6f040be53a7918f272a010700000001aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`
* Signature A: `5fa41cd81ab879c35b7da39e578d663bae3db724b5dd66bd138087ea91684a526f556e808cb7ebb0567729a3116ba11c7cf58eaf99ba043f6baf04cd34450c0c`
* Block B: 32 bytes of `bb`
* Vote B: `012a00000000000000250000002a0000008f02ee515a01644c9b5ad6f040be53a7918f272a010700000001bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb`
* Signature B: `c627b87a284c24c8d7c57896b906cc4004e32bc1c402af5f65d671b105f1d75fc270b4762e6a565fb15df3daf1ba013df7132b11a2ef18d29e6d5cb19a922405`
* Proposal (`cc` block): `2a0000000000000044000000cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc490000008f02ee515a01644c9b5ad6f040be53a7918f272a010700000000`
* Proposal signature: `4cf79676f7387fa458b98de9273ecd1a930706c1b0d5175b0e73dcf16a767b17e5c1763e751ffab4a8cc6aceb3ac54e2713f82770d756dfd2b7c3dd8c61ba306`
* Verification: both conflicting votes and the proposal return valid independently.

Reproduce the complete PoC and retain the dynamically selected listen address:

```console
cargo test -p arc-remote-signer \
  localhost_signer_accepts_and_verifies_conflicting_canonical_votes \
  -- --nocapture
```

Expected output fields are `listen_address=127.0.0.1:<ephemeral-port>`,
`transport=plaintext_h2c auth=none`, the public key and canonical/signature
vectors above, followed by
`production_verifier=vote_a:true vote_b:true proposal:true`.

The recorded run for this report selected `127.0.0.1:46489` and printed:

```text
transport=plaintext_h2c auth=none endpoint=http://127.0.0.1:46489
public_key=2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12
production_verifier=vote_a:true vote_b:true proposal:true
```

The port is intentionally ephemeral and will differ on later runs. After the
test, `git diff --exit-code HEAD -- . ':(exclude)target'` verifies that executing
the PoC did not modify any tracked source or configuration file.

This does not mean consensus accepts both votes into one quorum without other
rules: Malachite detects/evidences equivocation and its vote keeper controls
state transitions. It means cryptographic verification alone accepts each
signature, as expected. No slashing-protection or high-water-mark state exists
in arc-node's remote client or the reported signer; the consensus WAL is crash
recovery state, not an authorization boundary for direct signer callers.

## Transport and deployment boundary

An `http://` endpoint creates plaintext h2c gRPC. Supplying
`--signing.tls-cert-path` configures a trusted CA and `https://`, but the client
sets no client identity. There is no bearer token, call credential, metadata
credential, SPIFFE identity, or mTLS client certificate in the request path.

Documentation shows the illustrative endpoint
`http://validator-signer-proxy:10340`; unit tests use `http://signer:10340` and
the library default is `http://0.0.0.0:10340`. These are examples/defaults, not
proof of production topology. The repository cannot answer whether validator
and signer share a host/pod or use separate pods/EC2 instances, and contains no
signer-specific firewall, SecurityGroup, or NetworkPolicy. That missing
deployment evidence is the key counterargument: unauthenticated signing can be
an intended design under a strictly private, single-client network trust
boundary. Even then, mTLS/application authorization, signer-side canonical
parsing/domain checks, and durable double-sign protection are recommended
defense in depth.
