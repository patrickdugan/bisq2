# BISQ Easy Proven BTC Payment (research, feature flag)

Status: research. The feature is off by default. With the feature off, nothing in this document changes the behavior of a node.

In a BISQ Easy main-chain trade the seller pays the BTC to the address which the buyer sent. Today the buyer's node marks the BTC as received when the buyer confirms it. The buyer usually checks the payment in a block explorer, which is a third party that learns the address and the txid and can show wrong data.

With this feature the buyer's node marks the BTC as received only with a succinct proof that the payment is in the Bitcoin chain. The proof is a SNARK of the nova-bitvm3 M16 guest. It states that a transaction output with a given script and value is in a block with n confirmations under a tip whose header chain from genesis has valid proof of work. A node checks the statement against the trade and the proof against a pinned program. A node needs no full node, no explorer, and no trust in the seller.

## Choice of integration point

Of the candidate integration points, the BTC leg of a BISQ Easy trade is the strongest. That leg is a plain on-chain payment to a known script, and the M16 payment record commits exactly the fields that the trade defines: txid, output script, value, and confirmations.

The other candidates are weaker:
- BISQ MuSig oracle payout: the open question in a MuSig trade is the fiat leg, which no Bitcoin statement can prove. The workable shape there is an adaptor partial signature on a payout, gated by an oracle attestation of an off-chain fact. The proof of this document does not supply that fact.
- MuSig deposit confirmation: each MuSig party has a wallet that already watches the deposit transaction, so a proof adds little.

## Terms

- Statement: the public values that the guest commits. Guest A commits 1,164 bytes. The M16 guest adds a 128-byte payment record, so its statement has 1,292 bytes.
- Payment record: `"PAY1" | u32 segments | u32 height_B | hash_B | u32 confirmations | txid | u32 vout | u64 value | u32 script length | sha256(scriptPubKey)`. Integers are little endian. Hashes are in internal byte order, the reverse of the order that explorers show.
- State z: 17 canonical Pallas scalars of 32 bytes each, little endian. z[0] is the height, z[1] and z[2] are the low and high 128-bit halves of the tip block hash, and z[3] is the chainwork. z0 is the state at the start of the proven chain, zn the state at its tip.
- Network pin: the network magic (`NHC1` for mainnet, `NHT4` for testnet4), the fold width k, the SHA-256 of the Nova verifier key in compressed encoding, and the SHA-256 of the genesis state z0.
- Program verifying key digest: the SP1 digest that identifies the guest program. A proof is valid only for one program.

## Rules

Statement rules. The buyer's node accepts a statement only if all of these hold:
1. The statement has 1,164 or 1,292 bytes. Every element of z0 and zn is a canonical field element. The tip hash halves have at most 128 bits, and the heights fit in 32 bits.
2. The network magic and k equal the configured network pin.
3. The verifier key digest equals the pinned compressed-key digest.
4. SHA-256 of z0 equals the pinned genesis state digest.
5. The tip height minus the z0 height equals steps times k and is positive. The tip chainwork is greater than the z0 chainwork.
6. The tip chainwork is at least the minimum chainwork configured on the node.

Payment rules. For a confirmation of the BTC of a trade, also:

7. The statement has a payment record with magic `PAY1` and at least one segment.
8. `height_B + confirmations - 1` equals the tip height, and `confirmations` is at least 1.
9. If the seller reported a txid, the record's txid equals it.
10. The record's script length and script SHA-256 equal those of the scriptPubKey of the buyer's bitcoin payment data. The node reads the address from a bitcoin URI. It supports P2PKH, P2SH, segwit version 0 (bech32), and segwit versions 1 to 16 (bech32m) on the configured network.
11. The value is at least the contract's base side amount.
12. `confirmations` is at least the configured minimum.

Proof rules:

13. The program verifying key digest of the proof is in the configured set of trusted digests.
14. The SNARK verifier accepts the proof for exactly the statement bytes and that program. The node checks the proof after every other rule, because the proof check is the costliest step.

Trade rules:

15. With the feature on, the buyer's node of a main-chain trade does not apply a plain BTC confirmation. It applies the BTC confirmation only after rules 1 to 14 hold. The seller's node and Lightning trades keep the plain confirmation.
16. With the feature off, the plain confirmation works as before, and a confirmation with a proof is refused.

## Reasons

- Rules 2 to 4: the proof shows a valid chain from z0. Without the genesis pin, a prover could start from a made-up state. Without the key pin, a prover could use a Nova key for another step circuit.
- Rule 6: the proof shows a valid proof-of-work chain, not the heaviest chain. A prover could mine a short private fork from genesis with low total work. The minimum chainwork must come from a source the node trusts, for example a value shipped with the release, as Bitcoin Core does with `nMinimumChainWork`.
- Rule 8: the guest derives `height_B` from the tip height and the header count. A record that breaks rule 8 did not come from the guest.
- Rule 10: the record commits only a hash of the script, so the node compares hashes. Comparing a decoded address string would accept a different encoding of the same script or reject a correct one.
- Rule 11: the seller can pay more than the trade amount. A lower value is not the agreed payment.
- Rule 14: rules 1 to 13 hold for any byte string that has the right layout. Only the proof shows that the guest produced the bytes.

## Security considerations

- One payment, several trades: rules 1 to 14 do not bind a payment to one trade. A buyer who reuses an address in two trades with the same amount could see one payment proven twice. The node must reject an outpoint (txid and vout) that it has already used for another trade before the feature can be on by default. This draft does not store used outpoints yet.
- Freshness: the proven tip can be old. Rule 6 limits a forged chain, not an old honest chain. A reorganization deeper than the confirmations can remove the payment after the proof was made. The minimum confirmations should match the trade amount.
- The `m13-verify` binary decides rule 14, so the node trusts the configured command. Only the node's own configuration sets it, never a peer. The node limits the proof to 4 MiB before it writes it to disk, and it limits the process output it reads.
- The statement and proof come from the seller or from a proving service. Both are untrusted input. The parser reads fixed-size fields only and does not allocate by a length taken from the input.

## Limitations

- The SNARK verifier is the native `m13-verify verify-v2` (nova-bitvm3 M13, transcript v2, the proof format that the M14 garbled circuit evaluates). The node runs it as an external process. The node writes the expected statement: the pinned wrap key, the pinned recursion key root, the program verifying key digest, and SHA-256 of the statement bytes. A proof counts as accepted only if the process exits with 0 and reports `verified` for that statement digest. A timeout, a missing binary, or an I/O error counts as rejected. Without a configured command, every proof is rejected, so with the feature on the buyer of a main-chain trade cannot confirm the BTC. Bisq has no Java implementation of the verifier.
- The program verifying key digest of the M16 guest is not pinned yet. The mainnet header-chain fold that its first proof depends on is still running. The digest set is a configuration value, so it can be added without a code change.
- The cost of a proof is high: about 34 x 10^9 SP1 instructions, about 5 GPU hours per mainnet proof on a laptop. A garbled verifier instance is 12.6 GB. A proving service per trade is not practical yet. A proof for a batch of payments, or a proof made only on dispute, is cheaper.
- The buyer's desktop UI and the API have no input for the statement and the proof yet.

## Compatibility

- No message, protobuf, or storage change. The proof is checked only on the buyer's own node. The peer sees the same trade messages as before.
- Configuration: `trade.bisqEasy.provenBtcConfirmation` with `enabled` (default false), `network` (`MAINNET` or `TESTNET4`), `minConfirmations` (default 1), `minTipChainworkHex` (default 0), `trustedProgramVkDigests` (hex, default empty), and `m13Verify` with `command` (the program and leading arguments, default empty), `pathStyle` (`NATIVE`, or `WSL` for a Linux build run through `wsl.exe` on Windows), and `timeoutSeconds` (default 120). A missing block means off.

## Source of the pins

The pins and the layout come from the nova-bitvm3 handoff (`garbled-snark-verifier/nova-bitvm3/HANDOFF.md`) and the M16 guest (commit `d4aefcd`):
- mainnet k = 1 key: compressed digest `6aa50d09...da1d`, raw digest `4e815db8...7615`;
- testnet4 k = 1 key: compressed digest `6894f490...c12a`, raw digest `63f91f1e...d20e`;
- the M13 final layer, the same for every guest: wrap key SHA-256 `d42c63e3...b0d7`, recursion key root `7487c217...f257` (`nova-bitvm3/m13/pins.json`);
- the genesis state digests are SHA-256 of z0 taken from real guest output: the M16 block-170 test statement (`67a9deb9...`) for mainnet and guest A's proven testnet4 statement (`d3b478b0...`) for testnet4.
