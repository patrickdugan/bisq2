/*
 * This file is part of Bisq.
 *
 * Bisq is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or (at
 * your option) any later version.
 *
 * Bisq is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with Bisq. If not, see <http://www.gnu.org/licenses/>.
 */

package bisq.trade.bitvm3;

import lombok.EqualsAndHashCode;
import lombok.Getter;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Optional;

/**
 * The public values committed by the nova-bitvm3 SP1 guests: guest A's 1,164-byte header-chain statement, optionally
 * followed by the M16 guest's 128-byte payment record.
 * <pre>
 * magic "NHC1"|"NHT4" | u32 k | u32 steps | z0 (17 x 32) | zn (17 x 32) | sha256(compressed vk) | proofs digest
 * [ "PAY1" | u32 segments | u32 height_B | hash_B | u32 confirmations | txid | u32 vout | u64 value
 *   | u32 script length | sha256(scriptPubKey) ]
 * </pre>
 * Integers are little endian. Hashes are in internal byte order. A state element is a canonical 32-byte little-endian
 * Pallas scalar: z[0] is the height, z[1] and z[2] the low and high 128-bit halves of the tip block hash, z[3] the
 * chainwork.
 * <p>
 * Parsing only checks the layout and the encoding of the state. Pins and the trade's expectations are checked by
 * {@link ProvenPaymentValidator}. See docs/specifications/trade/bisq-easy-proven-btc-payment.md.
 */
@Getter
@EqualsAndHashCode
public final class NovaChainStatement {
    public static final int STATE_ELEMENTS = 17;
    public static final int STATE_BYTES = STATE_ELEMENTS * 32;
    public static final int CHAIN_STATEMENT_LENGTH = 12 + 2 * STATE_BYTES + 64; // 1,164
    public static final int PAYMENT_RECORD_LENGTH = 128;
    public static final int PAYMENT_STATEMENT_LENGTH = CHAIN_STATEMENT_LENGTH + PAYMENT_RECORD_LENGTH; // 1,292

    // Scalar field of Pallas, the field of Nova's primary curve (PallasEngine::Scalar).
    static final BigInteger PALLAS_SCALAR_MODULUS =
            new BigInteger("40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001", 16);

    private final String networkMagic;
    private final long k;
    private final long steps;
    private final byte[] z0;
    private final byte[] zn;
    private final byte[] vkSha256;
    private final byte[] proofsDigest;
    private final Optional<PaymentRecord> paymentRecord;
    private final byte[] encoded;

    private NovaChainStatement(String networkMagic, long k, long steps, byte[] z0, byte[] zn, byte[] vkSha256,
                               byte[] proofsDigest, Optional<PaymentRecord> paymentRecord, byte[] encoded) {
        this.networkMagic = networkMagic;
        this.k = k;
        this.steps = steps;
        this.z0 = z0;
        this.zn = zn;
        this.vkSha256 = vkSha256;
        this.proofsDigest = proofsDigest;
        this.paymentRecord = paymentRecord;
        this.encoded = encoded;
    }

    public static NovaChainStatement parse(byte[] bytes) {
        if (bytes.length != CHAIN_STATEMENT_LENGTH && bytes.length != PAYMENT_STATEMENT_LENGTH) {
            throw new ProvenPaymentException(ProvenPaymentException.Reason.MALFORMED,
                    "Statement has " + bytes.length + " bytes, expected " + CHAIN_STATEMENT_LENGTH + " or " +
                            PAYMENT_STATEMENT_LENGTH);
        }
        ByteBuffer buffer = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);
        String magic = new String(take(buffer, 4), StandardCharsets.US_ASCII);
        long k = Integer.toUnsignedLong(buffer.getInt());
        long steps = Integer.toUnsignedLong(buffer.getInt());
        byte[] z0 = take(buffer, STATE_BYTES);
        byte[] zn = take(buffer, STATE_BYTES);
        checkCanonicalState(z0, "z0");
        checkCanonicalState(zn, "zn");
        byte[] vkSha256 = take(buffer, 32);
        byte[] proofsDigest = take(buffer, 32);
        Optional<PaymentRecord> paymentRecord = Optional.empty();
        if (buffer.hasRemaining()) {
            paymentRecord = Optional.of(PaymentRecord.parse(take(buffer, PAYMENT_RECORD_LENGTH)));
        }
        return new NovaChainStatement(magic, k, steps, z0, zn, vkSha256, proofsDigest, paymentRecord, bytes.clone());
    }

    public long getZ0Height() {
        return smallElement(z0, 0, 4, "z0 height");
    }

    public long getTipHeight() {
        return smallElement(zn, 0, 4, "tip height");
    }

    /**
     * Tip block hash in internal byte order: z[1] holds bytes 0..15, z[2] bytes 16..31.
     */
    public byte[] getTipHash() {
        return blockHash(zn);
    }

    public byte[] getZ0TipHash() {
        return blockHash(z0);
    }

    public BigInteger getTipChainwork() {
        return element(zn, 3);
    }

    public BigInteger getZ0Chainwork() {
        return element(z0, 3);
    }

    public byte[] getZ0() {
        return z0.clone();
    }

    public byte[] getZn() {
        return zn.clone();
    }

    public byte[] getVkSha256() {
        return vkSha256.clone();
    }

    public byte[] getProofsDigest() {
        return proofsDigest.clone();
    }

    public byte[] getEncoded() {
        return encoded.clone();
    }

    private static byte[] blockHash(byte[] state) {
        byte[] hash = new byte[32];
        for (int half = 0; half < 2; half++) {
            int at = (1 + half) * 32;
            for (int i = 16; i < 32; i++) {
                if (state[at + i] != 0) {
                    throw new ProvenPaymentException(ProvenPaymentException.Reason.MALFORMED,
                            "Block hash half exceeds 128 bits");
                }
            }
            System.arraycopy(state, at, hash, 16 * half, 16);
        }
        return hash;
    }

    static BigInteger element(byte[] state, int index) {
        byte[] le = Arrays.copyOfRange(state, index * 32, index * 32 + 32);
        byte[] be = new byte[32];
        for (int i = 0; i < 32; i++) {
            be[i] = le[31 - i];
        }
        return new BigInteger(1, be);
    }

    private static long smallElement(byte[] state, int index, int maxBytes, String name) {
        BigInteger value = element(state, index);
        if (value.bitLength() > 8 * maxBytes) {
            throw new ProvenPaymentException(ProvenPaymentException.Reason.MALFORMED, name + " exceeds " + 8 * maxBytes + " bits");
        }
        return value.longValueExact();
    }

    private static void checkCanonicalState(byte[] state, String name) {
        for (int i = 0; i < STATE_ELEMENTS; i++) {
            if (element(state, i).compareTo(PALLAS_SCALAR_MODULUS) >= 0) {
                throw new ProvenPaymentException(ProvenPaymentException.Reason.MALFORMED,
                        name + "[" + i + "] is not a canonical field element");
            }
        }
    }

    static byte[] take(ByteBuffer buffer, int length) {
        byte[] bytes = new byte[length];
        buffer.get(bytes);
        return bytes;
    }

    /**
     * The M16 payment record: transaction {@code txid} has output {@code vout} of {@code value} sats paying a script
     * with the given length and SHA-256, and is in block {@code blockHash} at {@code blockHeight}, which has
     * {@code confirmations} blocks up to and including the proven tip.
     */
    @Getter
    @EqualsAndHashCode
    public static final class PaymentRecord {
        public static final String MAGIC = "PAY1";

        private final long segments;
        private final long blockHeight;
        private final byte[] blockHash;
        private final long confirmations;
        private final byte[] txid;
        private final long vout;
        private final long valueSats;
        private final long scriptLength;
        private final byte[] scriptSha256;

        private PaymentRecord(long segments, long blockHeight, byte[] blockHash, long confirmations, byte[] txid,
                              long vout, long valueSats, long scriptLength, byte[] scriptSha256) {
            this.segments = segments;
            this.blockHeight = blockHeight;
            this.blockHash = blockHash;
            this.confirmations = confirmations;
            this.txid = txid;
            this.vout = vout;
            this.valueSats = valueSats;
            this.scriptLength = scriptLength;
            this.scriptSha256 = scriptSha256;
        }

        static PaymentRecord parse(byte[] bytes) {
            ByteBuffer buffer = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);
            String magic = new String(take(buffer, 4), StandardCharsets.US_ASCII);
            if (!MAGIC.equals(magic)) {
                throw new ProvenPaymentException(ProvenPaymentException.Reason.MALFORMED, "Payment record magic is not " + MAGIC);
            }
            long segments = Integer.toUnsignedLong(buffer.getInt());
            long blockHeight = Integer.toUnsignedLong(buffer.getInt());
            byte[] blockHash = take(buffer, 32);
            long confirmations = Integer.toUnsignedLong(buffer.getInt());
            byte[] txid = take(buffer, 32);
            long vout = Integer.toUnsignedLong(buffer.getInt());
            long value = buffer.getLong();
            if (value < 0) {
                throw new ProvenPaymentException(ProvenPaymentException.Reason.MALFORMED, "Output value out of range");
            }
            long scriptLength = Integer.toUnsignedLong(buffer.getInt());
            byte[] scriptSha256 = take(buffer, 32);
            return new PaymentRecord(segments, blockHeight, blockHash, confirmations, txid, vout, value, scriptLength, scriptSha256);
        }

        public byte[] getBlockHash() {
            return blockHash.clone();
        }

        public byte[] getTxid() {
            return txid.clone();
        }

        public byte[] getScriptSha256() {
            return scriptSha256.clone();
        }

        /**
         * The txid as block explorers and wallets show it (reversed byte order).
         */
        public String getTxidDisplayHex() {
            return Hex.reversed(txid);
        }

        public String getBlockHashDisplayHex() {
            return Hex.reversed(blockHash);
        }
    }
}
