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

import bisq.trade.bitvm3.ProvenPaymentException.Reason;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;

/**
 * Checks a nova-bitvm3 statement against the pins of one network and against a trade's expected payment. The rules are
 * in docs/specifications/trade/bisq-easy-proven-btc-payment.md. This class checks the statement only. The proof of the
 * statement is checked by a {@link SnarkProofVerifier} (see {@link ProvenBtcConfirmationPolicy}).
 */
public final class ProvenPaymentValidator {
    private final NovaNetworkPin pin;
    private final BigInteger minTipChainwork;
    private final List<byte[]> trustedProgramVkDigests;

    public ProvenPaymentValidator(NovaNetworkPin pin, BigInteger minTipChainwork, List<byte[]> trustedProgramVkDigests) {
        this.pin = pin;
        this.minTipChainwork = minTipChainwork;
        this.trustedProgramVkDigests = trustedProgramVkDigests.stream().map(byte[]::clone).toList();
    }

    /**
     * Statement rules: the statement is a chain statement of the pinned network, anchored at its genesis state, with
     * a consistent height, and its tip is at least as heavy as the chainwork the node knows.
     */
    public void validateChain(NovaChainStatement statement) {
        if (!pin.getMagic().equals(statement.getNetworkMagic())) {
            throw new ProvenPaymentException(Reason.UNKNOWN_NETWORK,
                    "Statement network " + statement.getNetworkMagic() + " is not " + pin.getMagic());
        }
        if (statement.getK() != pin.getK()) {
            throw new ProvenPaymentException(Reason.WRONG_FOLD_WIDTH, "Fold width " + statement.getK() + " is not " + pin.getK());
        }
        if (!MessageDigest.isEqual(statement.getVkSha256(), pin.getCompressedVkSha256())) {
            throw new ProvenPaymentException(Reason.WRONG_VERIFIER_KEY, "Nova verifier key is not the pinned key");
        }
        if (!MessageDigest.isEqual(sha256(statement.getZ0()), pin.getGenesisStateSha256())) {
            throw new ProvenPaymentException(Reason.WRONG_GENESIS, "z0 is not the genesis state of " + pin.getMagic());
        }
        long z0Height = statement.getZ0Height();
        long tipHeight = statement.getTipHeight();
        if (tipHeight <= z0Height || tipHeight - z0Height != statement.getSteps() * statement.getK()) {
            throw new ProvenPaymentException(Reason.INCONSISTENT_CHAIN,
                    "Tip height " + tipHeight + " does not follow from z0 height " + z0Height + " and " +
                            statement.getSteps() + " steps of " + statement.getK() + " headers");
        }
        if (statement.getTipChainwork().compareTo(statement.getZ0Chainwork()) <= 0) {
            throw new ProvenPaymentException(Reason.INCONSISTENT_CHAIN, "Tip chainwork does not exceed the genesis chainwork");
        }
        if (statement.getTipChainwork().compareTo(minTipChainwork) < 0) {
            throw new ProvenPaymentException(Reason.CHAINWORK_TOO_LOW,
                    "Tip chainwork 0x" + statement.getTipChainwork().toString(16) + " is below the known minimum 0x" +
                            minTipChainwork.toString(16));
        }
    }

    /**
     * {@link #validateChain} plus the payment rules: the payment record is consistent with the proven tip and shows
     * the expected payment.
     */
    public NovaChainStatement.PaymentRecord validatePayment(NovaChainStatement statement, ExpectedPayment expected) {
        validateChain(statement);
        NovaChainStatement.PaymentRecord record = statement.getPaymentRecord()
                .orElseThrow(() -> new ProvenPaymentException(Reason.NO_PAYMENT_RECORD, "Statement has no payment record"));
        if (record.getSegments() < 1 || record.getConfirmations() < 1 ||
                record.getBlockHeight() + record.getConfirmations() - 1 != statement.getTipHeight()) {
            throw new ProvenPaymentException(Reason.INCONSISTENT_PAYMENT,
                    "Block height " + record.getBlockHeight() + " with " + record.getConfirmations() +
                            " confirmations does not end at tip height " + statement.getTipHeight());
        }
        if (expected.getTxidDisplayHex().isPresent() &&
                !expected.getTxidDisplayHex().get().equals(record.getTxidDisplayHex())) {
            throw new ProvenPaymentException(Reason.WRONG_TXID,
                    "Proven txid " + record.getTxidDisplayHex() + " is not " + expected.getTxidDisplayHex().get());
        }
        byte[] script = expected.getScriptPubKey();
        if (record.getScriptLength() != script.length || !MessageDigest.isEqual(record.getScriptSha256(), sha256(script))) {
            throw new ProvenPaymentException(Reason.WRONG_SCRIPT, "Proven output does not pay the expected script");
        }
        if (record.getValueSats() < expected.getMinValueSats()) {
            throw new ProvenPaymentException(Reason.VALUE_TOO_LOW,
                    "Proven value " + record.getValueSats() + " sats is below " + expected.getMinValueSats());
        }
        if (record.getConfirmations() < expected.getMinConfirmations()) {
            throw new ProvenPaymentException(Reason.TOO_FEW_CONFIRMATIONS,
                    record.getConfirmations() + " confirmations, " + expected.getMinConfirmations() + " required");
        }
        return record;
    }

    /**
     * The proof's program is one the node trusts.
     */
    public void validateProgram(byte[] programVkDigest) {
        boolean trusted = trustedProgramVkDigests.stream().anyMatch(d -> MessageDigest.isEqual(d, programVkDigest));
        if (!trusted) {
            throw new ProvenPaymentException(Reason.UNTRUSTED_PROGRAM,
                    "Program verifying key digest " + Hex.encode(programVkDigest) + " is not trusted");
        }
    }

    static byte[] sha256(byte[] bytes) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(bytes);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
