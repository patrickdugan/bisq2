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
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.List;
import java.util.Optional;
import java.util.function.Consumer;

import static bisq.trade.bitvm3.Bitvm3TestFixtures.BLOCK170_SCRIPT;
import static bisq.trade.bitvm3.Bitvm3TestFixtures.BLOCK170_TXID;
import static bisq.trade.bitvm3.Bitvm3TestFixtures.BLOCK170_VALUE;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ProvenPaymentValidatorTest {
    private static final BigInteger BLOCK800_CHAINWORK = new BigInteger("3440321299233");
    private static final byte[] PROGRAM = Hex.decode("11".repeat(32));

    private final ProvenPaymentValidator mainnet =
            new ProvenPaymentValidator(NovaNetworkPin.MAINNET, BLOCK800_CHAINWORK, List.of(PROGRAM));

    private static ExpectedPayment block170Payment() {
        return new ExpectedPayment(Optional.of(BLOCK170_TXID), BLOCK170_SCRIPT, BLOCK170_VALUE, 6);
    }

    @Test
    void acceptsBlock170Payment() {
        NovaChainStatement statement = NovaChainStatement.parse(Bitvm3TestFixtures.block170Statement());

        NovaChainStatement.PaymentRecord record = mainnet.validatePayment(statement, block170Payment());

        assertThat(record.getTxidDisplayHex()).isEqualTo(BLOCK170_TXID);
    }

    @Test
    void acceptsBlock170PaymentWithoutTxidAndWithUpperCaseTxid() {
        NovaChainStatement statement = NovaChainStatement.parse(Bitvm3TestFixtures.block170Statement());
        assertThatCode(() -> mainnet.validatePayment(statement,
                new ExpectedPayment(Optional.empty(), BLOCK170_SCRIPT, BLOCK170_VALUE, 631))).doesNotThrowAnyException();
        assertThatCode(() -> mainnet.validatePayment(statement,
                new ExpectedPayment(Optional.of(BLOCK170_TXID.toUpperCase()), BLOCK170_SCRIPT, 1, 1))).doesNotThrowAnyException();
    }

    @Test
    void acceptsTestnet4ChainStatementWithTestnet4Pin() {
        ProvenPaymentValidator testnet4 = new ProvenPaymentValidator(NovaNetworkPin.TESTNET4, BigInteger.ONE, List.of());
        NovaChainStatement statement = NovaChainStatement.parse(Bitvm3TestFixtures.testnet4Statement());

        assertThatCode(() -> testnet4.validateChain(statement)).doesNotThrowAnyException();
        assertRejected(Reason.NO_PAYMENT_RECORD, () -> testnet4.validatePayment(statement, block170Payment()));
        assertRejected(Reason.UNKNOWN_NETWORK, () -> mainnet.validateChain(statement));
    }

    @Test
    void rejectsMainnetStatementUnderTestnet4Pin() {
        ProvenPaymentValidator testnet4 = new ProvenPaymentValidator(NovaNetworkPin.TESTNET4, BigInteger.ONE, List.of());
        assertRejected(Reason.UNKNOWN_NETWORK,
                () -> testnet4.validateChain(NovaChainStatement.parse(Bitvm3TestFixtures.block170Statement())));
    }

    @Test
    void rejectsOtherFoldWidth() {
        assertMutationRejected(Reason.WRONG_FOLD_WIDTH, s -> s[4] = 2);
    }

    @Test
    void rejectsOtherVerifierKey() {
        assertMutationRejected(Reason.WRONG_VERIFIER_KEY, s -> s[12 + 2 * NovaChainStatement.STATE_BYTES] ^= 1);
    }

    @Test
    void rejectsOtherGenesisState() {
        // z0[5], the genesis time, changed by one second.
        assertMutationRejected(Reason.WRONG_GENESIS, s -> s[12 + 5 * 32] ^= 1);
    }

    @Test
    void rejectsStepsWhichDoNotMatchTipHeight() {
        assertMutationRejected(Reason.INCONSISTENT_CHAIN, s -> s[8] ^= 1);
    }

    @Test
    void rejectsTipBelowKnownChainwork() {
        ProvenPaymentValidator strict =
                new ProvenPaymentValidator(NovaNetworkPin.MAINNET, BLOCK800_CHAINWORK.add(BigInteger.ONE), List.of(PROGRAM));
        assertRejected(Reason.CHAINWORK_TOO_LOW, () -> strict.validatePayment(
                NovaChainStatement.parse(Bitvm3TestFixtures.block170Statement()), block170Payment()));
    }

    @Test
    void rejectsPaymentHeightWhichDoesNotEndAtTip() {
        assertMutationRejected(Reason.INCONSISTENT_PAYMENT, s -> s[NovaChainStatement.CHAIN_STATEMENT_LENGTH + 8] ^= 1);
        assertMutationRejected(Reason.INCONSISTENT_PAYMENT, s -> s[NovaChainStatement.CHAIN_STATEMENT_LENGTH + 44] ^= 1);
    }

    @Test
    void rejectsZeroSegments() {
        assertMutationRejected(Reason.INCONSISTENT_PAYMENT, s -> s[NovaChainStatement.CHAIN_STATEMENT_LENGTH + 4] = 0);
    }

    @Test
    void rejectsOtherTxid() {
        assertMutationRejected(Reason.WRONG_TXID, s -> s[NovaChainStatement.CHAIN_STATEMENT_LENGTH + 48] ^= 1);
    }

    @Test
    void rejectsOtherScript() {
        assertMutationRejected(Reason.WRONG_SCRIPT, s -> s[NovaChainStatement.CHAIN_STATEMENT_LENGTH + 96] ^= 1);
        assertMutationRejected(Reason.WRONG_SCRIPT, s -> s[NovaChainStatement.CHAIN_STATEMENT_LENGTH + 92] ^= 1);
    }

    @Test
    void rejectsValueBelowTradeAmount() {
        NovaChainStatement statement = NovaChainStatement.parse(Bitvm3TestFixtures.block170Statement());
        assertRejected(Reason.VALUE_TOO_LOW, () -> mainnet.validatePayment(statement,
                new ExpectedPayment(Optional.of(BLOCK170_TXID), BLOCK170_SCRIPT, BLOCK170_VALUE + 1, 1)));
    }

    @Test
    void rejectsTooFewConfirmations() {
        NovaChainStatement statement = NovaChainStatement.parse(Bitvm3TestFixtures.block170Statement());
        assertRejected(Reason.TOO_FEW_CONFIRMATIONS, () -> mainnet.validatePayment(statement,
                new ExpectedPayment(Optional.of(BLOCK170_TXID), BLOCK170_SCRIPT, BLOCK170_VALUE, 632)));
    }

    @Test
    void trustsOnlyConfiguredPrograms() {
        assertThatCode(() -> mainnet.validateProgram(PROGRAM)).doesNotThrowAnyException();
        assertRejected(Reason.UNTRUSTED_PROGRAM, () -> mainnet.validateProgram(Hex.decode("12".repeat(32))));
    }

    private void assertMutationRejected(Reason reason, Consumer<byte[]> mutation) {
        byte[] bytes = Bitvm3TestFixtures.block170Statement();
        mutation.accept(bytes);
        NovaChainStatement statement = NovaChainStatement.parse(bytes);
        assertRejected(reason, () -> mainnet.validatePayment(statement, block170Payment()));
    }

    private static void assertRejected(Reason reason, Runnable check) {
        assertThatThrownBy(check::run).isInstanceOf(ProvenPaymentException.class).extracting("reason").isEqualTo(reason);
    }
}
