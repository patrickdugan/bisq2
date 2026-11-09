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

import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class NovaChainStatementTest {
    private static final int ZN_AT = 12 + NovaChainStatement.STATE_BYTES;

    @Test
    void fixturesAreTheGuestOutputs() {
        assertThat(Hex.encode(ProvenPaymentValidator.sha256(Bitvm3TestFixtures.block170Statement())))
                .isEqualTo(Bitvm3TestFixtures.BLOCK170_STATEMENT_SHA256);
        assertThat(Hex.encode(ProvenPaymentValidator.sha256(Bitvm3TestFixtures.testnet4Statement())))
                .isEqualTo(Bitvm3TestFixtures.TESTNET4_STATEMENT_SHA256);
    }

    @Test
    void parsesBlock170PaymentStatement() {
        NovaChainStatement statement = NovaChainStatement.parse(Bitvm3TestFixtures.block170Statement());

        assertThat(statement.getNetworkMagic()).isEqualTo("NHC1");
        assertThat(statement.getK()).isEqualTo(1);
        assertThat(statement.getSteps()).isEqualTo(800);
        assertThat(statement.getZ0Height()).isZero();
        assertThat(Hex.reversed(statement.getZ0TipHash()))
                .isEqualTo("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f");
        assertThat(statement.getZ0Chainwork()).isEqualTo(BigInteger.valueOf(0x100010001L));
        assertThat(statement.getTipHeight()).isEqualTo(800);
        assertThat(Hex.reversed(statement.getTipHash()))
                .isEqualTo("00000000def8545899ea7274e5c59bda5982f8f960052774df45b7d5c64f9c5d");
        assertThat(statement.getTipChainwork()).isEqualTo(new BigInteger("3440321299233"));
        assertThat(Hex.encode(statement.getVkSha256()))
                .isEqualTo("6aa50d09397c51d0b89d78b3a918d3fe0962251225c8b6ca91e83199a4e6da1d");

        NovaChainStatement.PaymentRecord record = statement.getPaymentRecord().orElseThrow();
        assertThat(record.getSegments()).isEqualTo(2);
        assertThat(record.getBlockHeight()).isEqualTo(170);
        assertThat(record.getBlockHashDisplayHex())
                .isEqualTo("00000000d1145790a8694403d4063f323d499e655c83426834d4ce2f8dd4a2ee");
        assertThat(record.getConfirmations()).isEqualTo(631);
        assertThat(record.getTxidDisplayHex()).isEqualTo(Bitvm3TestFixtures.BLOCK170_TXID);
        assertThat(record.getVout()).isZero();
        assertThat(record.getValueSats()).isEqualTo(Bitvm3TestFixtures.BLOCK170_VALUE);
        assertThat(record.getScriptLength()).isEqualTo(67);
        assertThat(record.getScriptSha256()).isEqualTo(ProvenPaymentValidator.sha256(Bitvm3TestFixtures.BLOCK170_SCRIPT));
    }

    @Test
    void parsesTestnet4ChainStatementWithoutPaymentRecord() {
        NovaChainStatement statement = NovaChainStatement.parse(Bitvm3TestFixtures.testnet4Statement());

        assertThat(statement.getNetworkMagic()).isEqualTo("NHT4");
        assertThat(statement.getSteps()).isEqualTo(4);
        assertThat(statement.getTipHeight()).isEqualTo(4);
        assertThat(Hex.reversed(statement.getTipHash()))
                .isEqualTo("000000008f5794caa45c418a0184303e848e9d6756e4d77234c9aada983b4265");
        assertThat(statement.getPaymentRecord()).isEmpty();
    }

    @Test
    void rejectsOtherLengths() {
        byte[] statement = Bitvm3TestFixtures.block170Statement();
        assertMalformed(Arrays.copyOf(statement, statement.length - 1));
        assertMalformed(Arrays.copyOf(statement, statement.length + 1));
        assertMalformed(new byte[0]);
    }

    @Test
    void rejectsNonCanonicalFieldElement() {
        byte[] statement = Bitvm3TestFixtures.block170Statement();
        // z0[5] = 2^255 - 1 is above the Pallas scalar modulus.
        Arrays.fill(statement, 12 + 5 * 32, 12 + 6 * 32, (byte) 0xff);
        statement[12 + 6 * 32 - 1] = 0x7f;
        assertMalformed(statement);
    }

    @Test
    void rejectsPaymentRecordWithOtherMagic() {
        byte[] statement = Bitvm3TestFixtures.block170Statement();
        statement[NovaChainStatement.CHAIN_STATEMENT_LENGTH] = 'X';
        assertMalformed(statement);
    }

    @Test
    void rejectsTipHashHalfAbove128Bits() {
        byte[] statement = Bitvm3TestFixtures.block170Statement();
        statement[ZN_AT + 32 + 20] = 1;
        NovaChainStatement parsed = NovaChainStatement.parse(statement);
        assertThatThrownBy(parsed::getTipHash).isInstanceOf(ProvenPaymentException.class)
                .extracting("reason").isEqualTo(ProvenPaymentException.Reason.MALFORMED);
    }

    @Test
    void rejectsHeightAbove32Bits() {
        byte[] statement = Bitvm3TestFixtures.block170Statement();
        statement[ZN_AT + 4] = 1;
        NovaChainStatement parsed = NovaChainStatement.parse(statement);
        assertThatThrownBy(parsed::getTipHeight).isInstanceOf(ProvenPaymentException.class)
                .extracting("reason").isEqualTo(ProvenPaymentException.Reason.MALFORMED);
    }

    private static void assertMalformed(byte[] statement) {
        assertThatThrownBy(() -> NovaChainStatement.parse(statement)).isInstanceOf(ProvenPaymentException.class)
                .extracting("reason").isEqualTo(ProvenPaymentException.Reason.MALFORMED);
    }
}
