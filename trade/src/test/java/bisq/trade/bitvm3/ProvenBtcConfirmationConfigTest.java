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

import com.typesafe.config.ConfigFactory;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ProvenBtcConfirmationConfigTest {
    @Test
    void missingBlockIsDisabled() {
        ProvenBtcConfirmationPolicy.Config config =
                ProvenBtcConfirmationPolicy.Config.from(ConfigFactory.parseString("muSig={}"));
        assertThat(config.isEnabled()).isFalse();
    }

    @Test
    void readsAllFields() {
        ProvenBtcConfirmationPolicy.Config config = ProvenBtcConfirmationPolicy.Config.from(ConfigFactory.parseString("""
                bisqEasy.provenBtcConfirmation {
                    enabled = true
                    network = TESTNET4
                    minConfirmations = 3
                    minTipChainworkHex = "500050005"
                    trustedProgramVkDigests = ["%s"]
                }
                """.formatted("ab".repeat(32))));

        assertThat(config.isEnabled()).isTrue();
        assertThat(config.getNetwork()).isEqualTo(NovaNetworkPin.TESTNET4);
        assertThat(config.getMinConfirmations()).isEqualTo(3);
        assertThat(config.getMinTipChainwork()).isEqualTo(new BigInteger("500050005", 16));
        assertThat(config.getTrustedProgramVkDigests()).hasSize(1);
        assertThat(config.getTrustedProgramVkDigests().get(0)).isEqualTo(Hex.decode("ab".repeat(32)));
    }

    @Test
    void disabledPolicyRefusesEveryProof() {
        assertThatThrownBy(() -> ProvenBtcConfirmationPolicy.disabled().verify("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
                Optional.empty(), 1, Bitvm3TestFixtures.block170Statement(), new byte[32], new byte[0]))
                .isInstanceOf(ProvenPaymentException.class)
                .extracting("reason").isEqualTo(ProvenPaymentException.Reason.DISABLED);
    }
}
