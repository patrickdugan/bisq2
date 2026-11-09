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

import java.time.Duration;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class M13ProcessProofVerifierTest {
    static final String GUEST_A_PROGRAM_VK_DIGEST = "5df3760fed1620671151183a73c9407d528b2239a5cd243b14cf5c7b4d4af46b";

    @Test
    void expectedStatementMatchesGuestAStatementOfM13() {
        // nova-bitvm3/m13/fixtures/a-statement.json, field by field.
        String json = M13ProcessProofVerifier.expectedStatementJson(Hex.decode(GUEST_A_PROGRAM_VK_DIGEST),
                Hex.encode(ProvenPaymentValidator.sha256(Bitvm3TestFixtures.testnet4Statement())));

        assertThat(json)
                .contains("\"committed_values_sha256\": \"" + Bitvm3TestFixtures.TESTNET4_STATEMENT_SHA256 + "\"")
                .contains("\"exit_code\": 0")
                .contains("\"is_complete\": 1")
                .contains("\"program_vk_digest\": \"" + GUEST_A_PROGRAM_VK_DIGEST + "\"")
                .contains("\"recursion_vk_root\": \"7487c2175bd3256619ca0118094b8150d6df0246a1b41979a081642e5253f257\"")
                .contains("\"wrap_vk_sha256\": \"d42c63e3c873b35576b4c95fa8c41770a8c6b8a9f16ba74732c5b52a43b0b0d7\"");
    }

    @Test
    void convertsWindowsPathsForWsl() {
        assertThat(M13ProcessProofVerifier.toWslPath("C:\\Users\\x\\wrap.bin")).isEqualTo("/mnt/c/Users/x/wrap.bin");
        assertThat(M13ProcessProofVerifier.toWslPath("D:\\t")).isEqualTo("/mnt/d/t");
    }

    @Test
    void outputMustReportVerifiedForTheStatement() {
        String digest = "ab".repeat(32);
        assertThat(M13ProcessProofVerifier.isVerifiedOutput(
                "{\n  \"status\": \"verified\",\n  \"statement\": {\"committed_values_sha256\": \"" + digest + "\"}}", digest)).isTrue();
        assertThat(M13ProcessProofVerifier.isVerifiedOutput("{\"status\": \"verified\"}", digest)).isFalse();
        assertThat(M13ProcessProofVerifier.isVerifiedOutput("Error: refused: different committed statement " + digest, digest)).isFalse();
        assertThat(M13ProcessProofVerifier.isVerifiedOutput("", digest)).isFalse();
    }

    @Test
    void missingBinaryRejects() {
        M13ProcessProofVerifier verifier = new M13ProcessProofVerifier(List.of("bisq-no-such-m13-verify-binary"),
                M13ProcessProofVerifier.PathStyle.NATIVE, Duration.ofSeconds(5));

        assertThat(verifier.verify(new byte[32], Bitvm3TestFixtures.testnet4Statement(), new byte[]{1})).isFalse();
    }

    @Test
    void malformedInputRejectsWithoutRunningTheVerifier() {
        M13ProcessProofVerifier verifier = new M13ProcessProofVerifier(List.of("bisq-no-such-m13-verify-binary"),
                M13ProcessProofVerifier.PathStyle.NATIVE, Duration.ofSeconds(5));

        assertThat(verifier.verify(new byte[31], new byte[0], new byte[]{1})).isFalse();
        assertThat(verifier.verify(new byte[32], new byte[0], new byte[0])).isFalse();
        assertThat(verifier.verify(new byte[32], new byte[0], new byte[M13ProcessProofVerifier.MAX_PROOF_BYTES + 1])).isFalse();
    }

    @Test
    void configCreatesProcessVerifierOnlyWithCommand() {
        ProvenBtcConfirmationPolicy.Config without = ProvenBtcConfirmationPolicy.Config.from(ConfigFactory.parseString(
                "bisqEasy.provenBtcConfirmation.enabled = true"));
        assertThat(without.createProofVerifier()).isSameAs(SnarkProofVerifier.REJECT_ALL);

        ProvenBtcConfirmationPolicy.Config with = ProvenBtcConfirmationPolicy.Config.from(ConfigFactory.parseString("""
                bisqEasy.provenBtcConfirmation {
                    enabled = true
                    m13Verify {
                        command = ["wsl.exe", "-d", "Ubuntu-24.04", "--", "/root/m13-verify"]
                        pathStyle = WSL
                        timeoutSeconds = 30
                    }
                }
                """));
        assertThat(with.getM13VerifyCommand()).containsExactly("wsl.exe", "-d", "Ubuntu-24.04", "--", "/root/m13-verify");
        assertThat(with.getM13VerifyPathStyle()).isEqualTo(M13ProcessProofVerifier.PathStyle.WSL);
        assertThat(with.getM13VerifyTimeout()).isEqualTo(Duration.ofSeconds(30));
        assertThat(with.createProofVerifier()).isInstanceOf(M13ProcessProofVerifier.class);
    }
}
