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

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;

import static bisq.trade.bitvm3.M13ProcessProofVerifierTest.GUEST_A_PROGRAM_VK_DIGEST;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Runs the real {@code m13-verify} on guest A's real final proof (nova-bitvm3/m13/fixtures/a-wrap-blake3-v2.bin,
 * 1,099,173 bytes, not copied into this repository). The test runs only when both are given:
 * <ul>
 *     <li>{@code BISQ_BITVM3_M13_VERIFY}: the command, arguments separated by {@code |}, for example
 *     {@code wsl.exe|-d|Ubuntu-24.04|-u|root|--|/root/nb3/m13/verify/target/release/m13-verify};</li>
 *     <li>{@code BISQ_BITVM3_GUEST_A_WRAP}: the path of {@code a-wrap-blake3-v2.bin};</li>
 *     <li>optional {@code BISQ_BITVM3_PATH_STYLE}: {@code NATIVE} (default) or {@code WSL}.</li>
 * </ul>
 */
class M13ProcessProofVerifierRealProofTest {
    private static M13ProcessProofVerifier verifier;
    private static byte[] proof;

    @BeforeAll
    static void setUp() throws IOException {
        String command = System.getenv("BISQ_BITVM3_M13_VERIFY");
        String wrap = System.getenv("BISQ_BITVM3_GUEST_A_WRAP");
        assumeTrue(command != null && !command.isBlank() && wrap != null && Files.isRegularFile(Path.of(wrap)),
                "m13-verify or the guest A wrap proof is not configured");
        String style = System.getenv().getOrDefault("BISQ_BITVM3_PATH_STYLE", "NATIVE");
        verifier = new M13ProcessProofVerifier(List.of(command.split("\\|")),
                M13ProcessProofVerifier.PathStyle.valueOf(style), Duration.ofSeconds(120));
        proof = Files.readAllBytes(Path.of(wrap));
    }

    @Test
    void acceptsGuestAProofOfTestnet4Statement() {
        assertThat(verifier.verify(Hex.decode(GUEST_A_PROGRAM_VK_DIGEST), Bitvm3TestFixtures.testnet4Statement(), proof))
                .isTrue();
    }

    @Test
    void provenTestnet4ChainPassesTheWholeChainPolicy() {
        ProvenPaymentValidator validator = new ProvenPaymentValidator(NovaNetworkPin.TESTNET4, BigInteger.ONE,
                List.of(Hex.decode(GUEST_A_PROGRAM_VK_DIGEST)));
        NovaChainStatement statement = NovaChainStatement.parse(Bitvm3TestFixtures.testnet4Statement());

        validator.validateChain(statement);
        validator.validateProgram(Hex.decode(GUEST_A_PROGRAM_VK_DIGEST));
        assertThat(verifier.verify(Hex.decode(GUEST_A_PROGRAM_VK_DIGEST), statement.getEncoded(), proof)).isTrue();
    }

    @Test
    void rejectsOtherStatement() {
        byte[] statement = Bitvm3TestFixtures.testnet4Statement();
        statement[12] ^= 1;
        assertThat(verifier.verify(Hex.decode(GUEST_A_PROGRAM_VK_DIGEST), statement, proof)).isFalse();
    }

    @Test
    void rejectsOtherProgram() {
        byte[] program = Hex.decode(GUEST_A_PROGRAM_VK_DIGEST);
        program[0] ^= 1;
        assertThat(verifier.verify(program, Bitvm3TestFixtures.testnet4Statement(), proof)).isFalse();
    }

    @Test
    void rejectsTamperedProof() {
        byte[] tampered = Arrays.copyOf(proof, proof.length);
        tampered[tampered.length / 2] ^= 1;
        assertThat(verifier.verify(Hex.decode(GUEST_A_PROGRAM_VK_DIGEST), Bitvm3TestFixtures.testnet4Statement(), tampered))
                .isFalse();
    }
}
