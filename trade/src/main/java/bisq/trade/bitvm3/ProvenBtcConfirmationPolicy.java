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
import lombok.Getter;
import lombok.ToString;

import java.math.BigInteger;
import java.time.Duration;
import java.util.List;
import java.util.Optional;

/**
 * The feature flag and the decision of the buyer's node in a Bisq Easy main-chain trade: the node marks the BTC as
 * received only with a statement of the M16 guest which shows the trade's payment, and a proof of that statement.
 * See docs/specifications/trade/bisq-easy-proven-btc-payment.md.
 */
@ToString
public final class ProvenBtcConfirmationPolicy {
    @Getter
    @ToString
    public static final class Config {
        public static final String PATH = "bisqEasy.provenBtcConfirmation";

        private final boolean enabled;
        private final NovaNetworkPin network;
        private final long minConfirmations;
        private final BigInteger minTipChainwork;
        private final List<byte[]> trustedProgramVkDigests;
        // m13-verify command and leading arguments; empty means no SNARK verifier, so every proof is rejected.
        private final List<String> m13VerifyCommand;
        private final M13ProcessProofVerifier.PathStyle m13VerifyPathStyle;
        private final Duration m13VerifyTimeout;

        public Config(boolean enabled,
                      NovaNetworkPin network,
                      long minConfirmations,
                      BigInteger minTipChainwork,
                      List<byte[]> trustedProgramVkDigests) {
            this(enabled, network, minConfirmations, minTipChainwork, trustedProgramVkDigests, List.of(),
                    M13ProcessProofVerifier.PathStyle.NATIVE, Duration.ofSeconds(120));
        }

        public Config(boolean enabled,
                      NovaNetworkPin network,
                      long minConfirmations,
                      BigInteger minTipChainwork,
                      List<byte[]> trustedProgramVkDigests,
                      List<String> m13VerifyCommand,
                      M13ProcessProofVerifier.PathStyle m13VerifyPathStyle,
                      Duration m13VerifyTimeout) {
            if (minConfirmations < 1) {
                throw new IllegalArgumentException("minConfirmations must be at least 1");
            }
            this.enabled = enabled;
            this.network = network;
            this.minConfirmations = minConfirmations;
            this.minTipChainwork = minTipChainwork;
            this.trustedProgramVkDigests = trustedProgramVkDigests.stream().map(byte[]::clone).toList();
            this.m13VerifyCommand = List.copyOf(m13VerifyCommand);
            this.m13VerifyPathStyle = m13VerifyPathStyle;
            this.m13VerifyTimeout = m13VerifyTimeout;
        }

        /**
         * The configured {@link M13ProcessProofVerifier}, or {@link SnarkProofVerifier#REJECT_ALL} without a command.
         */
        public SnarkProofVerifier createProofVerifier() {
            if (m13VerifyCommand.isEmpty()) {
                return SnarkProofVerifier.REJECT_ALL;
            }
            return new M13ProcessProofVerifier(m13VerifyCommand, m13VerifyPathStyle, m13VerifyTimeout);
        }

        public static Config disabled() {
            return new Config(false, NovaNetworkPin.MAINNET, 1, BigInteger.ZERO, List.of());
        }

        /**
         * Reads {@value #PATH} from the trade config. A missing block or a missing {@code enabled} means disabled.
         */
        public static Config from(com.typesafe.config.Config tradeConfig) {
            if (!tradeConfig.hasPath(PATH)) {
                return disabled();
            }
            com.typesafe.config.Config c = tradeConfig.getConfig(PATH);
            boolean enabled = c.hasPath("enabled") && c.getBoolean("enabled");
            NovaNetworkPin network = c.hasPath("network")
                    ? NovaNetworkPin.valueOf(c.getString("network"))
                    : NovaNetworkPin.MAINNET;
            long minConfirmations = c.hasPath("minConfirmations") ? c.getLong("minConfirmations") : 1;
            BigInteger minTipChainwork = c.hasPath("minTipChainworkHex")
                    ? new BigInteger(c.getString("minTipChainworkHex"), 16)
                    : BigInteger.ZERO;
            List<byte[]> digests = c.hasPath("trustedProgramVkDigests")
                    ? c.getStringList("trustedProgramVkDigests").stream().map(Hex::decode).toList()
                    : List.of();
            List<String> m13VerifyCommand = c.hasPath("m13Verify.command")
                    ? c.getStringList("m13Verify.command")
                    : List.of();
            M13ProcessProofVerifier.PathStyle pathStyle = c.hasPath("m13Verify.pathStyle")
                    ? M13ProcessProofVerifier.PathStyle.valueOf(c.getString("m13Verify.pathStyle"))
                    : M13ProcessProofVerifier.PathStyle.NATIVE;
            Duration timeout = c.hasPath("m13Verify.timeoutSeconds")
                    ? Duration.ofSeconds(c.getLong("m13Verify.timeoutSeconds"))
                    : Duration.ofSeconds(120);
            return new Config(enabled, network, minConfirmations, minTipChainwork, digests, m13VerifyCommand,
                    pathStyle, timeout);
        }
    }

    @Getter
    private final Config config;
    private final ProvenPaymentValidator validator;
    private final SnarkProofVerifier proofVerifier;

    public ProvenBtcConfirmationPolicy(Config config, SnarkProofVerifier proofVerifier) {
        this.config = config;
        this.validator = new ProvenPaymentValidator(config.getNetwork(), config.getMinTipChainwork(),
                config.getTrustedProgramVkDigests());
        this.proofVerifier = proofVerifier;
    }

    public static ProvenBtcConfirmationPolicy disabled() {
        return new ProvenBtcConfirmationPolicy(Config.disabled(), SnarkProofVerifier.REJECT_ALL);
    }

    public boolean isEnabled() {
        return config.isEnabled();
    }

    /**
     * @param bitcoinPaymentData the buyer's address or bitcoin URI, as sent to the seller
     * @param paymentProof       the txid the seller reported, if any
     * @param tradeAmountSats    the contract's base side amount
     * @param statement          the public values of the M16 guest (1,292 bytes)
     * @param programVkDigest    the SP1 program verifying key digest of the proof
     * @param proof              the SP1 wrap proof
     * @return the proven payment record
     * @throws ProvenPaymentException if any rule fails; the SNARK is checked last because it is the costliest check
     */
    public NovaChainStatement.PaymentRecord verify(String bitcoinPaymentData,
                                                   Optional<String> paymentProof,
                                                   long tradeAmountSats,
                                                   byte[] statement,
                                                   byte[] programVkDigest,
                                                   byte[] proof) {
        if (!isEnabled()) {
            throw new ProvenPaymentException(Reason.DISABLED, "Proven BTC confirmation is disabled");
        }
        NovaChainStatement parsed = NovaChainStatement.parse(statement);
        byte[] script = BitcoinAddressScript.scriptPubKey(bitcoinPaymentData, config.getNetwork());
        ExpectedPayment expected = new ExpectedPayment(paymentProof.filter(s -> !s.isBlank()), script,
                tradeAmountSats, config.getMinConfirmations());
        NovaChainStatement.PaymentRecord record = validator.validatePayment(parsed, expected);
        validator.validateProgram(programVkDigest);
        if (!proofVerifier.verify(programVkDigest.clone(), parsed.getEncoded(), proof.clone())) {
            throw new ProvenPaymentException(Reason.PROOF_REJECTED, "The SNARK verifier rejected the proof");
        }
        return record;
    }
}
