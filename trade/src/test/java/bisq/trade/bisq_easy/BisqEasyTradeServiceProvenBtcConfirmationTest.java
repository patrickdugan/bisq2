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

package bisq.trade.bisq_easy;

import bisq.account.payment_method.BitcoinPaymentMethod;
import bisq.account.payment_method.BitcoinPaymentMethodSpec;
import bisq.account.payment_method.BitcoinPaymentRail;
import bisq.bonded_roles.release.AppType;
import bisq.common.network.Address;
import bisq.common.network.AddressByTransportTypeMap;
import bisq.contract.bisq_easy.BisqEasyContract;
import bisq.identity.Identity;
import bisq.network.identity.NetworkId;
import bisq.offer.bisq_easy.BisqEasyOffer;
import bisq.security.keys.KeyGeneration;
import bisq.security.keys.PubKey;
import bisq.trade.ServiceProvider;
import bisq.trade.TradeActionNotAppliedException;
import bisq.trade.bitvm3.BitcoinAddressScript;
import bisq.trade.bitvm3.Bitvm3TestFixtures;
import bisq.trade.bitvm3.NovaChainStatement;
import bisq.trade.bitvm3.NovaNetworkPin;
import bisq.trade.bitvm3.ProvenBtcConfirmationPolicy;
import bisq.trade.bitvm3.ProvenPaymentException;
import bisq.trade.bitvm3.SnarkProofVerifier;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Rules 15 and 16 of docs/specifications/trade/bisq-easy-proven-btc-payment.md. No protocol is registered for the trade,
 * so an applied BTC confirmation only reaches handleBisqEasyTradeEvent; the tests check the decision before it.
 */
class BisqEasyTradeServiceProvenBtcConfirmationTest {
    private static final String BUYER_ADDRESS = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
    private static final byte[] PROGRAM = HexFormat.of().parseHex("22".repeat(32));
    private static final byte[] PROOF = {1, 2, 3};

    private final List<byte[]> verifiedStatements = new ArrayList<>();
    private BisqEasyTradeService service;

    @AfterEach
    void tearDown() {
        if (service != null) {
            service.shutdown().join();
        }
    }

    @Test
    void disabledKeepsPlainConfirmationAndRefusesProof() {
        service = service(false, true);
        BisqEasyTrade trade = trade(true, BitcoinPaymentRail.MAIN_CHAIN);

        assertThatCode(() -> service.btcConfirmed(trade)).doesNotThrowAnyException();
        assertThatThrownBy(() -> service.buyerConfirmBtcReceivedWithProof(trade, statement(), PROGRAM, PROOF))
                .isInstanceOf(TradeActionNotAppliedException.class);
    }

    @Test
    void enabledBuyerOfMainChainTradeNeedsProof() {
        service = service(true, true);
        BisqEasyTrade trade = trade(true, BitcoinPaymentRail.MAIN_CHAIN);

        assertThatThrownBy(() -> service.btcConfirmed(trade)).isInstanceOf(TradeActionNotAppliedException.class);

        NovaChainStatement.PaymentRecord record =
                service.buyerConfirmBtcReceivedWithProof(trade, statement(), PROGRAM, PROOF);
        assertThat(record.getTxidDisplayHex()).isEqualTo(Bitvm3TestFixtures.BLOCK170_TXID);
        assertThat(verifiedStatements).containsExactly(statement());
    }

    @Test
    void enabledRejectsProofWhichSnarkVerifierRejects() {
        service = service(true, false);
        BisqEasyTrade trade = trade(true, BitcoinPaymentRail.MAIN_CHAIN);

        assertThatThrownBy(() -> service.buyerConfirmBtcReceivedWithProof(trade, statement(), PROGRAM, PROOF))
                .isInstanceOf(ProvenPaymentException.class)
                .extracting("reason").isEqualTo(ProvenPaymentException.Reason.PROOF_REJECTED);
    }

    @Test
    void enabledRejectsPaymentToAnotherAddressBeforeCheckingTheProof() {
        service = service(true, true);
        BisqEasyTrade trade = trade(true, BitcoinPaymentRail.MAIN_CHAIN);
        trade.setBitcoinPaymentData(Optional.of("31h38a54tFMrR8kzBnP2241MFD2EUHtGha"));

        assertThatThrownBy(() -> service.buyerConfirmBtcReceivedWithProof(trade, statement(), PROGRAM, PROOF))
                .isInstanceOf(ProvenPaymentException.class)
                .extracting("reason").isEqualTo(ProvenPaymentException.Reason.WRONG_SCRIPT);
        assertThat(verifiedStatements).isEmpty();
    }

    @Test
    void enabledRejectsOtherTxidThanSellerReported() {
        service = service(true, true);
        BisqEasyTrade trade = trade(true, BitcoinPaymentRail.MAIN_CHAIN);
        trade.setPaymentProof(Optional.of("00".repeat(32)));

        assertThatThrownBy(() -> service.buyerConfirmBtcReceivedWithProof(trade, statement(), PROGRAM, PROOF))
                .isInstanceOf(ProvenPaymentException.class)
                .extracting("reason").isEqualTo(ProvenPaymentException.Reason.WRONG_TXID);
    }

    @Test
    void enabledKeepsPlainConfirmationForSellerAndLightning() {
        service = service(true, true);

        assertThatCode(() -> service.btcConfirmed(trade(false, BitcoinPaymentRail.MAIN_CHAIN))).doesNotThrowAnyException();
        assertThatCode(() -> service.btcConfirmed(trade(true, BitcoinPaymentRail.LN))).doesNotThrowAnyException();
        assertThatThrownBy(() -> service.buyerConfirmBtcReceivedWithProof(trade(true, BitcoinPaymentRail.LN),
                statement(), PROGRAM, PROOF)).isInstanceOf(TradeActionNotAppliedException.class);
    }

    private BisqEasyTradeService service(boolean enabled, boolean snarkAccepts) {
        ProvenBtcConfirmationPolicy.Config config = new ProvenBtcConfirmationPolicy.Config(enabled, NovaNetworkPin.MAINNET,
                6, BigInteger.ONE, List.of(PROGRAM));
        SnarkProofVerifier verifier = (programVkDigest, publicValues, proof) -> {
            verifiedStatements.add(publicValues);
            return snarkAccepts;
        };
        return new BisqEasyTradeService(mock(ServiceProvider.class, RETURNS_DEEP_STUBS), AppType.DESKTOP,
                new BisqEasyProtocolRegistry(), new ProvenBtcConfirmationPolicy(config, verifier));
    }

    private static byte[] statement() {
        return Bitvm3TestFixtures.block170StatementPaying(BitcoinAddressScript.scriptPubKey(BUYER_ADDRESS, NovaNetworkPin.MAINNET));
    }

    private static BisqEasyTrade trade(boolean isBuyer, BitcoinPaymentRail rail) {
        BisqEasyContract contract = mock(BisqEasyContract.class);
        when(contract.getTakeOfferDate()).thenReturn(0L);
        when(contract.getBaseSideAmount()).thenReturn(Bitvm3TestFixtures.BLOCK170_VALUE);
        when(contract.getBaseSidePaymentMethodSpec())
                .thenReturn(new BitcoinPaymentMethodSpec(BitcoinPaymentMethod.fromPaymentRail(rail)));
        BisqEasyOffer offer = mock(BisqEasyOffer.class);
        when(offer.getId()).thenReturn("offerId");
        BisqEasyTrade trade = new BisqEasyTrade(contract, isBuyer, true, mock(Identity.class), offer,
                networkId("me", 1001), networkId("peer", 1002));
        trade.setBitcoinPaymentData(Optional.of("bitcoin:" + BUYER_ADDRESS));
        trade.setPaymentProof(Optional.of(Bitvm3TestFixtures.BLOCK170_TXID));
        return trade;
    }

    private static NetworkId networkId(String keyId, int port) {
        Address address = Address.from("127.0.0.1", port);
        return new NetworkId(new AddressByTransportTypeMap(Map.of(address.getTransportType(), address)),
                new PubKey(KeyGeneration.generateDefaultEcKeyPair().getPublic(), keyId));
    }
}
