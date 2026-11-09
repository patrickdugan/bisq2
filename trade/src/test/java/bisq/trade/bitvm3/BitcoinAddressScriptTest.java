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

import static bisq.trade.bitvm3.NovaNetworkPin.MAINNET;
import static bisq.trade.bitvm3.NovaNetworkPin.TESTNET4;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class BitcoinAddressScriptTest {
    private static final String GENESIS_P2PKH = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
    private static final String GENESIS_P2PKH_SCRIPT = "76a91462e907b15cbf27d5425399ebf6f0fb50ebb88f1888ac";

    @Test
    void p2pkh() {
        assertScript(GENESIS_P2PKH, MAINNET, GENESIS_P2PKH_SCRIPT);
        // Version 0x6f, hash 00 01 .. 13.
        assertScript("mfWyW5fc9NUj75YAnFgoRLrjxgLDn2MMth", TESTNET4, "76a914000102030405060708090a0b0c0d0e0f1011121388ac");
    }

    @Test
    void p2sh() {
        // Version 0x05, hash 00 01 .. 13.
        assertScript("31h38a54tFMrR8kzBnP2241MFD2EUHtGha", MAINNET, "a914000102030405060708090a0b0c0d0e0f1011121387");
    }

    @Test
    void segwitVersion0() {
        // BIP 173 test vectors.
        assertScript("BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4", MAINNET,
                "0014751e76e8199196d454941c45d1b3a323f1433bd6");
        assertScript("tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7", TESTNET4,
                "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262");
    }

    @Test
    void segwitVersion1() {
        // BIP 350 test vector: the x coordinate of the secp256k1 generator as taproot output key.
        assertScript("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0", MAINNET,
                "512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
    }

    @Test
    void readsAddressOfBitcoinUri() {
        assertScript("bitcoin:" + GENESIS_P2PKH + "?amount=0.001", MAINNET, GENESIS_P2PKH_SCRIPT);
        assertScript("BITCOIN:" + GENESIS_P2PKH, MAINNET, GENESIS_P2PKH_SCRIPT);
    }

    @Test
    void rejectsBadChecksums() {
        assertInvalid("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb", MAINNET);
        assertInvalid("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj1", MAINNET);
    }

    @Test
    void rejectsAddressOfOtherNetwork() {
        assertInvalid(GENESIS_P2PKH, TESTNET4);
        assertInvalid("tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7", MAINNET);
    }

    @Test
    void rejectsMixedCaseBech32() {
        assertInvalid("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jJ0", MAINNET);
    }

    private static void assertScript(String address, NovaNetworkPin network, String scriptHex) {
        assertThat(Hex.encode(BitcoinAddressScript.scriptPubKey(address, network))).isEqualTo(scriptHex);
    }

    private static void assertInvalid(String address, NovaNetworkPin network) {
        assertThatThrownBy(() -> BitcoinAddressScript.scriptPubKey(address, network))
                .isInstanceOf(ProvenPaymentException.class)
                .extracting("reason").isEqualTo(ProvenPaymentException.Reason.WRONG_SCRIPT);
    }
}
