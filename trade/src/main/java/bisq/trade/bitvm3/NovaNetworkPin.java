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

import java.util.Arrays;
import java.util.Optional;

/**
 * The pins of the nova-bitvm3 header chain per network, from nova-bitvm3/HANDOFF.md and the M16 guest
 * (garbled-snark-verifier commit d4aefcd). The verifier key digest is over the key's compressed encoding, the value the
 * statement commits; the raw-key digest is the one the M15/M16 guests check before decoding the same key. The genesis
 * state digest is SHA-256 over the 544 bytes of z0, taken from real guest output: the M16 block-170 statement for
 * mainnet and guest A's proven statement (d3b478b0...) for testnet4. z0 holds height 0, the genesis block hash and the
 * genesis block's work.
 */
public enum NovaNetworkPin {
    MAINNET("NHC1", 1,
            "6aa50d09397c51d0b89d78b3a918d3fe0962251225c8b6ca91e83199a4e6da1d",
            "4e815db864116def3aa6556d3ff9ff5540a48e6b1bd59f4a2f3c925cec937615",
            "b6eeaf96639fecb456f742df89c6fb02f54bf94f2484d42c92da21be978bf045"),
    TESTNET4("NHT4", 1,
            "6894f4903a9ff9713111bb1076b61663ac3592ad3d51b697d58125403fc5c12a",
            "63f91f1ec5c6b2d19185df0578311a5dfb8404441631c1ae515d07a8198dd20e",
            "9c82dffe8b6005378775c8f2028b7644039defadb0fcc1d77820b7aaced6de9c");

    private final String magic;
    private final long k;
    private final byte[] compressedVkSha256;
    private final byte[] rawVkSha256;
    private final byte[] genesisStateSha256;

    NovaNetworkPin(String magic, long k, String compressedVkSha256, String rawVkSha256, String genesisStateSha256) {
        this.magic = magic;
        this.k = k;
        this.compressedVkSha256 = Hex.decode(compressedVkSha256);
        this.rawVkSha256 = Hex.decode(rawVkSha256);
        this.genesisStateSha256 = Hex.decode(genesisStateSha256);
    }

    public static Optional<NovaNetworkPin> fromMagic(String magic) {
        return Arrays.stream(values()).filter(pin -> pin.magic.equals(magic)).findFirst();
    }

    public String getMagic() {
        return magic;
    }

    public long getK() {
        return k;
    }

    public byte[] getCompressedVkSha256() {
        return compressedVkSha256.clone();
    }

    public byte[] getRawVkSha256() {
        return rawVkSha256.clone();
    }

    public byte[] getGenesisStateSha256() {
        return genesisStateSha256.clone();
    }
}
