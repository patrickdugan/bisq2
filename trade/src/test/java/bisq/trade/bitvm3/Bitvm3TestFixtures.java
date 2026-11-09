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

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

/**
 * Real outputs of the nova-bitvm3 guests (garbled-snark-verifier commit d4aefcd), hex encoded:
 * <ul>
 *     <li>{@code m16-block170-statement.hex}: the M16 guest's 1,292-byte statement for the block-170 test (mainnet
 *     headers 0 to 800 in two segments, payment f4184fc5... output 0, 10 BTC, 631 confirmations). Executed, not
 *     proved; SHA-256 67a9deb9...5c71, as in nova-bitvm3/m16/README.md.</li>
 *     <li>{@code guest-a-testnet4-statement.hex}: guest A's 1,164-byte proven testnet4 statement (headers 0 to 4),
 *     cut from the public values of m13/fixtures/a-compressed.bin; SHA-256 d3b478b0...2fa0, the value pinned in
 *     m13/pins.json.</li>
 * </ul>
 */
public final class Bitvm3TestFixtures {
    public static final String BLOCK170_STATEMENT_SHA256 = "67a9deb95cb04d9d7fa7615d9aba45a2a0c95256a5d8e853191706c8b9a25c71";
    public static final String TESTNET4_STATEMENT_SHA256 = "d3b478b0ed0055bbd43a59775729c990a33d1df07bd0a66ee728a3573c832fa0";
    public static final String BLOCK170_TXID = "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16";
    // Output 0 of the block-170 transaction: pay-to-pubkey of an uncompressed key.
    public static final byte[] BLOCK170_SCRIPT = HexFormat.of().parseHex(
            "4104ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0" +
                    "626f1baded5c72a704f7e6cd84cac");
    public static final long BLOCK170_VALUE = 1_000_000_000L;

    private Bitvm3TestFixtures() {
    }

    public static byte[] block170Statement() {
        return read("m16-block170-statement.hex");
    }

    public static byte[] testnet4Statement() {
        return read("guest-a-testnet4-statement.hex");
    }

    /**
     * The block-170 statement with the payment record's script length and script hash replaced. A P2PK script has no
     * address, so the trade hook tests use this variant. It is not a guest output.
     */
    public static byte[] block170StatementPaying(byte[] script) {
        byte[] statement = block170Statement();
        int at = NovaChainStatement.CHAIN_STATEMENT_LENGTH + 92;
        statement[at] = (byte) script.length;
        statement[at + 1] = 0;
        statement[at + 2] = 0;
        statement[at + 3] = 0;
        System.arraycopy(ProvenPaymentValidator.sha256(script), 0, statement, at + 4, 32);
        return statement;
    }

    private static byte[] read(String name) {
        try (InputStream in = Bitvm3TestFixtures.class.getResourceAsStream("/bisq/trade/bitvm3/" + name)) {
            if (in == null) {
                throw new IllegalStateException("Missing fixture " + name);
            }
            return HexFormat.of().parseHex(new String(in.readAllBytes(), StandardCharsets.US_ASCII).trim());
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
