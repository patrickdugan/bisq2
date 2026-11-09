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

import java.util.HexFormat;

final class Hex {
    private static final HexFormat FORMAT = HexFormat.of();

    private Hex() {
    }

    static String encode(byte[] bytes) {
        return FORMAT.formatHex(bytes);
    }

    static byte[] decode(String hex) {
        return FORMAT.parseHex(hex);
    }

    static String reversed(byte[] bytes) {
        return encode(reverse(bytes));
    }

    static byte[] reverse(byte[] bytes) {
        byte[] out = new byte[bytes.length];
        for (int i = 0; i < bytes.length; i++) {
            out[i] = bytes[bytes.length - 1 - i];
        }
        return out;
    }
}
