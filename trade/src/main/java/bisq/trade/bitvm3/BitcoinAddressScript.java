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

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Locale;

/**
 * Converts a Bitcoin address, or the address of a BIP 21 bitcoin URI, to the scriptPubKey it pays: P2PKH and P2SH
 * (base58check), and segwit version 0 (BIP 173, bech32) and versions 1 to 16 (BIP 350, bech32m). The payment record
 * commits SHA-256 of the scriptPubKey, so the buyer's address must be turned into the script to compare it.
 */
public final class BitcoinAddressScript {
    private static final String BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    private static final String BECH32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    private static final int BECH32_CONST = 1;
    private static final int BECH32M_CONST = 0x2bc830a3;

    private BitcoinAddressScript() {
    }

    public static byte[] scriptPubKey(String paymentData, NovaNetworkPin network) {
        String address = stripBitcoinUri(paymentData.trim());
        String lower = address.toLowerCase(Locale.ROOT);
        String hrp = network == NovaNetworkPin.MAINNET ? "bc" : "tb";
        if (lower.startsWith(hrp + "1")) {
            return segwitScript(address, hrp);
        }
        return base58Script(address, network);
    }

    private static String stripBitcoinUri(String data) {
        if (data.regionMatches(true, 0, "bitcoin:", 0, 8)) {
            String rest = data.substring(8);
            int query = rest.indexOf('?');
            return query < 0 ? rest : rest.substring(0, query);
        }
        return data;
    }

    private static byte[] base58Script(String address, NovaNetworkPin network) {
        byte[] decoded = base58Decode(address);
        if (decoded.length != 25) {
            throw invalid("base58 address has " + decoded.length + " bytes");
        }
        byte[] payload = Arrays.copyOfRange(decoded, 0, 21);
        byte[] checksum = Arrays.copyOfRange(ProvenPaymentValidator.sha256(ProvenPaymentValidator.sha256(payload)), 0, 4);
        if (!MessageDigest.isEqual(checksum, Arrays.copyOfRange(decoded, 21, 25))) {
            throw invalid("base58 checksum");
        }
        byte[] hash = Arrays.copyOfRange(payload, 1, 21);
        int version = payload[0] & 0xff;
        boolean mainnet = network == NovaNetworkPin.MAINNET;
        if (version == (mainnet ? 0x00 : 0x6f)) {
            return concat(new byte[]{0x76, (byte) 0xa9, 0x14}, hash, new byte[]{(byte) 0x88, (byte) 0xac});
        }
        if (version == (mainnet ? 0x05 : 0xc4)) {
            return concat(new byte[]{(byte) 0xa9, 0x14}, hash, new byte[]{(byte) 0x87});
        }
        throw invalid("base58 version " + version + " is not a P2PKH or P2SH address of " + network);
    }

    private static byte[] base58Decode(String s) {
        BigInteger value = BigInteger.ZERO;
        int leadingZeros = 0;
        boolean leading = true;
        for (char c : s.toCharArray()) {
            int digit = BASE58.indexOf(c);
            if (digit < 0) {
                throw invalid("character '" + c + "' is not base58");
            }
            if (leading && digit == 0) {
                leadingZeros++;
            } else {
                leading = false;
            }
            value = value.multiply(BigInteger.valueOf(58)).add(BigInteger.valueOf(digit));
        }
        byte[] bytes = value.equals(BigInteger.ZERO) ? new byte[0] : value.toByteArray();
        if (bytes.length > 0 && bytes[0] == 0) {
            bytes = Arrays.copyOfRange(bytes, 1, bytes.length);
        }
        return concat(new byte[leadingZeros], bytes);
    }

    private static byte[] segwitScript(String address, String hrp) {
        if (!address.equals(address.toLowerCase(Locale.ROOT)) && !address.equals(address.toUpperCase(Locale.ROOT))) {
            throw invalid("bech32 address has mixed case");
        }
        String lower = address.toLowerCase(Locale.ROOT);
        if (lower.length() > 90) {
            throw invalid("bech32 address is too long");
        }
        String dataPart = lower.substring(hrp.length() + 1);
        if (dataPart.length() < 7) {
            throw invalid("bech32 data part is too short");
        }
        int[] data = new int[dataPart.length()];
        for (int i = 0; i < data.length; i++) {
            data[i] = BECH32.indexOf(dataPart.charAt(i));
            if (data[i] < 0) {
                throw invalid("character '" + dataPart.charAt(i) + "' is not bech32");
            }
        }
        int checksum = polymod(hrp, data);
        int witnessVersion = data[0];
        if (witnessVersion > 16) {
            throw invalid("witness version " + witnessVersion);
        }
        int expectedConst = witnessVersion == 0 ? BECH32_CONST : BECH32M_CONST;
        if (checksum != expectedConst) {
            throw invalid("bech32 checksum");
        }
        byte[] program = convertBits(Arrays.copyOfRange(data, 1, data.length - 6));
        if (program.length < 2 || program.length > 40) {
            throw invalid("witness program has " + program.length + " bytes");
        }
        if (witnessVersion == 0 && program.length != 20 && program.length != 32) {
            throw invalid("version 0 witness program has " + program.length + " bytes");
        }
        byte opcode = (byte) (witnessVersion == 0 ? 0x00 : 0x50 + witnessVersion);
        return concat(new byte[]{opcode, (byte) program.length}, program);
    }

    private static int polymod(String hrp, int[] data) {
        int[] generator = {0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3};
        int chk = 1;
        int[] values = new int[hrp.length() * 2 + 1 + data.length];
        int n = 0;
        for (char c : hrp.toCharArray()) {
            values[n++] = c >> 5;
        }
        values[n++] = 0;
        for (char c : hrp.toCharArray()) {
            values[n++] = c & 31;
        }
        for (int d : data) {
            values[n++] = d;
        }
        for (int v : values) {
            int top = chk >>> 25;
            chk = (chk & 0x1ffffff) << 5 ^ v;
            for (int i = 0; i < 5; i++) {
                if (((top >>> i) & 1) == 1) {
                    chk ^= generator[i];
                }
            }
        }
        return chk;
    }

    // 5-bit groups to bytes without padding, as BIP 173 requires for a witness program.
    private static byte[] convertBits(int[] fiveBit) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int acc = 0;
        int bits = 0;
        for (int value : fiveBit) {
            acc = (acc << 5) | value;
            bits += 5;
            if (bits >= 8) {
                bits -= 8;
                out.write((acc >>> bits) & 0xff);
            }
        }
        if (bits >= 5 || ((acc << (8 - bits)) & 0xff) != 0) {
            throw invalid("bech32 padding");
        }
        return out.toByteArray();
    }

    private static byte[] concat(byte[]... parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] part : parts) {
            out.writeBytes(part);
        }
        return out.toByteArray();
    }

    private static ProvenPaymentException invalid(String message) {
        return new ProvenPaymentException(ProvenPaymentException.Reason.WRONG_SCRIPT, "Invalid address: " + message);
    }
}
