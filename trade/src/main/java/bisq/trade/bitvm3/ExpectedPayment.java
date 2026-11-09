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

import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;

import java.util.Optional;

/**
 * What the trade expects of the proven payment: an output paying {@code scriptPubKey} at least {@code minValueSats},
 * with at least {@code minConfirmations}, and, if the seller gave one, in transaction {@code txidDisplayHex}.
 */
@Getter
@ToString
@EqualsAndHashCode
public final class ExpectedPayment {
    private final Optional<String> txidDisplayHex;
    private final byte[] scriptPubKey;
    private final long minValueSats;
    private final long minConfirmations;

    public ExpectedPayment(Optional<String> txidDisplayHex, byte[] scriptPubKey, long minValueSats, long minConfirmations) {
        if (minValueSats <= 0) {
            throw new IllegalArgumentException("minValueSats must be positive");
        }
        if (minConfirmations < 1) {
            throw new IllegalArgumentException("minConfirmations must be at least 1");
        }
        this.txidDisplayHex = txidDisplayHex.map(String::trim).map(String::toLowerCase);
        this.scriptPubKey = scriptPubKey.clone();
        this.minValueSats = minValueSats;
        this.minConfirmations = minConfirmations;
    }

    public byte[] getScriptPubKey() {
        return scriptPubKey.clone();
    }
}
