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

import lombok.Getter;

/**
 * A statement or proof which does not show the payment the trade expects. The reason lets callers and tests tell the
 * failed rule apart without parsing the message.
 */
@Getter
public class ProvenPaymentException extends IllegalArgumentException {
    public enum Reason {
        MALFORMED,
        UNKNOWN_NETWORK,
        WRONG_FOLD_WIDTH,
        WRONG_VERIFIER_KEY,
        WRONG_GENESIS,
        INCONSISTENT_CHAIN,
        CHAINWORK_TOO_LOW,
        NO_PAYMENT_RECORD,
        INCONSISTENT_PAYMENT,
        WRONG_TXID,
        WRONG_SCRIPT,
        VALUE_TOO_LOW,
        TOO_FEW_CONFIRMATIONS,
        UNTRUSTED_PROGRAM,
        PROOF_REJECTED,
        DISABLED
    }

    private final Reason reason;

    public ProvenPaymentException(Reason reason, String message) {
        super(reason + ": " + message);
        this.reason = reason;
    }
}
