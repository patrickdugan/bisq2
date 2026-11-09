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

/**
 * Checks an SP1 wrap proof (M13 BLAKE3 final layer) of a guest's public values. Bisq has no Java implementation of this
 * verifier. A node plugs in the native `m13-verify` or the evaluation of the M14 garbled circuit. Without a plugged-in
 * verifier every proof is rejected.
 */
@FunctionalInterface
public interface SnarkProofVerifier {
    SnarkProofVerifier REJECT_ALL = (programVkDigest, publicValues, proof) -> false;

    /**
     * @return true only if {@code proof} proves that the program with {@code programVkDigest} committed exactly
     * {@code publicValues}.
     */
    boolean verify(byte[] programVkDigest, byte[] publicValues, byte[] proof);
}
