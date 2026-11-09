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

import lombok.ToString;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * Checks an SP1 wrap proof with the native nova-bitvm3 verifier {@code m13-verify verify-v2 WRAP.bin EXPECT.json}
 * (garbled-snark-verifier nova-bitvm3/m13/verify, transcript v2, the proof format the M14 garbled circuit evaluates).
 * <p>
 * The node writes the expected statement: the pinned wrap key and recursion key root (the same for every guest), the
 * program verifying key digest, and SHA-256 of the public values. {@code m13-verify} accepts only if the proof's
 * statement equals it, the guest's exit code is 0 and the proof is complete. It then exits with 0 and prints
 * {@code "status": "verified"}. Every other outcome, also a timeout, an I/O error or a missing binary, counts as
 * rejected.
 */
@Slf4j
@ToString
public final class M13ProcessProofVerifier implements SnarkProofVerifier {
    // nova-bitvm3/m13/pins.json: guest-independent pins of the M13 final layer (SP1 6.9.0).
    static final String WRAP_VK_SHA256 = "d42c63e3c873b35576b4c95fa8c41770a8c6b8a9f16ba74732c5b52a43b0b0d7";
    static final String RECURSION_VK_ROOT = "7487c2175bd3256619ca0118094b8150d6df0246a1b41979a081642e5253f257";
    // A wrap proof file is 1,099,173 bytes. The limit keeps an oversized input from reaching the disk.
    static final int MAX_PROOF_BYTES = 4 * 1024 * 1024;
    private static final int MAX_OUTPUT_BYTES = 1024 * 1024;
    private static final Pattern VERIFIED = Pattern.compile("\"status\"\\s*:\\s*\"verified\"");

    /**
     * How the verifier process sees the node's file paths. {@code WSL} converts a Windows path such as
     * {@code C:\Users\x} to {@code /mnt/c/Users/x}, for a Linux build of {@code m13-verify} run through
     * {@code wsl.exe}.
     */
    public enum PathStyle {
        NATIVE,
        WSL
    }

    private final List<String> command;
    private final PathStyle pathStyle;
    private final Duration timeout;

    /**
     * @param command the program and leading arguments, for example {@code ["/usr/local/bin/m13-verify"]} or
     *                {@code ["wsl.exe", "-d", "Ubuntu-24.04", "--", "/root/m13-verify"]}
     */
    public M13ProcessProofVerifier(List<String> command, PathStyle pathStyle, Duration timeout) {
        if (command.isEmpty()) {
            throw new IllegalArgumentException("command must not be empty");
        }
        this.command = List.copyOf(command);
        this.pathStyle = pathStyle;
        this.timeout = timeout;
    }

    @Override
    public boolean verify(byte[] programVkDigest, byte[] publicValues, byte[] proof) {
        if (programVkDigest.length != 32 || proof.length == 0 || proof.length > MAX_PROOF_BYTES) {
            log.warn("Refused proof input: program digest of {} bytes, proof of {} bytes", programVkDigest.length, proof.length);
            return false;
        }
        String committedValuesSha256 = Hex.encode(ProvenPaymentValidator.sha256(publicValues));
        Path dir = null;
        try {
            dir = Files.createTempDirectory("bisq-m13-verify");
            Path wrap = dir.resolve("wrap.bin");
            Path expect = dir.resolve("expect.json");
            Files.write(wrap, proof);
            Files.writeString(expect, expectedStatementJson(programVkDigest, committedValuesSha256), StandardCharsets.UTF_8);

            List<String> cmd = new ArrayList<>(command);
            cmd.add("verify-v2");
            cmd.add(processPath(wrap));
            cmd.add(processPath(expect));
            Process process = new ProcessBuilder(cmd).redirectErrorStream(true).start();
            process.getOutputStream().close();
            CompletableFuture<String> output = CompletableFuture.supplyAsync(() -> readBounded(process.getInputStream()));
            if (!process.waitFor(timeout.toMillis(), TimeUnit.MILLISECONDS)) {
                process.destroyForcibly();
                log.warn("m13-verify did not finish within {}", timeout);
                return false;
            }
            String out = output.get(10, TimeUnit.SECONDS);
            boolean verified = process.exitValue() == 0 && isVerifiedOutput(out, committedValuesSha256);
            if (!verified) {
                log.info("m13-verify refused the proof (exit {}): {}", process.exitValue(), lastLine(out));
            }
            return verified;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        } catch (Exception e) {
            log.warn("m13-verify could not run: {}", e.toString());
            return false;
        } finally {
            deleteQuietly(dir);
        }
    }

    static String expectedStatementJson(byte[] programVkDigest, String committedValuesSha256) {
        return """
                {
                  "committed_values_sha256": "%s",
                  "exit_code": 0,
                  "is_complete": 1,
                  "program_vk_digest": "%s",
                  "recursion_vk_root": "%s",
                  "wrap_vk_sha256": "%s"
                }
                """.formatted(committedValuesSha256, Hex.encode(programVkDigest), RECURSION_VK_ROOT, WRAP_VK_SHA256);
    }

    /**
     * The exit code is the verifier's decision. The output must also report success for our statement, so that a
     * wrong program at the configured path, which exits with 0 for any input, does not count as a verifier.
     */
    static boolean isVerifiedOutput(String out, String committedValuesSha256) {
        return VERIFIED.matcher(out).find() && out.contains(committedValuesSha256);
    }

    String processPath(Path path) {
        String absolute = path.toAbsolutePath().toString();
        if (pathStyle == PathStyle.NATIVE) {
            return absolute;
        }
        return toWslPath(absolute);
    }

    static String toWslPath(String windowsPath) {
        if (windowsPath.length() < 3 || windowsPath.charAt(1) != ':') {
            throw new IllegalArgumentException("Not a Windows drive path: " + windowsPath);
        }
        String drive = windowsPath.substring(0, 1).toLowerCase(Locale.ROOT);
        return "/mnt/" + drive + windowsPath.substring(2).replace('\\', '/');
    }

    private static String readBounded(InputStream in) {
        try (in) {
            byte[] bytes = in.readNBytes(MAX_OUTPUT_BYTES);
            in.transferTo(OutputStream.nullOutputStream());
            return new String(bytes, StandardCharsets.UTF_8);
        } catch (IOException e) {
            return "";
        }
    }

    private static String lastLine(String out) {
        String trimmed = out.strip();
        int nl = trimmed.lastIndexOf('\n');
        return nl < 0 ? trimmed : trimmed.substring(nl + 1);
    }

    private static void deleteQuietly(Path dir) {
        if (dir == null) {
            return;
        }
        try (Stream<Path> files = Files.walk(dir)) {
            files.sorted(Comparator.reverseOrder()).forEach(p -> {
                try {
                    Files.deleteIfExists(p);
                } catch (IOException ignored) {
                }
            });
        } catch (IOException ignored) {
        }
    }
}
