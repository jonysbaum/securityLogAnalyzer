package com.jon;

import java.io.IOException;

import java.nio.file.Files;
import java.nio.file.Path;

import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;

import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class App {

    // Supported line format:
    // ex. 2026-02-19T21:15:30Z FAILED_LOGIN user=johndoe ip=203.0.113.9
    private static final Pattern FAILED_LOGIN = Pattern.compile(
            "^(?<ts>\\S+)\\s+FAILED_LOGIN\\s+user=(?<user>\\S+)\\s+ip=(?<ip>\\S+).*$"
    );

    private static final DateTimeFormatter ISO_TS = DateTimeFormatter.ISO_DATE_TIME;

    public static void main(String[] args) throws IOException {
        Map<String, String> argMap = parseArgs(args);

        String file = argMap.get("file");
        if (file == null || file.isBlank()) {
            System.out.println("Usage: java -jar security-log-analyzer.jar --file <path> [--threshold 5]");
            System.exit(2);
        }

        int threshold = parseIntOrDefault(argMap.get("threshold"), 5);

        AnalysisResult result = analyze(Path.of(file));

        System.out.println("=== Security Log Analyzer Summary ===");
        System.out.println("File: " + file);
        System.out.println("Total failed login events: " + result.totalFailedLogins());
        System.out.println();

        System.out.println("Top users by failed logins:");
        result.failedByUser().entrySet().stream()
                .sorted((a, b) -> Integer.compare(b.getValue(), a.getValue()))
                .limit(10)
                .forEach(e -> System.out.printf("  %s: %d%n", e.getKey(), e.getValue()));

        System.out.println();
        System.out.println("Top IPs by failed logins:");
        result.failedByIp().entrySet().stream()
                .sorted((a, b) -> Integer.compare(b.getValue(), a.getValue()))
                .limit(10)
                .forEach(e -> System.out.printf("  %s: %d%n", e.getKey(), e.getValue()));

        System.out.println();
        System.out.println("Alerts (threshold >= " + threshold + "):");
        boolean anyAlerts = result.failedByUser().entrySet().stream()
                .filter(e -> e.getValue() >= threshold)
                .peek(e -> System.out.printf("  ALERT: user %s has %d failed logins%n", e.getKey(), e.getValue()))
                .findAny()
                .isPresent();

        if (!anyAlerts) System.out.println("  (none)");
    }

    private static AnalysisResult analyze(Path filePath) throws IOException {
        int totalFailed = 0;
        Map<String, Integer> byUser = new HashMap<>();
        Map<String, Integer> byIp = new HashMap<>();

        try (var lines = Files.lines(filePath)) {
            for (String line : (Iterable<String>) lines::iterator) {
                Matcher m = FAILED_LOGIN.matcher(line);
                if (!m.matches()) continue;

                totalFailed++;

                String user = m.group("user");
                String ip = m.group("ip");
                String ts = m.group("ts");

                // Parsed for future enhancements (time windows, unusual hours).
                try {
                    OffsetDateTime.parse(ts, ISO_TS);
                } catch (Exception ignored) {
                    // tolerate timestamp variations for now
                }

                byUser.merge(user, 1, Integer::sum);
                byIp.merge(ip, 1, Integer::sum);
            }
        }

        return new AnalysisResult(totalFailed, byUser, byIp);
    }

    private static Map<String, String> parseArgs(String[] args) {
        Map<String, String> m = new HashMap<>();
        for (int i = 0; i < args.length; i++) {
            String a = args[i];
            if (a.startsWith("--")) {
                String key = a.substring(2);
                String val = (i + 1 < args.length && !args[i + 1].startsWith("--")) ? args[++i] : "true";
                m.put(key, val);
            }
        }
        return m;
    }

    private static int parseIntOrDefault(String value, int fallback) {
        if (value == null) return fallback;
        try { return Integer.parseInt(value);
        } catch (NumberFormatException ignored) {
            return fallback;
        }
    }

    public record AnalysisResult(
            int totalFailedLogins,
            Map<String, Integer> failedByUser,
            Map<String, Integer> failedByIp
    ) {}
}
