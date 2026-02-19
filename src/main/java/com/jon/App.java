package com.jon;

import java.io.IOException;

import java.nio.file.Files;
import java.nio.file.Path;

import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class App {

    // checks if line contains a FAILED_LOGIN event
    private static final Pattern FAILED_LOGIN = Pattern.compile("\\bFAILED_LOGIN\\b");


    public static void main(String[] args) throws IOException {
        Map<String, String> argMap = parseArgs(args);

        String file = argMap.get("file");
        if (file == null || file.isBlank()) {
            System.out.println("Usage: java -jar security-log-analyzer.jar --file <path> [--threshold 5]");
            System.exit(2);
        }

        int threshold = 5;
        if (argMap.containsKey("threshold")) {
            threshold = Integer.parseInt(argMap.get("threshold"));
        }

        AnalysisResult result = analyze(Path.of(file));

        System.out.println("=== Security Log Analyzer Summary ===");
        System.out.println("File: " + file);
        System.out.println("Total failed login events: " + result.totalFailedLogins);
        System.out.println();

        System.out.println("Top users by failed logins:");
        result.failedByUser.entrySet().stream()
                .sorted((a, b) -> Integer.compare(b.getValue(), a.getValue()))
                .limit(10)
                .forEach(e -> System.out.printf("  %s: %d%n", e.getKey(), e.getValue()));

        System.out.println();
        System.out.println("Top IPs by failed logins:");
        result.failedByIp.entrySet().stream()
                .sorted((a, b) -> Integer.compare(b.getValue(), a.getValue()))
                .limit(10)
                .forEach(e -> System.out.printf("  %s: %d%n", e.getKey(), e.getValue()));

        System.out.println();
        System.out.println("Alerts (threshold >= " + threshold + "):");
        boolean anyAlerts = false;
        for (var entry : result.failedByUser.entrySet()) {
            if (entry.getValue() >=  threshold) {
                anyAlerts = true;
                System.out.printf(" Alert: user %s has %d failed logins%n", entry.getKey(), entry.getValue());
            }
        }

        if (!anyAlerts) System.out.println("  (none)");
    }

    private static AnalysisResult analyze(Path filePath) throws IOException {
        AnalysisResult r = new AnalysisResult();

        try (var lines = Files.lines(filePath)) {
            lines.forEach(line -> {
                ;
                Matcher m = FAILED_LOGIN.matcher(line);
                if (!m.find()) return;

                r.totalFailedLogins++;

                String user = extractValue(line, "user=");
                String ip = extractValue(line, "ip=");

                if (user != null) r.failedByUser.merge(user, 1, Integer::sum);
                if (ip != null) r.failedByIp.merge(user, 1, Integer::sum);
            });
        }
        return r;
    }

    private static String extractValue(String line, String key) {
        int start = line.indexOf(key);
        if (start == -1) return null;

        start += key.length();
        int end = line.indexOf(' ', start);

        if (end == -1) {
            return line.substring(start);
        }
        return line.substring(start, end);
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

    public static class AnalysisResult{
            int totalFailedLogins = 0;
            Map<String, Integer> failedByUser = new HashMap<>();
            Map<String, Integer> failedByIp = new HashMap<>();
    }
}
