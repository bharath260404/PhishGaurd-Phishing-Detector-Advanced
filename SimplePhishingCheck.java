import java.util.Scanner;
import java.util.List;
import java.util.Arrays;

public class SimplePhishingCheck {

    // List of keywords often found in phishing URLs
    private static final List<String> SUSPICIOUS_KEYWORDS = Arrays.asList(
        "login", "verify", "update", "secure", "account", "bank", "confirm", "free", "bonus"
    );

    public static void main(String[] args) {
        Scanner sc = new Scanner(System.in);
        System.out.println("Simple Phishing URL Checker");
        System.out.println("Enter a website URL (or type 'exit' to quit):");

        while (true) {
            System.out.print("> ");
            String url = sc.nextLine().trim();
            if (url.equalsIgnoreCase("exit")) {
                break;
            }
            if (url.isEmpty()) {
                System.out.println("Please enter a non-empty URL.");
                continue;
            }

            Result res = analyzeUrl(url);
            printResult(res);
        }

        sc.close();
        System.out.println("Exiting. Stay safe!");
    }

    // Container for analysis result
    private static class Result {
        String url;
        double score;
        String risk;      // "LOW", "MEDIUM", "HIGH"
        StringBuilder reasons = new StringBuilder();

        Result(String url) {
            this.url = url;
            this.score = 0.0;
        }
    }

    // Analyze URL and produce a Result
    private static Result analyzeUrl(String url) {
        Result r = new Result(url);

        // Normalize for checks
        String lower = url.toLowerCase();

        // Rule: long URL -> +2 points if > 75 chars, +1 if 50-75
        int len = url.length();
        if (len > 75) {
            r.score += 2.0;
            r.reasons.append("Long URL (>75 chars). ");
        } else if (len > 50) {
            r.score += 1.0;
            r.reasons.append("Moderately long URL (50-75 chars). ");
        }

        // Rule: presence of '@' -> +3 points (rare and suspicious)
        if (lower.contains("@")) {
            r.score += 3.0;
            r.reasons.append("'@' symbol present in URL. ");
        }

        // Rule: missing https -> +1.5 points
        if (!lower.startsWith("https://")) {
            // http or missing protocol
            r.score += 1.5;
            r.reasons.append("No HTTPS (secure) prefix. ");
        } else {
            // has https, small negative weight (safer)
            r.score -= 0.5;
        }

        // Rule: contains IP address instead of domain -> +3 points
        if (hasIpAddress(lower)) {
            r.score += 3.0;
            r.reasons.append("IP address used instead of domain. ");
        }

        // Rule: suspicious keywords -> +1 point per keyword (cap at 3)
        int kwCount = 0;
        for (String kw : SUSPICIOUS_KEYWORDS) {
            if (lower.contains(kw)) {
                kwCount++;
                r.reasons.append("Contains suspicious word: '" + kw + "'. ");
            }
        }
        r.score += Math.min(3, kwCount) * 1.0;

        // Rule: number of dots (many subdomains) -> +0.5 if >3
        int dots = countChar(lower, '.');
        if (dots > 3) {
            r.score += 0.5;
            r.reasons.append("Many subdomains detected. ");
        }

        // Final risk determination (thresholds)
        if (r.score >= 6.0) {
            r.risk = "HIGH";
        } else if (r.score >= 3.0) {
            r.risk = "MEDIUM";
        } else {
            r.risk = "LOW";
        }

        return r;
    }

    // Basic helper: detect IPv4 in URL (very simple check)
    private static boolean hasIpAddress(String s) {
        // Check for pattern like http://123.45.67.89 or //123.45.67.89
        // This is a heuristic, not full validation
        String[] parts = s.split("/");
        for (String p : parts) {
            if (p.matches("\\d+\\.\\d+\\.\\d+\\.\\d+(:\\d+)?")) return true;
        }
        return false;
    }

    private static int countChar(String s, char c) {
        int cnt = 0;
        for (char ch : s.toCharArray()) if (ch == c) cnt++;
        return cnt;
    }

    // Print result nicely
    private static void printResult(Result r) {
        System.out.println("----- Analysis for: " + r.url);
        System.out.printf("Risk score: %.1f   Risk level: %s%n", r.score, r.risk);
        if (r.reasons.length() > 0) {
            System.out.println("Reasons: " + r.reasons.toString().trim());
        } else {
            System.out.println("No obvious heuristic issues found.");
        }

        if (r.risk.equals("HIGH")) {
            System.out.println("🚨 Recommendation: Treat as PHISHING. Do NOT enter credentials.");
        } else if (r.risk.equals("MEDIUM")) {
            System.out.println("⚠️ Recommendation: Be cautious. Verify URL/domain before proceeding.");
        } else {
            System.out.println("✅ Recommendation: Likely SAFE, but always double-check before entering sensitive info.");
        }
        System.out.println();
    }
}
