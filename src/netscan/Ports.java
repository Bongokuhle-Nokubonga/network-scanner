package netscan;

import java.util.ArrayList;
import java.util.List;
import java.util.TreeSet;

/** Parses port lists such as "22,80,443", "1-1024" or "top". */
public final class Ports {
    public static final int MAX_PORTS = 1024;

    /** Commonly exposed services worth checking first. */
    public static final List<Integer> TOP = List.of(
            21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 389, 443, 445, 587, 993, 995,
            1433, 1521, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 9100, 27017);

    private Ports() { }

    public static List<Integer> parse(String spec) {
        if (spec == null || spec.isBlank() || spec.trim().equalsIgnoreCase("top")) return TOP;
        TreeSet<Integer> ports = new TreeSet<>();
        for (String raw : spec.split(",")) {
            String part = raw.trim();
            if (part.isEmpty()) continue;
            if (part.matches("\\d{1,5}-\\d{1,5}")) {
                String[] ends = part.split("-");
                int from = port(ends[0]), to = port(ends[1]);
                if (from > to) throw new IllegalArgumentException("Port range start is after end: " + part);
                if (to - from + 1 > MAX_PORTS) throw new IllegalArgumentException("Too many ports (limit " + MAX_PORTS + ").");
                for (int p = from; p <= to; p++) ports.add(p);
            } else if (part.matches("\\d{1,5}")) {
                ports.add(port(part));
            } else {
                throw new IllegalArgumentException("Not a valid port: " + part);
            }
            if (ports.size() > MAX_PORTS) throw new IllegalArgumentException("Too many ports (limit " + MAX_PORTS + ").");
        }
        if (ports.isEmpty()) throw new IllegalArgumentException("No ports given.");
        return new ArrayList<>(ports);
    }

    private static int port(String text) {
        int p = Integer.parseInt(text);
        if (p < 1 || p > 65535) throw new IllegalArgumentException("Port must be 1-65535: " + text);
        return p;
    }
}
