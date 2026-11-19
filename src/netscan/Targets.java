package netscan;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Parses scan targets: a CIDR block, a last-octet range, a single IPv4 address or a hostname. */
public final class Targets {
    /** Safety limit: at most a /22 (1022 hosts) per scan. */
    public static final int MAX_HOSTS = 1024;

    private static final Pattern IPV4 = Pattern.compile("^(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})$");
    private static final Pattern RANGE = Pattern.compile("^(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})\\.(\\d{1,3})-(\\d{1,3})$");
    private static final Pattern HOSTNAME = Pattern.compile("^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*$");

    private Targets() { }

    public static List<InetAddress> parse(String spec) {
        if (spec == null || spec.isBlank()) throw new IllegalArgumentException("No target given.");
        String s = spec.trim();

        if (s.contains("/")) return parseCidr(s);

        Matcher range = RANGE.matcher(s);
        if (range.matches()) {
            int from = octet(range.group(2)), to = octet(range.group(3));
            if (from > to) throw new IllegalArgumentException("Range start is after range end: " + s);
            int base = ipToInt(range.group(1) + ".0");
            List<InetAddress> out = new ArrayList<>();
            for (int i = from; i <= to; i++) out.add(intToAddress(base | i));
            return out;
        }

        if (IPV4.matcher(s).matches()) return List.of(intToAddress(ipToInt(s)));

        if (HOSTNAME.matcher(s).matches() && !s.matches("[\\d.]+")) {
            try {
                for (InetAddress a : InetAddress.getAllByName(s)) {
                    if (a instanceof Inet4Address) return List.of(a);
                }
                throw new IllegalArgumentException(s + " has no IPv4 address.");
            } catch (UnknownHostException e) {
                throw new IllegalArgumentException("Can't resolve host name: " + s);
            }
        }
        throw new IllegalArgumentException("Not a valid target: " + s + " (use 192.168.1.10, 192.168.1.0/24, 192.168.1.1-50 or a host name)");
    }

    private static List<InetAddress> parseCidr(String s) {
        String[] parts = s.split("/", -1);
        if (parts.length != 2 || !parts[1].matches("\\d{1,2}")) throw new IllegalArgumentException("Not a valid CIDR block: " + s);
        int prefix = Integer.parseInt(parts[1]);
        if (prefix > 32) throw new IllegalArgumentException("Prefix must be 0-32: " + s);
        long size = 1L << (32 - prefix);
        if (size > MAX_HOSTS) {
            throw new IllegalArgumentException("Network " + s + " has " + size + " addresses; the limit is " + MAX_HOSTS + " (a /22). Scan smaller blocks.");
        }
        int mask = prefix == 0 ? 0 : -1 << (32 - prefix);
        int network = ipToInt(parts[0]) & mask;
        List<InetAddress> out = new ArrayList<>();
        if (prefix >= 31) {
            for (long i = 0; i < size; i++) out.add(intToAddress((int) (network + i)));
        } else {
            for (long i = 1; i < size - 1; i++) out.add(intToAddress((int) (network + i))); // skip network + broadcast
        }
        return out;
    }

    static int ipToInt(String ip) {
        Matcher m = IPV4.matcher(ip.trim());
        if (!m.matches()) throw new IllegalArgumentException("Not a valid IPv4 address: " + ip);
        int v = 0;
        for (int i = 1; i <= 4; i++) v = (v << 8) | octet(m.group(i));
        return v;
    }

    private static int octet(String text) {
        int n = Integer.parseInt(text);
        if (n > 255) throw new IllegalArgumentException("Octet out of range (0-255): " + text);
        return n;
    }

    static InetAddress intToAddress(int v) {
        byte[] b = { (byte) (v >>> 24), (byte) (v >>> 16), (byte) (v >>> 8), (byte) v };
        try {
            return InetAddress.getByAddress(b);
        } catch (UnknownHostException e) {
            throw new IllegalStateException(e); // cannot happen for 4 bytes
        }
    }
}
