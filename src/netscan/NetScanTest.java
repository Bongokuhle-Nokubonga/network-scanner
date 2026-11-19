package netscan;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import netscan.PortScanner.HostResult;
import netscan.PortScanner.PortResult;
import netscan.PortScanner.ScanSummary;

/** Dependency-free tests. Run: java -cp out netscan.NetScanTest */
public final class NetScanTest {
    private static int passed, failed, skipped;

    interface Body { void run() throws Exception; }

    static void test(String name, Body body) {
        try {
            body.run();
            passed++;
            System.out.println("PASS  " + name);
        } catch (SkipException e) {
            skipped++;
            System.out.println("SKIP  " + name + " (" + e.getMessage() + ")");
        } catch (Throwable t) {
            failed++;
            System.out.println("FAIL  " + name + " -> " + t);
        }
    }

    static final class SkipException extends RuntimeException {
        private static final long serialVersionUID = 1L;

        SkipException(String m) { super(m); }
    }

    static void eq(Object actual, Object expected, String what) {
        if (!java.util.Objects.equals(actual, expected)) throw new AssertionError(what + ": expected <" + expected + "> but was <" + actual + ">");
    }

    static void yes(boolean cond, String what) {
        if (!cond) throw new AssertionError(what);
    }

    static void throwsArg(Body body, String fragment, String what) {
        try {
            body.run();
        } catch (IllegalArgumentException e) {
            if (!e.getMessage().contains(fragment)) throw new AssertionError(what + ": wrong message: " + e.getMessage());
            return;
        } catch (Exception e) {
            throw new AssertionError(what + ": wrong exception " + e);
        }
        throw new AssertionError(what + ": expected IllegalArgumentException");
    }

    static List<String> ips(List<InetAddress> list) {
        List<String> out = new ArrayList<>();
        for (InetAddress a : list) out.add(a.getHostAddress());
        return out;
    }

    public static void main(String[] args) {
        // ---------- Targets ----------
        test("CIDR /30 gives the two usable hosts", () ->
                eq(ips(Targets.parse("192.168.1.0/30")), List.of("192.168.1.1", "192.168.1.2"), "hosts"));
        test("CIDR /24 skips network and broadcast", () -> {
            List<String> h = ips(Targets.parse("10.0.0.0/24"));
            eq(h.size(), 254, "count");
            eq(h.get(0), "10.0.0.1", "first");
            eq(h.get(253), "10.0.0.254", "last");
        });
        test("host bits in a CIDR are ignored", () ->
                eq(ips(Targets.parse("192.168.1.77/30")).get(0), "192.168.1.77", "77 is in .76/30, first usable is .77"));
        test("/31 and /32 include every address", () -> {
            eq(ips(Targets.parse("10.1.1.4/31")), List.of("10.1.1.4", "10.1.1.5"), "/31");
            eq(ips(Targets.parse("10.1.1.9/32")), List.of("10.1.1.9"), "/32");
        });
        test("CIDR across an octet boundary", () -> {
            List<String> h = ips(Targets.parse("172.16.0.0/23"));
            eq(h.size(), 510, "count");
            eq(h.get(255), "172.16.1.0", "crosses into .1.0");
        });
        test("last-octet range and single IP", () -> {
            eq(ips(Targets.parse("192.168.5.10-12")), List.of("192.168.5.10", "192.168.5.11", "192.168.5.12"), "range");
            eq(ips(Targets.parse(" 8.8.8.8 ")), List.of("8.8.8.8"), "single");
        });
        test("rejects bad or oversized targets", () -> {
            throwsArg(() -> Targets.parse("10.0.0.0/16"), "limit is 1024", "too big");
            throwsArg(() -> Targets.parse("10.0.0.0/33"), "Prefix", "prefix > 32");
            throwsArg(() -> Targets.parse("300.1.1.1"), "Octet", "octet > 255");
            throwsArg(() -> Targets.parse("10.0.0.20-10"), "after", "reversed range");
            throwsArg(() -> Targets.parse("1.2.3"), "Not a valid target", "3 octets");
            throwsArg(() -> Targets.parse("bad host!"), "Not a valid target", "invalid name");
            throwsArg(() -> Targets.parse(""), "No target", "blank");
        });

        // ---------- Ports ----------
        test("port lists, ranges, duplicates and order", () -> {
            eq(Ports.parse("443, 22,80,22"), List.of(22, 80, 443), "sorted unique");
            eq(Ports.parse("8000-8003"), List.of(8000, 8001, 8002, 8003), "range");
            eq(Ports.parse("top"), Ports.TOP, "top");
            eq(Ports.parse(null), Ports.TOP, "default");
        });
        test("rejects bad ports", () -> {
            throwsArg(() -> Ports.parse("0"), "1-65535", "zero");
            throwsArg(() -> Ports.parse("70000"), "1-65535", "too high");
            throwsArg(() -> Ports.parse("90-80"), "after", "reversed");
            throwsArg(() -> Ports.parse("1-5000"), "Too many", "too many");
            throwsArg(() -> Ports.parse("ssh"), "Not a valid port", "text");
        });

        // ---------- Services ----------
        test("service names and security notes", () -> {
            eq(Services.lookup(22).name(), "SSH", "ssh");
            eq(Services.lookup(22).risk(), null, "ssh is fine");
            yes(Services.lookup(23).risk().contains("SSH"), "telnet warning");
            yes(Services.lookup(3389).risk().contains("VPN"), "rdp warning");
            yes(Services.lookup(445).risk().contains("ransomware"), "smb warning");
            eq(Services.lookup(54321).name(), "unknown", "unknown port");
        });

        // ---------- Output safety ----------
        test("banners are sanitised (control chars, length)", () -> {
            eq(PortScanner.sanitize("SSH-2.0-OpenSSH_9.6\r\n"), "SSH-2.0-OpenSSH_9.6", "trim CRLF");
            eq(PortScanner.sanitize("a\u001b[31mred\u0000b"), "a [31mred b", "escape codes removed");
            eq(PortScanner.sanitize("x".repeat(200)).length(), 80, "max length");
        });
        test("JSON escapes untrusted text", () -> {
            eq(Report.q("a\"b\\c\nd\u0001"), "\"a\\\"b\\\\c\\nd\\u0001\"", "escaped");
            ScanSummary s = new ScanSummary(List.of(new HostResult("10.0.0.5",
                    List.of(new PortResult(22, "SSH", "x\"y", null)))), 1, 1, 1, 5);
            String json = Report.toJson("10.0.0.5", s);
            yes(json.contains("\"banner\": \"x\\\"y\""), "banner escaped in output");
            yes(json.contains("\"risk\": null"), "null risk");
            yes(Report.toJson("t", new ScanSummary(List.of(), 1, 1, 1, 1)).contains("\"hosts\": []"), "empty list");
        });
        test("CSV quotes fields and blocks spreadsheet formulas", () -> {
            eq(Report.csv("a,b"), "\"a,b\"", "comma");
            eq(Report.csv("say \"hi\""), "\"say \"\"hi\"\"\"", "quotes");
            eq(Report.csv("=HYPERLINK(\"http://evil\")"), "\"'=HYPERLINK(\"\"http://evil\"\")\"", "formula neutralised");
            eq(Report.csv(null), "", "null");
        });
        test("text report lists ports and warnings", () -> {
            ScanSummary s = new ScanSummary(List.of(new HostResult("10.0.0.5", List.of(
                    new PortResult(22, "SSH", "SSH-2.0-OpenSSH", null),
                    new PortResult(23, "Telnet", "", Services.lookup(23).risk())))), 1, 2, 2, 1500);
            String t = Report.toText("10.0.0.5", s);
            yes(t.contains("22/tcp"), "port shown");
            yes(t.contains("! Unencrypted remote login"), "warning shown");
            yes(t.contains("1 security warning(s)"), "warning count");
        });
        test("scanner rejects unsafe settings", () -> {
            throwsArg(() -> new PortScanner(10, 10, false), "Timeout", "timeout too low");
            throwsArg(() -> new PortScanner(300, 1000, false), "Threads", "too many threads");
        });
        test("CLI returns usage errors instead of crashing", () -> {
            eq(NetScanApp.run(new String[] {}), 2, "no target");
            eq(NetScanApp.run(new String[] {"10.0.0.0/8"}), 2, "too large");
            eq(NetScanApp.run(new String[] {"127.0.0.1", "-p"}), 2, "missing value");
            eq(NetScanApp.run(new String[] {"127.0.0.1", "--bogus"}), 2, "unknown option");
            eq(NetScanApp.run(new String[] {"--help"}), 0, "help");
        });

        // ---------- Live scan against local test servers ----------
        test("finds open ports on localhost and reads the banner", NetScanTest::liveScan);

        System.out.println();
        System.out.println(passed + " passed, " + failed + " failed" + (skipped > 0 ? ", " + skipped + " skipped" : ""));
        System.exit(failed > 0 ? 1 : 0);
    }

    private static void liveScan() throws Exception {
        InetAddress lo = InetAddress.getByName("127.0.0.1");
        ServerSocket banner, silent;
        try {
            banner = new ServerSocket(0, 50, lo);
            silent = new ServerSocket(0, 50, lo);
        } catch (IOException | SecurityException e) {
            throw new SkipException("cannot open local sockets here: " + e.getMessage());
        }
        try (banner; silent) {
            int closedPort;
            try (ServerSocket tmp = new ServerSocket(0, 1, lo)) { closedPort = tmp.getLocalPort(); } // freed again = closed
            Thread t1 = serve(banner, "SSH-2.0-TestServer_1.0\r\n");
            Thread t2 = serve(silent, null);
            try (Socket check = new Socket()) {
                check.connect(new java.net.InetSocketAddress(lo, banner.getLocalPort()), 1000);
            } catch (IOException e) {
                throw new SkipException("loopback connections blocked: " + e.getMessage());
            }

            PortScanner scanner = new PortScanner(500, 8, true);
            ScanSummary s = scanner.scan(List.of(lo), List.of(banner.getLocalPort(), silent.getLocalPort(), closedPort), null);
            eq(s.hosts().size(), 1, "host up");
            List<PortResult> open = s.hosts().get(0).openPorts();
            eq(open.size(), 2, "two open ports, closed one not reported");
            PortResult withBanner = open.stream().filter(p -> p.port() == banner.getLocalPort()).findFirst().orElseThrow();
            eq(withBanner.banner(), "SSH-2.0-TestServer_1.0", "banner read");
            PortResult quiet = open.stream().filter(p -> p.port() == silent.getLocalPort()).findFirst().orElseThrow();
            eq(quiet.banner(), "", "silent service still open");
            eq(s.probes(), 3L, "probe count");
            t1.interrupt();
            t2.interrupt();
        }
    }

    /** Accepts connections; sends a greeting if given, otherwise stays silent. */
    private static Thread serve(ServerSocket server, String greeting) {
        Thread t = new Thread(() -> {
            while (!server.isClosed()) {
                try (Socket c = server.accept()) {
                    if (greeting != null) {
                        OutputStream out = c.getOutputStream();
                        out.write(greeting.getBytes(StandardCharsets.US_ASCII));
                        out.flush();
                    }
                    Thread.sleep(300);
                } catch (IOException | InterruptedException e) {
                    return;
                }
            }
        });
        t.setDaemon(true);
        t.start();
        return t;
    }
}
