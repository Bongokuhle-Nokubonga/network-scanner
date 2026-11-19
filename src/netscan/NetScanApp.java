package netscan;

import java.io.IOException;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/** Command-line entry point. */
public final class NetScanApp {

    private static final String USAGE = """
            Usage: java -cp out netscan.NetScanApp <target> [options]

              target            192.168.1.10 | 192.168.1.0/24 | 192.168.1.1-50 | hostname

            Options:
              -p, --ports LIST  ports to scan: "top" (default), "22,80,443", "1-1024"
              -t, --timeout MS  connect timeout per port in ms (default 300)
              --threads N       parallel connections (default 100)
              --banners         read service banners (SSH version, HTTP Server header...)
              --json FILE       save results as JSON
              --csv FILE        save results as CSV
              -h, --help        show this help

            Only scan networks you own or have written permission to test.
            """;

    private NetScanApp() { }

    public static void main(String[] args) {
        System.exit(run(args));
    }

    static int run(String[] args) {
        String target = null, ports = "top", json = null, csvFile = null;
        int timeout = 300, threads = 100;
        boolean banners = false;
        try {
            for (int i = 0; i < args.length; i++) {
                String a = args[i];
                switch (a) {
                    case "-h", "--help" -> { System.out.print(USAGE); return 0; }
                    case "-p", "--ports" -> ports = value(args, ++i, a);
                    case "-t", "--timeout" -> timeout = Integer.parseInt(value(args, ++i, a));
                    case "--threads" -> threads = Integer.parseInt(value(args, ++i, a));
                    case "--banners" -> banners = true;
                    case "--json" -> json = value(args, ++i, a);
                    case "--csv" -> csvFile = value(args, ++i, a);
                    default -> {
                        if (a.startsWith("-")) throw new IllegalArgumentException("Unknown option: " + a);
                        if (target != null) throw new IllegalArgumentException("Only one target allowed.");
                        target = a;
                    }
                }
            }
            if (target == null) { System.err.print(USAGE); return 2; }

            List<InetAddress> hosts = Targets.parse(target);
            List<Integer> portList = Ports.parse(ports);
            PortScanner scanner = new PortScanner(timeout, threads, banners);

            System.out.println("netscan - authorised use only. Scanning " + hosts.size() + " host(s) x " + portList.size() + " port(s)...");
            int[] lastDecile = { 0 };
            PortScanner.ScanSummary result = scanner.scan(hosts, portList, pct -> {
                synchronized (lastDecile) { // threads report out of order; only ever print upwards
                    if (pct / 10 > lastDecile[0]) {
                        lastDecile[0] = pct / 10;
                        System.out.print("\r  progress: " + lastDecile[0] * 10 + "%   ");
                    }
                }
            });
            System.out.println();
            System.out.print(Report.toText(target, result));

            if (json != null) save(json, Report.toJson(target, result));
            if (csvFile != null) save(csvFile, Report.toCsv(result));
            return 0;
        } catch (NumberFormatException e) {
            System.err.println("Error: expected a number (" + e.getMessage() + ")");
            return 2;
        } catch (IllegalArgumentException e) {
            System.err.println("Error: " + e.getMessage());
            return 2;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            System.err.println("Scan interrupted.");
            return 130;
        } catch (IOException e) {
            System.err.println("Error writing output: " + e.getMessage());
            return 1;
        }
    }

    private static String value(String[] args, int i, String option) {
        if (i >= args.length) throw new IllegalArgumentException(option + " needs a value.");
        return args[i];
    }

    private static void save(String file, String content) throws IOException {
        Files.writeString(Path.of(file), content, StandardCharsets.UTF_8);
        System.out.println("Saved " + file);
    }
}
