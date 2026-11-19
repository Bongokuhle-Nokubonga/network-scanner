package netscan;

import java.time.Instant;
import java.util.List;
import java.util.Locale;
import netscan.PortScanner.HostResult;
import netscan.PortScanner.PortResult;
import netscan.PortScanner.ScanSummary;

/** Formats scan results as a console table, JSON or CSV. */
public final class Report {
    private Report() { }

    public static String toText(String target, ScanSummary s) {
        StringBuilder sb = new StringBuilder();
        sb.append(String.format(Locale.ROOT, "Scan of %s: %d host(s), %d port(s) each, %d probes in %.1fs%n",
                target, s.hostsScanned(), s.portsPerHost(), s.probes(), s.millis() / 1000.0));
        if (s.hosts().isEmpty()) {
            sb.append("No open ports found (hosts may be down or firewalled).").append(System.lineSeparator());
            return sb.toString();
        }
        int warnings = 0;
        for (HostResult h : s.hosts()) {
            sb.append(System.lineSeparator()).append(h.ip()).append("  (").append(h.openPorts().size()).append(" open)").append(System.lineSeparator());
            sb.append(String.format("  %-7s %-22s %s%n", "PORT", "SERVICE", "BANNER"));
            for (PortResult p : h.openPorts()) {
                sb.append(String.format("  %-7s %-22s %s%n", p.port() + "/tcp", p.service(), p.banner()));
                if (p.risk() != null) {
                    sb.append("          ! ").append(p.risk()).append(System.lineSeparator());
                    warnings++;
                }
            }
        }
        sb.append(System.lineSeparator()).append(String.format("%d host(s) with open ports, %d security warning(s).%n", s.hosts().size(), warnings));
        return sb.toString();
    }

    public static String toJson(String target, ScanSummary s) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\n  \"target\": ").append(q(target))
          .append(",\n  \"finished\": ").append(q(Instant.now().toString()))
          .append(",\n  \"hostsScanned\": ").append(s.hostsScanned())
          .append(",\n  \"portsPerHost\": ").append(s.portsPerHost())
          .append(",\n  \"durationMs\": ").append(s.millis())
          .append(",\n  \"hosts\": [");
        List<HostResult> hosts = s.hosts();
        for (int i = 0; i < hosts.size(); i++) {
            HostResult h = hosts.get(i);
            sb.append(i == 0 ? "\n" : ",\n").append("    {\"ip\": ").append(q(h.ip())).append(", \"openPorts\": [");
            for (int j = 0; j < h.openPorts().size(); j++) {
                PortResult p = h.openPorts().get(j);
                sb.append(j == 0 ? "\n" : ",\n")
                  .append("      {\"port\": ").append(p.port())
                  .append(", \"service\": ").append(q(p.service()))
                  .append(", \"banner\": ").append(q(p.banner()))
                  .append(", \"risk\": ").append(p.risk() == null ? "null" : q(p.risk()))
                  .append("}");
            }
            sb.append(h.openPorts().isEmpty() ? "]}" : "\n    ]}");
        }
        sb.append(hosts.isEmpty() ? "]\n}\n" : "\n  ]\n}\n");
        return sb.toString();
    }

    public static String toCsv(ScanSummary s) {
        StringBuilder sb = new StringBuilder("ip,port,service,banner,risk\n");
        for (HostResult h : s.hosts()) {
            for (PortResult p : h.openPorts()) {
                sb.append(csv(h.ip())).append(',').append(p.port()).append(',').append(csv(p.service())).append(',')
                  .append(csv(p.banner())).append(',').append(csv(p.risk())).append('\n');
            }
        }
        return sb.toString();
    }

    static String q(String s) {
        if (s == null) return "null";
        StringBuilder sb = new StringBuilder("\"");
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
                    else sb.append(c);
                }
            }
        }
        return sb.append('"').toString();
    }

    /** CSV field with quoting, plus a leading ' for values a spreadsheet would run as a formula. */
    static String csv(String s) {
        if (s == null || s.isEmpty()) return "";
        String v = s;
        if ("=+-@".indexOf(v.charAt(0)) >= 0) v = "'" + v;
        if (v.contains(",") || v.contains("\"") || v.contains("\n") || v.contains("\r")) {
            v = "\"" + v.replace("\"", "\"\"") + "\"";
        }
        return v;
    }
}
