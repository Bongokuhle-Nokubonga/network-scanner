package netscan;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.IntConsumer;

/** Multithreaded TCP connect scanner. A port is "open" when a full TCP handshake succeeds. */
public final class PortScanner {

    public record PortResult(int port, String service, String banner, String risk) { }

    public record HostResult(String ip, List<PortResult> openPorts) { }

    public record ScanSummary(List<HostResult> hosts, int hostsScanned, int portsPerHost, long probes, long millis) { }

    private final int timeoutMs;
    private final int threads;
    private final boolean grabBanners;

    public PortScanner(int timeoutMs, int threads, boolean grabBanners) {
        if (timeoutMs < 50 || timeoutMs > 10_000) throw new IllegalArgumentException("Timeout must be 50-10000 ms.");
        if (threads < 1 || threads > 256) throw new IllegalArgumentException("Threads must be 1-256.");
        this.timeoutMs = timeoutMs;
        this.threads = threads;
        this.grabBanners = grabBanners;
    }

    public ScanSummary scan(List<InetAddress> hosts, List<Integer> ports, IntConsumer progress) throws InterruptedException {
        long start = System.nanoTime();
        Map<String, ConcurrentLinkedQueue<PortResult>> found = new ConcurrentHashMap<>();
        Map<String, Integer> order = new ConcurrentHashMap<>();
        for (int i = 0; i < hosts.size(); i++) order.put(hosts.get(i).getHostAddress(), i);

        long total = (long) hosts.size() * ports.size();
        AtomicInteger done = new AtomicInteger();
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        try {
            for (InetAddress host : hosts) {
                for (int port : ports) {
                    pool.execute(() -> {
                        PortResult r = probe(host, port);
                        if (r != null) found.computeIfAbsent(host.getHostAddress(), k -> new ConcurrentLinkedQueue<>()).add(r);
                        int d = done.incrementAndGet();
                        if (progress != null && total > 0) progress.accept((int) (d * 100L / total));
                    });
                }
            }
            pool.shutdown();
            if (!pool.awaitTermination(1, TimeUnit.HOURS)) throw new IllegalStateException("Scan did not finish in time.");
        } finally {
            pool.shutdownNow();
        }

        List<HostResult> results = new ArrayList<>();
        found.forEach((ip, list) -> {
            List<PortResult> sorted = new ArrayList<>(list);
            sorted.sort(Comparator.comparingInt(PortResult::port));
            results.add(new HostResult(ip, List.copyOf(sorted)));
        });
        results.sort(Comparator.comparingInt(h -> order.getOrDefault(h.ip(), Integer.MAX_VALUE)));
        long millis = (System.nanoTime() - start) / 1_000_000;
        return new ScanSummary(List.copyOf(results), hosts.size(), ports.size(), total, millis);
    }

    /** Returns a result if the port accepts a TCP connection, otherwise null (closed or filtered). */
    PortResult probe(InetAddress host, int port) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(host, port), timeoutMs);
            Services.Info info = Services.lookup(port);
            String banner = grabBanners ? readBanner(socket, host, port) : "";
            return new PortResult(port, info.name(), banner, info.risk());
        } catch (IOException e) {
            return null;
        }
    }

    private String readBanner(Socket socket, InetAddress host, int port) {
        try {
            socket.setSoTimeout(Math.min(timeoutMs * 2, 2000));
            if (Services.isPlainHttp(port)) {
                OutputStream out = socket.getOutputStream();
                out.write(("HEAD / HTTP/1.0\r\nHost: " + host.getHostAddress() + "\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
                out.flush();
            }
            InputStream in = socket.getInputStream();
            byte[] buf = new byte[512];
            int n = in.read(buf);
            if (n <= 0) return "";
            String text = new String(buf, 0, n, StandardCharsets.ISO_8859_1);
            if (Services.isPlainHttp(port)) {
                for (String line : text.split("\r?\n")) {
                    if (line.regionMatches(true, 0, "Server:", 0, 7)) return sanitize(line.substring(7));
                }
                return sanitize(text.split("\r?\n", 2)[0]); // status line
            }
            return sanitize(text);
        } catch (IOException e) {
            return ""; // service didn't send anything in time; port is still open
        }
    }

    /** Banners come from untrusted servers: keep printable ASCII only, one line, max 80 chars. */
    static String sanitize(String raw) {
        if (raw == null) return "";
        StringBuilder sb = new StringBuilder();
        for (char c : raw.toCharArray()) sb.append(c >= 0x20 && c <= 0x7e ? c : ' ');
        String s = sb.toString().replaceAll("\\s+", " ").trim();
        return s.length() > 80 ? s.substring(0, 77) + "..." : s;
    }
}
