package netscan;

import java.util.Map;

/** Well-known service names, with a security note for services that are risky to expose. */
public final class Services {
    public record Info(String name, String risk) { }

    private static final Map<Integer, Info> KNOWN = Map.ofEntries(
            Map.entry(21, new Info("FTP", "Sends passwords in clear text; use SFTP instead")),
            Map.entry(22, new Info("SSH", null)),
            Map.entry(23, new Info("Telnet", "Unencrypted remote login; disable and use SSH")),
            Map.entry(25, new Info("SMTP", null)),
            Map.entry(53, new Info("DNS", null)),
            Map.entry(80, new Info("HTTP", null)),
            Map.entry(110, new Info("POP3", "Unencrypted mail login; prefer POP3S (995)")),
            Map.entry(135, new Info("MS RPC", "Should not be reachable from untrusted networks")),
            Map.entry(139, new Info("NetBIOS", "Legacy file sharing; block at the firewall")),
            Map.entry(143, new Info("IMAP", "Unencrypted mail login; prefer IMAPS (993)")),
            Map.entry(389, new Info("LDAP", "Directory queries in clear text; prefer LDAPS (636)")),
            Map.entry(443, new Info("HTTPS", null)),
            Map.entry(445, new Info("SMB", "File sharing; a common ransomware entry point, never expose to the internet")),
            Map.entry(587, new Info("SMTP submission", null)),
            Map.entry(636, new Info("LDAPS", null)),
            Map.entry(993, new Info("IMAPS", null)),
            Map.entry(995, new Info("POP3S", null)),
            Map.entry(1433, new Info("Microsoft SQL Server", "Database should only be reachable from app servers")),
            Map.entry(1521, new Info("Oracle DB", "Database should only be reachable from app servers")),
            Map.entry(3306, new Info("MySQL", "Database should only be reachable from app servers")),
            Map.entry(3389, new Info("RDP", "Remote Desktop is heavily brute-forced; put it behind a VPN")),
            Map.entry(5432, new Info("PostgreSQL", "Database should only be reachable from app servers")),
            Map.entry(5900, new Info("VNC", "Remote control, often weakly protected; restrict access")),
            Map.entry(6379, new Info("Redis", "Often runs without authentication; never expose")),
            Map.entry(8000, new Info("HTTP (alt)", null)),
            Map.entry(8080, new Info("HTTP proxy / alt", null)),
            Map.entry(8443, new Info("HTTPS (alt)", null)),
            Map.entry(9100, new Info("Printer (JetDirect)", "Raw printing; restrict to the print server")),
            Map.entry(27017, new Info("MongoDB", "Often runs without authentication; never expose")));

    private Services() { }

    public static Info lookup(int port) {
        return KNOWN.getOrDefault(port, new Info("unknown", null));
    }

    /** Ports where the server waits for the client, so we send a harmless HTTP HEAD to get a banner. */
    static boolean isPlainHttp(int port) {
        return port == 80 || port == 8000 || port == 8008 || port == 8080 || port == 8888;
    }
}
