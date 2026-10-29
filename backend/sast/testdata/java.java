import java.io.File;
import java.io.ObjectInputStream;
import java.net.URL;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.Statement;
import javax.crypto.Cipher;
import javax.net.ssl.SSLSession;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilderFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

public class Fixture {

    void sqlCases(Connection conn, Statement st, String id) throws Exception {
        // ruleid: ck-java-sql-built-from-strings
        st.executeQuery("SELECT * FROM users WHERE id = " + id);

        String q = String.format("SELECT * FROM users WHERE name = '%s'", id);
        // ruleid: ck-java-sql-built-from-strings
        java.sql.ResultSet rs = st.executeQuery(q);

        // ok: ck-java-sql-built-from-strings
        conn.prepareStatement("SELECT * FROM users WHERE id = ?");
    }

    void servletCases(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String tool = request.getParameter("tool");
        // ruleid: ck-java-command-from-request
        Runtime.getRuntime().exec(tool);
        // ok: ck-java-command-from-request
        Runtime.getRuntime().exec("git --version");

        String name = request.getParameter("name");
        // ruleid: ck-java-path-from-request
        File f = new File("/srv/files/" + name);
        // ok: ck-java-path-from-request
        File g = new File("/srv/files/report.pdf");

        String next = request.getParameter("next");
        // ruleid: ck-java-open-redirect
        response.sendRedirect(next);
        // ok: ck-java-open-redirect
        response.sendRedirect("/home");
    }

    @GetMapping("/fetch")
    public String fetch(@RequestParam("url") String url) throws Exception {
        // ruleid: ck-java-ssrf-from-request
        new URL(url).openStream();
        // ok: ck-java-ssrf-from-request
        new URL("https://api.example.com/users/" + url).openStream();
        // ruleid: ck-java-path-from-request
        Paths.get(url);
        return "ok";
    }

    void deserializationCases(java.io.InputStream in) throws Exception {
        // ruleid: ck-java-unsafe-deserialization
        ObjectInputStream ois = new ObjectInputStream(in);
    }

    void xxeUnsafe() throws Exception {
        // ruleid: ck-java-xxe
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.newDocumentBuilder();
    }

    void xxeSafe() throws Exception {
        // ok: ck-java-xxe
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        dbf.newDocumentBuilder();
    }

    // ruleid: ck-java-tls-verification-disabled
    public boolean verify(String host, SSLSession session) { return true; }

    void cryptoCases() throws Exception {
        // ruleid: ck-java-weak-cipher
        Cipher.getInstance("DES/CBC/PKCS5Padding");
        // ruleid: ck-java-weak-cipher
        Cipher.getInstance("AES");
        // ok: ck-java-weak-cipher
        Cipher.getInstance("AES/GCM/NoPadding");

        // ruleid: ck-java-weak-hash
        MessageDigest.getInstance("MD5");
        // ok: ck-java-weak-hash
        MessageDigest.getInstance("SHA-256");
    }
}
