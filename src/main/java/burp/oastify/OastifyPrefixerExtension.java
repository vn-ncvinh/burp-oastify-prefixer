package burp.oastify;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.UserInterface;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.*;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * VCS Pentest - Oastify Prefixer
 * - Thêm tab cấu hình prefix.
 * - Thay thế domain *.oastify.com -> <prefix>*.oastify.com trong:
 *   + Path: replace trực tiếp
 *   + Query params: URL-decode -> replace -> URL-encode
 *   + Body x-www-form-urlencoded: URL-decode -> replace -> URL-encode
 *   + Header Cookie: URL-decode (name & value) -> replace -> URL-encode
 *   + Header khác: replace trực tiếp trên giá trị
 * - Không thay đổi HttpService (đích kết nối).
 */
public class OastifyPrefixerExtension implements BurpExtension, HttpHandler {

    private MontoyaApi api;

    // Khớp “abc.oastify.com”, không phân biệt hoa thường.
    private static final Pattern DOMAIN_PATTERN =
            Pattern.compile("(?:[a-z0-9-]+\\.)?(?:oastify\\.com|oast\\.(?:pro|live|site|online|fun|me))", Pattern.CASE_INSENSITIVE);

    // Prefix cấu hình ở tab (mặc định)
    private volatile String currentPrefix = "vcspentest.";

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;

        api.extension().setName("VCS Pentest - Oastify Prefixer");
        api.logging().logToOutput("Loaded: VCS Pentest - Oastify Prefixer");

        // Đăng ký HTTP handler
        Http http = api.http();
        http.registerHttpHandler(this);

        // Tạo UI tab
        buildSettingsTab(api.userInterface());
    }

    private void buildSettingsTab(UserInterface ui) {
        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints gc = new GridBagConstraints();
        gc.insets = new Insets(6, 6, 6, 6);
        gc.anchor = GridBagConstraints.WEST;
        gc.fill = GridBagConstraints.HORIZONTAL;

        gc.gridx = 0; gc.gridy = 0;
        JLabel title = new JLabel("Oastify Prefixer Settings");
        title.setFont(title.getFont().deriveFont(Font.BOLD, 14f));
        panel.add(title, gc);

        gc.gridy++;
        panel.add(new JLabel("Custom prefix (ví dụ: vcspentest.)"), gc);

        gc.gridy++;
        JTextField prefixField = new JTextField(currentPrefix, 24);
        panel.add(prefixField, gc);

        gc.gridy++;
        JLabel hint = new JLabel("Sẽ thêm prefix trước mọi domain khớp *.oastify.com, oast.pro, oast.live, oast.site, oast.online, oast.fun, oast.me  (vd: abc.oastify.com → <prefix>abc.oastify.com).");
        hint.setForeground(Color.DARK_GRAY);
        panel.add(hint, gc);

        gc.gridy++;
        JPanel row = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        JButton resetBtn = new JButton("Reset mặc định");
        JLabel live = new JLabel("Đang dùng prefix: " + currentPrefix);
        row.add(resetBtn);
        row.add(live);
        panel.add(row, gc);

        prefixField.getDocument().addDocumentListener(new DocumentListener() {
            private void update() {
                String v = prefixField.getText();
                currentPrefix = (v == null) ? "" : v;
                live.setText("Đang dùng prefix: " + currentPrefix);
            }
            public void insertUpdate(DocumentEvent e) { update(); }
            public void removeUpdate(DocumentEvent e) { update(); }
            public void changedUpdate(DocumentEvent e) { update(); }
        });

        resetBtn.addActionListener(e -> prefixField.setText("vcspentest."));

        ui.registerSuiteTab("Oastify Prefixer", panel);
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        try {
            HttpRequest req = requestToBeSent;

            // Lấy Content-Type gốc để quyết định xử lý body
            String originalContentType = getHeaderValue(req.headers(), "Content-Type");

            boolean changed = false;

            // 1) Path + Query: query decode -> replace -> encode; path replace trực tiếp
            String oldPath = req.path();
            String newPath = processPathAndQuery(oldPath, currentPrefix);
            if (!newPath.equals(oldPath)) {
                req = req.withPath(newPath);
                changed = true;
            }

            // 2) Headers
            List<HttpHeader> updated = new ArrayList<>();
            for (HttpHeader h : req.headers()) {
                String name = h.name();
                String oldVal = h.value();
                String newVal;

                if (name.equalsIgnoreCase("Cookie")) {
                    // Cookie: decode -> replace -> encode cho từng cặp name=value
                    newVal = processCookieHeader(oldVal, currentPrefix);
                } else {
                    // Header khác: replace trực tiếp trên giá trị
                    newVal = addPrefix(oldVal, currentPrefix);
                }

                if (!newVal.equals(oldVal)) {
                    changed = true;
                    updated.add(HttpHeader.httpHeader(name, newVal));
                } else {
                    updated.add(h);
                }
            }
            if (changed) {
                req = req.withUpdatedHeaders(updated);
            }

            // 3) Body
            String oldBody = req.bodyToString();
            String newBody;
            if (isFormUrlEncoded(originalContentType)) {
                // Form: decode -> replace -> encode (giống query)
                newBody = rebuildQueryWithDecodeReplace(oldBody, currentPrefix);
            } else {
                // Các loại khác: replace trực tiếp
                newBody = addPrefix(oldBody, currentPrefix);
            }
            if (!newBody.equals(oldBody)) {
                req = req.withBody(newBody);
                changed = true;
            }

            // Không thay đổi HttpService (đích kết nối).
            return RequestToBeSentAction.continueWith(req);
        } catch (Exception e) {
            api.logging().logToError("OastifyPrefixer error: " + e.getMessage());
            return RequestToBeSentAction.continueWith(requestToBeSent);
        }
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        // Không chỉnh sửa response
        return ResponseReceivedAction.continueWith(responseReceived);
    }

    // ===== Helpers =====

    private static String getHeaderValue(List<HttpHeader> headers, String name) {
        if (headers == null) return null;
        for (HttpHeader h : headers) {
            if (h.name().equalsIgnoreCase(name)) {
                return h.value();
            }
        }
        return null;
    }

    private static boolean isFormUrlEncoded(String contentType) {
        if (contentType == null) return false;
        String ct = contentType.toLowerCase();
        return ct.startsWith("application/x-www-form-urlencoded");
    }

    /** Path + query: path replace trực tiếp; query decode -> replace -> encode. */
    private static String processPathAndQuery(String pathAndQuery, String prefix) {
        if (pathAndQuery == null || pathAndQuery.isEmpty()) return pathAndQuery;

        // Cắt fragment nếu có
        String fragment = "";
        int hashIdx = pathAndQuery.indexOf('#');
        if (hashIdx >= 0) {
            fragment = pathAndQuery.substring(hashIdx); // gồm '#'
            pathAndQuery = pathAndQuery.substring(0, hashIdx);
        }

        int qIdx = pathAndQuery.indexOf('?');
        if (qIdx < 0) {
            String newPathOnly = addPrefix(pathAndQuery, prefix);
            return newPathOnly + fragment;
        }

        String pathOnly = pathAndQuery.substring(0, qIdx);
        String query = pathAndQuery.substring(qIdx + 1);

        String newPathOnly = addPrefix(pathOnly, prefix);
        String newQuery = rebuildQueryWithDecodeReplace(query, prefix);

        return newPathOnly + "?" + newQuery + fragment;
    }

    /** Dùng chung cho query string & body application/x-www-form-urlencoded. */
    private static String rebuildQueryWithDecodeReplace(String query, String prefix) {
        if (query == null || query.isEmpty()) return query;

        StringBuilder out = new StringBuilder();
        int start = 0;
        while (start <= query.length()) {
            int amp = query.indexOf('&', start);
            String pair = (amp >= 0) ? query.substring(start, amp) : query.substring(start);
            if (pair.isEmpty() && amp < 0) break;

            String name, value;
            int eq = pair.indexOf('=');
            if (eq >= 0) {
                name = pair.substring(0, eq);
                value = pair.substring(eq + 1);
            } else {
                name = pair;
                value = null;
            }

            String decodedName = safeUrlDecode(name);
            String decodedValue = (value != null) ? safeUrlDecode(value) : null;

            decodedName = addPrefix(decodedName, prefix);
            if (decodedValue != null) decodedValue = addPrefix(decodedValue, prefix);

            String encName = safeUrlEncode(decodedName);
            String encValue = (decodedValue != null) ? safeUrlEncode(decodedValue) : null;

            if (out.length() > 0) out.append('&');
            out.append(encName);
            if (encValue != null) out.append('=').append(encValue);

            if (amp < 0) break;
            start = amp + 1;
        }
        return out.toString();
    }

    /** Xử lý header Cookie: tách theo ';', với từng name=value: decode -> replace -> encode. */
    private static String processCookieHeader(String cookieHeader, String prefix) {
        if (cookieHeader == null || cookieHeader.isEmpty()) return cookieHeader;

        String[] parts = cookieHeader.split(";");
        StringBuilder out = new StringBuilder();

        for (String p : parts) {
            String part = p.trim();
            if (part.isEmpty()) continue;

            String name;
            String value;
            int eq = part.indexOf('=');
            if (eq >= 0) {
                name = part.substring(0, eq);
                value = part.substring(eq + 1);
            } else {
                // Không có '=' — replace trực tiếp toàn bộ token
                String replaced = addPrefix(part, prefix);
                if (out.length() > 0) out.append("; ");
                out.append(replaced);
                continue;
            }

            boolean quoted = value.length() >= 2 && value.startsWith("\"") && value.endsWith("\"");
            String rawVal = quoted ? value.substring(1, value.length() - 1) : value;

            // Decode -> replace -> encode cho name & value
            String decName = safeUrlDecode(name);
            String decVal  = safeUrlDecode(rawVal);

            decName = addPrefix(decName, prefix);
            decVal  = addPrefix(decVal,  prefix);

            String encName = safeCookieEncode(decName);
            String encVal  = safeCookieEncode(decVal);

            if (out.length() > 0) out.append("; ");
            out.append(encName).append("=").append(quoted ? "\"" + encVal + "\"" : encVal);
        }

        return out.toString();
    }

    /** URL-decode cho component query/form/cookie (dấu '+' -> space). */
    private static String safeUrlDecode(String s) {
        try {
            return URLDecoder.decode(s, StandardCharsets.UTF_8.name());
        } catch (Exception ignored) {
            return s;
        }
    }

    /** URL-encode cho component query/form (chuyển space thành %20 để tránh '+'). */
    private static String safeUrlEncode(String s) {
        try {
            String enc = URLEncoder.encode(s, StandardCharsets.UTF_8.name());
            return enc.replace("+", "%20");
        } catch (Exception ignored) {
            return s;
        }
    }

    /** URL-encode cho cookie component (giống safeUrlEncode). */
    private static String safeCookieEncode(String s) {
        try {
            String enc = URLEncoder.encode(s, StandardCharsets.UTF_8.name());
            return enc.replace("+", "%20");
        } catch (Exception ignored) {
            return s;
        }
    }

    /** Thêm prefix vào mọi chuỗi khớp DOMAIN_PATTERN. */
    private static String addPrefix(String input, String prefix) {
        if (input == null || input.isEmpty()) return input;
        if (prefix == null) prefix = "";
        Matcher m = DOMAIN_PATTERN.matcher(input);
        StringBuffer sb = new StringBuffer();
        while (m.find()) {
            String matched = m.group(0); // vd: abc.oastify.com
            String replacement = prefix + matched;
            m.appendReplacement(sb, Matcher.quoteReplacement(replacement));
        }
        m.appendTail(sb);
        return sb.toString();
    }
}
