package burp.oastify;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.BurpExtension;
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
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class OastifyPrefixerExtension implements BurpExtension, HttpHandler {

    private MontoyaApi api;

    // Khớp cả “abc.oastify.com”, không phân biệt hoa thường.
    private static final Pattern DOMAIN_PATTERN =
            Pattern.compile("([a-z0-9]+)\\.oastify\\.com", Pattern.CASE_INSENSITIVE);

    // Prefix hiện tại do người dùng cấu hình trên tab (mặc định như bản cũ)
    private volatile String currentPrefix = "vcspentest.";

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;

        api.extension().setName("VCS Pentest - Oastify Prefixer");
        api.logging().logToOutput("Loaded: VCS Pentest - Oastify Prefixer");

        // Đăng ký HTTP handler
        Http http = api.http();
        http.registerHttpHandler(this);

        // Tạo UI tab cho phép custom prefix
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
        JLabel hint = new JLabel("Chuỗi này sẽ được thêm trước mọi domain khớp *.oastify.com (ví dụ: abc.oastify.com → <prefix>abc.oastify.com).");
        hint.setForeground(Color.DARK_GRAY);
        panel.add(hint, gc);

        gc.gridy++;
        JPanel buttonRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        JButton resetBtn = new JButton("Reset về mặc định");
        JLabel liveStatus = new JLabel("Đang dùng prefix: " + currentPrefix);
        buttonRow.add(resetBtn);
        buttonRow.add(liveStatus);
        panel.add(buttonRow, gc);

        // Lắng nghe thay đổi để cập nhật ngay
        prefixField.getDocument().addDocumentListener(new DocumentListener() {
            private void update() {
                String newVal = prefixField.getText();
                if (newVal == null) newVal = "";
                currentPrefix = newVal;
                liveStatus.setText("Đang dùng prefix: " + currentPrefix);
            }
            public void insertUpdate(DocumentEvent e) { update(); }
            public void removeUpdate(DocumentEvent e) { update(); }
            public void changedUpdate(DocumentEvent e) { update(); }
        });

        // Reset về mặc định
        resetBtn.addActionListener(e -> {
            prefixField.setText("vcspentest.");
            // DocumentListener sẽ tự cập nhật currentPrefix + label
        });

        // Đăng ký tab vào Burp
        ui.registerSuiteTab("Oastify Prefixer", panel);
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        try {
            HttpRequest req = requestToBeSent;

            boolean changed = false;

            // 1) Path (bao gồm query)
            String oldPath = req.path();
            String newPath = addPrefix(oldPath, currentPrefix);
            if (!newPath.equals(oldPath)) {
                req = req.withPath(newPath);
                changed = true;
            }

            // 2) Headers
            List<HttpHeader> updated = new ArrayList<>();
            for (HttpHeader h : req.headers()) {
                String oldVal = h.value();
                String newVal = addPrefix(oldVal, currentPrefix);
                if (!newVal.equals(oldVal)) {
                    changed = true;
                    updated.add(HttpHeader.httpHeader(h.name(), newVal));
                } else {
                    updated.add(h);
                }
            }
            if (changed) {
                req = req.withUpdatedHeaders(updated);
            }

            // 3) Body
            String oldBody = req.bodyToString();
            String newBody = addPrefix(oldBody, currentPrefix);
            if (!newBody.equals(oldBody)) {
                req = req.withBody(newBody);
                changed = true;
            }

            // Không đổi HttpService (đích kết nối).
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

    // Hàm thêm prefix được cấu hình vào mọi chuỗi khớp DOMAIN_PATTERN
    private static String addPrefix(String input, String prefix) {
        if (input == null || input.isEmpty()) return input;
        if (prefix == null) prefix = "";
        Matcher m = DOMAIN_PATTERN.matcher(input);
        StringBuffer sb = new StringBuffer();
        while (m.find()) {
            String matched = m.group(0); // ví dụ: abc.oastify.com
            String replacement = prefix + matched;
            m.appendReplacement(sb, Matcher.quoteReplacement(replacement));
        }
        m.appendTail(sb);
        return sb.toString();
    }
}
