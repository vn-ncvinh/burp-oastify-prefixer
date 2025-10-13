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

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class OastifyPrefixerExtension implements BurpExtension, HttpHandler {

    private MontoyaApi api;
    // Khớp cả “abc.oastify.com”, không phân biệt hoa thường.
    private static final Pattern DOMAIN_PATTERN =
            Pattern.compile("([a-z0-9]+)\\.oastify\\.com", Pattern.CASE_INSENSITIVE);

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;

        // Đặt tên, mô tả cho extension
        api.extension().setName("VCS Pentest - Oastify Prefixer");
        api.logging().logToOutput("Loaded: VCS Pentest - Oastify Prefixer");

        // Đăng ký HTTP handler để chặn & chỉnh sửa mọi request đi qua các tool của Burp
        Http http = api.http();
        http.registerHttpHandler(this);
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        try {
            HttpRequest req = requestToBeSent;

            boolean changed = false;

            // 1) URL/path (bao gồm query) – thay thế trong path
            String oldPath = req.path();
            String newPath = addPrefix(oldPath);
            if (!newPath.equals(oldPath)) {
                req = req.withPath(newPath);
                changed = true;
            }

            // 2) Headers – thay thế trong từng giá trị header
            List<HttpHeader> updated = new ArrayList<>();
            for (HttpHeader h : req.headers()) {
                String oldVal = h.value();
                String newVal = addPrefix(oldVal);
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

            // 3) Body – thay thế trong body dạng chuỗi
            // (Nếu body nhị phân, bodyToString vẫn trả về chuỗi; nếu không đổi thì giữ nguyên.)
            String oldBody = req.bodyToString();
            String newBody = addPrefix(oldBody);
            if (!newBody.equals(oldBody)) {
                req = req.withBody(newBody);
                changed = true;
            }

            // Lưu ý: ta không đổi đích kết nối (HttpService). Nếu bạn cũng muốn chuyển host
            // đích khi Header Host bị đổi, hãy bổ sung logic withService(...) tương ứng.

            return RequestToBeSentAction.continueWith(req);
        } catch (Exception e) {
            // Có lỗi thì tiếp tục request gốc cho an toàn
            api.logging().logToError("OastifyPrefixer error: " + e.getMessage());
            return RequestToBeSentAction.continueWith(requestToBeSent);
        }
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        // Không chỉnh sửa response
        return ResponseReceivedAction.continueWith(responseReceived);
    }

    // Hàm thêm prefix 'vcspentest.' vào mọi chuỗi khớp DOMAIN_PATTERN
    private static String addPrefix(String input) {
        if (input == null || input.isEmpty()) return input;
        Matcher m = DOMAIN_PATTERN.matcher(input);
        StringBuffer sb = new StringBuffer();
        while (m.find()) {
            String matched = m.group(0); // ví dụ: abc.oastify.com
            String replacement = "vcspentest." + matched;
            m.appendReplacement(sb, Matcher.quoteReplacement(replacement));
        }
        m.appendTail(sb);
        return sb.toString();
    }
}
