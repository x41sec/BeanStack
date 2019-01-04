package burp;

import java.net.HttpURLConnection;
import java.net.URL;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.nio.ByteBuffer;

public class BurpExtender implements IBurpExtender, IHttpListener {
	// TODO find a way to do settings (at least for the debug flag)
	private final String API_URL = "http://18.184.145.100:8880/";
	private final String RESPONSE_NOMATCH = "No matches found.";
	private final String EXTENSION_NAME = "Java Fingerprinting using Stack Traces";
	private final String ISSUE_TITLE = "Java Fingerprinter";
	private final boolean DEBUG = true;

    private IBurpExtenderCallbacks callbacks;

	// Dictionary mapping request body hashes to response bodies
	private Map<ByteBuffer, String> HttpReqMemoization;

	// Hashes of issues to avoid duplicates
	private Set<ByteBuffer> AlreadyFingerprinted;

	MessageDigest md5;

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
		if (DEBUG) {
			System.out.println(EXTENSION_NAME + " extension's constructor called (with debug=true, compile-time).");
		}

        this.callbacks = callbacks;
        
        callbacks.setExtensionName(EXTENSION_NAME);
        callbacks.registerHttpListener(this);

		this.AlreadyFingerprinted = new HashSet<ByteBuffer>();
		this.HttpReqMemoization = new HashMap<ByteBuffer, String>();

		try {
			this.md5 = MessageDigest.getInstance("MD5");
		}
		catch (java.security.NoSuchAlgorithmException e) {
			e.printStackTrace(new java.io.PrintStream(System.out));
		}

		// Check if we already checked this URL
		IScanIssue[] issuelist = callbacks.getScanIssues("");
		for (IScanIssue si : issuelist) {
			// Only add fingerprinting items
			if (si.getIssueName().equals(ISSUE_TITLE)) {
				AlreadyFingerprinted.add(hashScanIssue(si));
			}
		}
		if (DEBUG) {
			System.out.println("Found " + Integer.toString(AlreadyFingerprinted.size()) + " fingerprints (for which we will avoid creating duplicate issues).");
		}
    }

	private ByteBuffer hashScanIssue(IScanIssue si) {
		return ByteBuffer.wrap(md5.digest((si.getUrl().toString() + "\n" + si.getIssueDetail()).getBytes()));
	}

	private String checktrace(String stacktrace) {
		try {
			byte[] b_stacktrace = stacktrace.getBytes("UTF-8");
			ByteBuffer tracedigest = ByteBuffer.wrap(md5.digest(b_stacktrace));
			if (HttpReqMemoization.containsKey(tracedigest)) {
				if (DEBUG) {
					System.out.println("Trace found in memoization table, returning stored response.");
				}
				return HttpReqMemoization.get(tracedigest);
			}

			if (DEBUG) {
				System.out.println("Submitting a trace: " + stacktrace.substring(0, 50));
			}

			URL url = new URL(API_URL);
			HttpURLConnection req = (HttpURLConnection) url.openConnection();
			req.setRequestMethod("POST");
			//req.setRequestProperty("Content-Type", "text/plain");

			// write the post body
			req.setDoOutput(true);
			java.io.OutputStream os = req.getOutputStream();
			os.write("trace=".getBytes("UTF-8"));
			os.write(java.net.URLEncoder.encode(stacktrace).getBytes("UTF-8"));
			os.close();

			if (req.getResponseCode() != 200) {
				callbacks.issueAlert("Extension " + EXTENSION_NAME + ": HTTP request for fingerprinting a Java stack trace failed with status " + Integer.toString(req.getResponseCode()));

				if (DEBUG) {
					System.out.println("HTTP request failed with status " + Integer.toString(req.getResponseCode()));
				}

				return null;
			}

			String response = readFully(req.getInputStream()).toString("UTF-8");

			if (response.equals(RESPONSE_NOMATCH)) {
				response = null;
			}

			if (DEBUG) {
				System.out.println("Result: " + response.substring(0, 30));
			}

			HttpReqMemoization.put(tracedigest, response);

			return response;
		}
		catch (java.io.UnsupportedEncodingException e) {
			e.printStackTrace(new java.io.PrintStream(System.out));
		}
		catch (java.io.IOException e) {
			e.printStackTrace(new java.io.PrintStream(System.out));
		}

		return null;
	}

    private java.io.ByteArrayOutputStream readFully(java.io.InputStream inputStream) throws java.io.IOException {
        java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        int length = 0;
        while ((length = inputStream.read(buffer)) != -1) {
            baos.write(buffer, 0, length);
        }
        return baos;
    }

    @Override
	public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse baseRequestResponse) {
		// TODO we should try to match a few versions of the response, like urldecoded, str_replace(r'\$', '$'), maybe base64-decode?, and probably others
		// TODO and maybe also the request instead of only the response?

		if (messageIsRequest)
			return;

		// Basically the pattern checks /\s[valid class path chars].[more valid class chars]([filename chars].java:1234)/
		Pattern pattern = Pattern.compile("\\s([a-zA-Z0-9\\.\\$]{1,300}\\.[a-zA-Z0-9\\.\\$]{1,300})\\(([a-zA-Z0-9]{1,300})\\.java:\\d{1,6}\\)");
		Matcher matcher = null;

		try {
			matcher = pattern.matcher(new String(baseRequestResponse.getResponse(), "UTF-8"));
		}
		catch (java.io.UnsupportedEncodingException e) {
			e.printStackTrace(new java.io.PrintStream(System.out));
		}

		// Reconstruct the trace (since who knows what might be in between the lines, e.g. "&lt;br&gt;")
		String stacktrace = "";
		while (matcher.find()) {
			if ( ! matcher.group(1).contains(".")) {
				// I have yet to see a stack trace without a . in the first part
				continue;
			}
			if ( ! (matcher.group(1).indexOf(matcher.group(2) + "$") >= 2
				    || matcher.group(1).indexOf(matcher.group(2) + ".") >= 2)) {
				// The filename should occur in the first part, either followed by a dollar or by a dot,
				// and it usually does not start with that (so match from position 2 onwards, because
				// there should be at least 1 character and a dot, like "a.test.run(test.java:42)").
				continue;
			}
			stacktrace += matcher.group() + "\n";
		}

		// Check the trace with our back-end
		String result = checktrace(stacktrace);

		// Either some error or no results
		if (result == null) {
			return;
		}

		IScanIssue issue = new CustomScanIssue(
                    baseRequestResponse.getHttpService(),
                    callbacks.getHelpers().analyzeRequest(baseRequestResponse).getUrl(), 
                    new IHttpRequestResponse[] { baseRequestResponse }, 
                    ISSUE_TITLE,
                    result,
                    "Information");

		ByteBuffer hash = hashScanIssue(issue);

		if ( ! AlreadyFingerprinted.add(hash)) {
			// We already created an issue for this, avoid creating a duplicate.
			if (DEBUG) {
				System.out.println("Issue already exists! Avoiding duplicate.");
			}
			return;
		}

		this.callbacks.addScanIssue(issue);
	}
}

// From the example project
class CustomScanIssue implements IScanIssue {
    private IHttpService httpService;
    private URL url;
    private IHttpRequestResponse[] httpMessages;
    private String name;
    private String detail;
    private String severity;

    public CustomScanIssue(
            IHttpService httpService,
            URL url, 
            IHttpRequestResponse[] httpMessages, 
            String name,
            String detail,
            String severity) {
        this.httpService = httpService;
        this.url = url;
        this.httpMessages = httpMessages;
        this.name = name;
        this.detail = detail;
        this.severity = severity;
    }
    
    @Override
    public URL getUrl() {
        return url;
    }

    @Override
    public String getIssueName() {
        return name;
    }

    @Override
    public int getIssueType() {
        return 0;
    }

    @Override
    public String getSeverity() {
        return severity;
    }

    @Override
    public String getConfidence() {
        return "Firm"; // TODO Would we say the confidence is complete? It can be Complete, Firm, or Tentative.
    }

    @Override
    public String getIssueBackground() {
        return null;
    }

    @Override
    public String getRemediationBackground() {
        return null;
    }

    @Override
    public String getIssueDetail() {
        return detail;
    }

    @Override
    public String getRemediationDetail() {
        return null;
    }

    @Override
    public IHttpRequestResponse[] getHttpMessages() {
        return httpMessages;
    }

    @Override
    public IHttpService getHttpService() {
        return httpService;
    }
}

