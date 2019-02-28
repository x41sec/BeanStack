package burp;

import burp.Config;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.concurrent.*;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.Set;
import javax.swing.*;

public class BurpExtender implements IBurpExtender, IHttpListener {
	private final String RESPONSE_NOMATCH = "No matches found.";

	// Dictionary mapping request body hashes to response bodies
	private Map<ByteBuffer, String> HttpReqMemoization;

	// Hashes of issues to avoid duplicates
	private Set<ByteBuffer> AlreadyFingerprinted;

	// Background thread that does the lookups
	private ExecutorService threader;

	MessageDigest md5;

	private boolean showed429AlertWithApiKey = false;
	private boolean showed429Alert = false;

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
        GlobalVars.callbacks = callbacks;

        GlobalVars.callbacks.setExtensionName(GlobalVars.EXTENSION_NAME);
        GlobalVars.callbacks.registerHttpListener(this);

		this.AlreadyFingerprinted = new HashSet<ByteBuffer>();
		this.HttpReqMemoization = new HashMap<ByteBuffer, String>();

		try {
			this.md5 = MessageDigest.getInstance("MD5");
		}
		catch (java.security.NoSuchAlgorithmException e) {
			e.printStackTrace(new java.io.PrintStream(GlobalVars.debug));
		}

		this.threader = Executors.newSingleThreadExecutor();

		GlobalVars.config = new Config();
		GlobalVars.config.printSettings();

		GlobalVars.callbacks.registerContextMenuFactory(new ContextMenuSettingsOptionAdder());

		// Check if we already checked this URL
		IScanIssue[] issuelist = GlobalVars.callbacks.getScanIssues("");
		for (IScanIssue si : issuelist) {
			// Only add fingerprinting items
			if (si.getIssueName().equals(GlobalVars.config.getString("issuetitle"))) {
				AlreadyFingerprinted.add(hashScanIssue(si));
			}
		}
		GlobalVars.debug("Found " + Integer.toString(AlreadyFingerprinted.size()) + " fingerprints in already-existing issues (to avoid creating duplicate issues).");
    }

	private ByteBuffer hashScanIssue(IScanIssue si) {
		return ByteBuffer.wrap(md5.digest((si.getUrl().toString() + "\n" + si.getIssueDetail()).getBytes()));
	}

	private String checktrace(String stacktrace) {
		try {
			byte[] b_stacktrace = stacktrace.getBytes("UTF-8");
			ByteBuffer tracedigest = ByteBuffer.wrap(md5.digest(b_stacktrace));
			if (HttpReqMemoization.containsKey(tracedigest)) {
				GlobalVars.debug("Trace found in memoization table, returning stored response.");
				return HttpReqMemoization.get(tracedigest);
			}

			GlobalVars.debug("Submitting a trace: " + stacktrace.substring(0, 50));

			URL url = new URL(GlobalVars.config.getString("apiurl"));
			HttpURLConnection req = (HttpURLConnection) url.openConnection();
			req.setRequestMethod("POST");
			req.setRequestProperty("User-Agent", GlobalVars.USER_AGENT);

			// write the post body
			req.setDoOutput(true);
			java.io.OutputStream os = req.getOutputStream();
			if (GlobalVars.config.getString("apikey").length() > 4) {
				os.write("apikey=".getBytes("UTF-8"));
				os.write(GlobalVars.config.getString("apikey").getBytes("UTF-8"));
				os.write("&".getBytes("UTF-8"));
			}
			os.write("trace=".getBytes("UTF-8"));
			os.write(java.net.URLEncoder.encode(stacktrace).getBytes("UTF-8"));
			os.close();

			String response;

			if (req.getResponseCode() == 204) {
				response = null;
			}
			else if (req.getResponseCode() == 429) {
				if (GlobalVars.config.getString("apikey").length() > 4) {
					GlobalVars.debug("HTTP request failed: 429 (with API key)");
					// An API key is set
					String msg = "Your API key ran out of requests. For bulk\nlookup of stack traces, please contact us.";
					if ( ! showed429AlertWithApiKey) {
						// Only alert once; nobody wants to be annoyed by this stuff
						showed429AlertWithApiKey = true;

						JOptionPane.showMessageDialog(null, msg, "Burp Extension" + GlobalVars.EXTENSION_NAME_SHORT, JOptionPane.ERROR_MESSAGE);
					}
					GlobalVars.callbacks.issueAlert(msg);
				}
				else {
					GlobalVars.debug("HTTP request failed: 429 (no API key set)");
					if ( ! showed429Alert) {
						// Only alert once; nobody wants to be annoyed by this stuff
						showed429Alert = true;

						// No API key set. Prompt for one and mention where they can get one.
						String result = JOptionPane.showInputDialog(Config.getBurpFrame(),
							"You hit the request limit for " + GlobalVars.EXTENSION_NAME_SHORT + ". "
								+ "Please register on " + GlobalVars.REGURL + "\nfor a free API key. If you already have an API key, please enter it here.",
							GlobalVars.EXTENSION_NAME + " API key",
							JOptionPane.PLAIN_MESSAGE
						);
						if (result.length() > 0) {
							GlobalVars.config.put("apikey", result);
							GlobalVars.debug("apikey configured after prompt");
						}
					}
					else {
						GlobalVars.callbacks.issueAlert("Extension " + GlobalVars.EXTENSION_NAME_SHORT + ": You hit the request limit for the API. "
							+ "Please register for a free API key to continue, or see our website for the current limit without API key.");
					}
				}
				return null;
			}
			if (req.getResponseCode() == 401) {
				GlobalVars.debug("HTTP request failed: invalid API key (401)");

				// N.B. we thread this, but due to the thread pool of 1, further requests will just be queued, so we won't get dialogs on top of each other.
				// Further requests will also automatically use the API key if the user enters one here.

				String result = JOptionPane.showInputDialog(Config.getBurpFrame(),
					"Your API key is invalid.\nIf you want to use a different API key, please enter it here.",
					//GlobalVars.EXTENSION_NAME + " API key invalid",
					GlobalVars.config.getString("apikey")
				);
				if (result != null && result.length() > 0) {
					GlobalVars.config.put("apikey", result);
				}
				else {
					// If they cancelled the dialog or emptied it, override the string so they don't get more of those alerts.
					GlobalVars.config.put("apikey", "none");
				}

				return null;
			}
			else if (req.getResponseCode() != 200) {
				GlobalVars.callbacks.issueAlert("Extension " + GlobalVars.EXTENSION_NAME + ": HTTP request for fingerprinting a Java stack trace failed with status " + Integer.toString(req.getResponseCode()));

				GlobalVars.debug("HTTP request failed with status " + Integer.toString(req.getResponseCode()));

				return null;
			}
			else {
				response = readFully(req.getInputStream()).toString("UTF-8");
				if (response.equals(RESPONSE_NOMATCH)) {
					response = null;
				}
			}

			GlobalVars.debug("Result: " + response.substring(0, 30));

			HttpReqMemoization.put(tracedigest, response);

			return response;
		}
		catch (java.io.UnsupportedEncodingException e) {
			e.printStackTrace(new java.io.PrintStream(GlobalVars.debug));
		}
		catch (java.io.IOException e) {
			e.printStackTrace(new java.io.PrintStream(GlobalVars.debug));
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

		Instant outerstart = Instant.now();

		if (messageIsRequest)
			return;

		if ( ! GlobalVars.config.getBoolean("enable")) {
			GlobalVars.debug("Note: " + GlobalVars.EXTENSION_NAME_SHORT + " plugin is disabled.");
			return;
		}

		threader.submit(new Runnable() {
			public void run() {
				GlobalVars.debug("Started thread...");
				Instant start = Instant.now();

				// Basically the pattern checks /\s[valid class path chars].[more valid class chars]([filename chars].java:1234)/
				Pattern pattern = Pattern.compile("\\s([a-zA-Z0-9\\.\\$]{1,300}\\.[a-zA-Z0-9\\.\\$]{1,300})\\(([a-zA-Z0-9]{1,300})\\.java:\\d{1,6}\\)");
				Matcher matcher = null;

				try {
					matcher = pattern.matcher(new String(baseRequestResponse.getResponse(), "UTF-8"));
				}
				catch (java.io.UnsupportedEncodingException e) {
					e.printStackTrace(new java.io.PrintStream(GlobalVars.debug));
				}

				// Reconstruct the trace (since who knows what might be in between the lines, e.g. "&lt;br&gt;")
				String stacktrace = "";
				while (matcher.find()) {
					GlobalVars.debug(matcher.group(0));
					if ( ! matcher.group(1).contains(".")) {
						// Enforce a dot in the full class name (sanity check)
						continue;
					}
					if ( ! (matcher.group(1).indexOf(matcher.group(2) + "$") >= 2
							|| matcher.group(1).indexOf(matcher.group(2) + ".") >= 2)) {
						// TODO is this check too strict?
						/*
java.lang.NullPointerException
	at burp.ConfigMenu.run(Config.java:38)
	at java.desktop/java.awt.event.InvocationEvent.dispatch(InvocationEvent.java:313)
	at java.desktop/java.awt.EventQueue.dispatchEventImpl(EventQueue.java:770)
	at java.desktop/java.awt.EventQueue$4.run(EventQueue.java:721)
	at java.desktop/java.awt.EventQueue$4.run(EventQueue.java:715)
	at java.base/java.security.AccessController.doPrivileged(Native Method)
	at java.base/java.security.ProtectionDomain$JavaSecurityAccessImpl.doIntersectionPrivilege(ProtectionDomain.java:85)
	at java.desktop/java.awt.EventQueue.dispatchEvent(EventQueue.java:740)
	at java.desktop/java.awt.EventDispatchThread.pumpOneEventForFilters(EventDispatchThread.java:203)
	at java.desktop/java.awt.EventDispatchThread.pumpEventsForFilter(EventDispatchThread.java:124)
	at java.desktop/java.awt.EventDispatchThread.pumpEventsForHierarchy(EventDispatchThread.java:113)
	at java.desktop/java.awt.EventDispatchThread.pumpEvents(EventDispatchThread.java:109)
	at java.desktop/java.awt.EventDispatchThread.pumpEvents(EventDispatchThread.java:101)
	at java.desktop/java.awt.EventDispatchThread.run(EventDispatchThread.java:90)
						 */
						// The filename should occur in the first part, either followed by a dollar or by a dot,
						// and it usually does not start with that (so match from position 2 onwards, because
						// there should be at least 1 character and a dot, like "a.test.run(test.java:42)").
						continue;
					}
					stacktrace += matcher.group() + "\n";
				}

				GlobalVars.debug("Checked page for traces in " + String.valueOf(Duration.between(start, Instant.now()).toMillis()) + "ms");
				start = Instant.now();

				// Check the trace with our back-end
				String result = checktrace(stacktrace);

				GlobalVars.debug("checktrace() returned in " + String.valueOf(Duration.between(start, Instant.now()).toMillis()) + "ms");

				// Either some error or no results
				if (result == null) {
					return;
				}

				IScanIssue issue = new CustomScanIssue(
							baseRequestResponse.getHttpService(),
							GlobalVars.callbacks.getHelpers().analyzeRequest(baseRequestResponse).getUrl(),
							new IHttpRequestResponse[] { baseRequestResponse },
							GlobalVars.config.getString("issuetitle"),
							result,
							"Information");

				ByteBuffer hash = hashScanIssue(issue);

				if ( ! AlreadyFingerprinted.add(hash)) {
					// We already created an issue for this, avoid creating a duplicate.
					if (GlobalVars.config.getBoolean("logdups")) {
						GlobalVars.debug("Issue already exists, but logging anyway because logdups config is set.");
					}
					else {
						GlobalVars.debug("Issue already exists! Avoiding duplicate.");
						return;
					}
				}

				GlobalVars.callbacks.addScanIssue(issue);
			}
		});

		GlobalVars.debug("Burp callback handled in " + String.valueOf(Duration.between(outerstart, Instant.now()).toMillis()) + "ms");
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

