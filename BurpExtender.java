package burp;

import burp.Blake2b;
import burp.Config;
import com.cedarsoftware.util.io.JsonReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
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
	// Dictionary mapping request body hashes to response bodies
	private Map<ByteBuffer, String> HttpReqMemoization;

	// Hashes of issues to avoid duplicates
	private Set<ByteBuffer> AlreadyFingerprinted;

	// Background thread that does the lookups
	private ExecutorService threader;

	final Blake2b blake2b = Blake2b.Digest.newInstance(16);

	private boolean showed429AlertWithApiKey = false;
	private boolean showed429Alert = false;

	final String htmlindent = "&nbsp;&nbsp;&nbsp;";
	final String CRLF = "\r\n";

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
        GlobalVars.callbacks = callbacks;

        GlobalVars.callbacks.setExtensionName(GlobalVars.EXTENSION_NAME);
        GlobalVars.callbacks.registerHttpListener(this);

		this.AlreadyFingerprinted = new HashSet<ByteBuffer>();
		this.HttpReqMemoization = new HashMap<ByteBuffer, String>();

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

	private String cvssToBurpSeverity(float cvss) {
		// Based on https://www.first.org/cvss/specification-document#5-Qualitative-Severity-Rating-Scale
		if (cvss < 4.0f) return "Information";
		if (cvss < 7.0f) return "Low";
		if (cvss < 9.0f) return "Medium";
		return "High";
	}

	private ByteBuffer hashScanIssue(IScanIssue si) {
		return ByteBuffer.wrap(blake2b.digest((si.getUrl().toString() + "\n" + si.getIssueDetail()).getBytes()));
	}

	private byte[] buildHttpRequest(String host, String URI, String method, String body) {
		String headers = "";
		headers += "User-Agent: " + GlobalVars.USER_AGENT + "/" + GlobalVars.VERSION + CRLF;
		if (method.equals("POST")) {
			headers += "Content-Type: application/x-www-form-urlencoded\r\n";
			headers += "Content-Length: " + body.length() + CRLF;
		}
		return (method + " " + URI + " HTTP/1.1\r\nHost: " + host + CRLF + headers + CRLF + body).getBytes();
	}

	private SHR parseHttpResponse(byte[] response) {
		String[] headersbody = new String(response).split("\r\n\r\n", 2);
		String[] headers = headersbody[0].split(CRLF);
		Map<String,String> headermap = new HashMap<>();
		for (String header : headers) {
			if (header == headers[0]) continue; // Skip first: that's the status line
			String[] nameval = header.split(":", 2);
			headermap.put(nameval[0].toLowerCase().trim(), nameval[1].trim());
		}
		String[] methodcodestatus = headers[0].split(" ", 3);

		int status = Integer.parseInt(methodcodestatus[1]);
		return new SHR(status, headermap, headersbody[1]);
	}

	private String url2uri(URL url) {
		return (url.getPath() != null ? url.getPath() : "")
			+ (url.getQuery() != null ? url.getQuery() : "");
	}

	private boolean isBlacklisted(String stacktraceline) {
		String[] blacklisted_class_prefixes = GlobalVars.config.getString("classblacklist").split(",");
		for (String blacklisted_class_prefix : blacklisted_class_prefixes) {
			if (blacklisted_class_prefix.length() < 3) {
				continue;
			}
			if (stacktraceline.contains(blacklisted_class_prefix)) {
				return true;
			}
		}

		return false;
	}

	private String getHashedTrace(String stacktrace) {
		// This function assumes a sanitized stack trace
		String hashedTrace = "";
		for (String line : stacktrace.split("\n")) {
			String[] match = line.trim().split("\\(|\\)|:");
			String fullfunctionname = match[0];
			String sourcename = match[1];
			int lineno = Integer.parseInt(match[2]);

			String[] splitfunc = fullfunctionname.split("\\.");
			String[] tmp = Arrays.copyOfRange(splitfunc, 0, splitfunc.length - 1);
			String classname = String.join(".", tmp);
			String functionname = splitfunc[splitfunc.length - 1];

			String functionname_2b = burp.Blake2b.Engine.LittleEndian.toHexStr(blake2b.digest(functionname.getBytes()));
			String classname_2b = burp.Blake2b.Engine.LittleEndian.toHexStr(blake2b.digest(classname.getBytes()));
			String fullfunctionname_2b = burp.Blake2b.Engine.LittleEndian.toHexStr(blake2b.digest(fullfunctionname.getBytes()));

			hashedTrace += String.format("%s:%s:%s:%d\n", fullfunctionname_2b, classname_2b, functionname_2b, lineno);
		}

		return hashedTrace;
	}

	private String checktrace(String stacktrace) {
		String retval = null; // Return value

		try {
			ByteBuffer tracedigest = ByteBuffer.wrap(blake2b.digest(stacktrace.getBytes("UTF-8")));
			if (HttpReqMemoization.containsKey(tracedigest)) {
				GlobalVars.debug("Trace found in memoization table, returning stored response.");
				return HttpReqMemoization.get(tracedigest);
			}

			boolean retry = true;
			while (retry) {
				retry = false;

				boolean isset_apikey = GlobalVars.config.getString("apikey").length() > 4;
				boolean submit_hashed_trace = isset_apikey && GlobalVars.config.getBoolean("hashtrace");

				URL url = new URL(GlobalVars.config.getString("apiurl") + (submit_hashed_trace ? "hashTrace" : ""));
				boolean ishttps = url.getProtocol().toLowerCase().equals("https");
				int port = url.getPort() == -1 ? url.getDefaultPort() : url.getPort();

				GlobalVars.debug(String.format("Submitting a trace to %s", url.toString()));

				String body = "";
				if (isset_apikey) {
					body += "apikey=";
					body += GlobalVars.config.getString("apikey").trim();
					body += "&";
				}
				body += "trace=";
				body += java.net.URLEncoder.encode(submit_hashed_trace ? getHashedTrace(stacktrace) : stacktrace);

				byte[] httpreq = buildHttpRequest(url.getHost(), url2uri(url), "POST", body);
				SHR response = parseHttpResponse(GlobalVars.callbacks.makeHttpRequest(url.getHost(), port, ishttps, httpreq));
				GlobalVars.debug("Response status " + response.status);

				if (response.status == 204) {
					retval = null;
				}
				else if (response.status == 301 && response.headers.containsKey("location") && response.headers.get("location").equals(GlobalVars.config.getString("apiurl").replace("http://", "https://"))) {
					// Oblige an HTTP -> HTTPS redirect (but nothing else)
					GlobalVars.debug(String.format("Got a 301, updating apiurl setting from <%s> to <%s>.", GlobalVars.config.getString("apiurl"), response.headers.get("location")));
					GlobalVars.config.putAndSave("apiurl", response.headers.get("location"));
					retry = true;
				}
				else if (response.status == 429) {
					if (isset_apikey) {
						GlobalVars.debug("HTTP request failed: 429 (with API key)");
						// An API key is set
						String msg = "Your API key ran out of requests. For bulk\nlookup of stack traces, please contact us.";
						if ( ! showed429AlertWithApiKey) {
							// Only alert once; nobody wants to be annoyed by this stuff
							showed429AlertWithApiKey = true;

							JOptionPane.showMessageDialog(null, msg, "Burp Extension " + GlobalVars.EXTENSION_NAME, JOptionPane.ERROR_MESSAGE);
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
								"You have reached the request limit for " + GlobalVars.EXTENSION_NAME_SHORT + ". "
									+ "Please register on " + GlobalVars.REGURL + "\nfor a free API key. If you already have an API key, please enter it here.",
								GlobalVars.EXTENSION_NAME + " API key",
								JOptionPane.PLAIN_MESSAGE
							);
							if (result.length() > 0) {
								GlobalVars.config.putAndSave("apikey", result);
								GlobalVars.debug("apikey configured after prompt");
								retry = true;
							}
						}
						else {
							GlobalVars.callbacks.issueAlert("Extension " + GlobalVars.EXTENSION_NAME_SHORT + ": You hit the request limit for the API. "
								+ "To continue, please register for a free API key at " + GlobalVars.REGURL + ", or slow the rate of requests.");
						}
					}
					if (!retry) {
						return null;
					}
				}
				else if (response.status == 401 && isset_apikey) {
					GlobalVars.debug("HTTP request failed: invalid API key (401)");

					// N.B. we thread this, but due to the thread pool of 1, further requests will just be queued, so we won't get dialogs on top of each other.
					// Further requests will also automatically use the API key if the user enters one here, even if they were already queued previously.

					String result = (String)JOptionPane.showInputDialog(Config.getBurpFrame(),
						"Your API key is invalid.\nIf you want to use a different API key, please enter it here.",
						GlobalVars.EXTENSION_NAME + " API key invalid",
						JOptionPane.PLAIN_MESSAGE,
						null,
						null,
						GlobalVars.config.getString("apikey")
					);
					if (result != null && result.length() > 0) {
						GlobalVars.config.putAndSave("apikey", result);
						GlobalVars.debug("apikey reconfigured");
						retry = true;
					}
					else {
						// If they cancelled the dialog or emptied it, override the string so they don't get more of those alerts.
						GlobalVars.config.putAndSave("apikey", "none");
					}

					if (!retry) {
						return null;
					}
				}
				else if (response.status != 200) {
					GlobalVars.callbacks.issueAlert("Extension " + GlobalVars.EXTENSION_NAME + ": HTTP request to back-end failed with status " + Integer.toString(response.status));

					GlobalVars.debug("HTTP request failed with status " + Integer.toString(response.status));

					return null;
				}
				else {
					retval = response.body;
				}
			} // End of while(retry) loop

			// The code should only reach here if we want to memoize the result. Otherwise, early exit (return) above!

			GlobalVars.debug("Result: " + (retval == null ? "null" : retval.substring(0, Math.min(150, retval.length()))));

			HttpReqMemoization.put(tracedigest, retval);

			return retval;
		}
		catch (java.io.UnsupportedEncodingException e) {
			e.printStackTrace(new java.io.PrintStream(GlobalVars.debug));
		}
		catch (java.io.IOException e) {
			e.printStackTrace(new java.io.PrintStream(GlobalVars.debug));
		}

		return null;
	}

    @Override
	public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse baseRequestResponse) {
		if (messageIsRequest) {
			// TODO maybe also the request instead of only the response?
			return;
		}

		if ( ! GlobalVars.config.getBoolean("enable")) {
			GlobalVars.debug("Note: " + GlobalVars.EXTENSION_NAME_SHORT + " plugin is disabled.");
			return;
		}

		threader.submit(new Runnable() {
			public void run() {
				String response = null;

				// Basically the pattern checks /\s[valid class path chars].[more valid class chars]([filename chars].java:1234)/
				Pattern pattern = Pattern.compile("(\\s|/)([a-zA-Z0-9\\.\\$]{1,300}\\.[a-zA-Z0-9\\.\\$]{1,300})\\(([a-zA-Z0-9]{1,300})\\.java:\\d{1,6}\\)");

				try {
					response = new String(baseRequestResponse.getResponse(), "UTF-8");
				}
				catch (java.io.UnsupportedEncodingException e) {
					e.printStackTrace(new java.io.PrintStream(GlobalVars.debug));
				}

				response = response.replace("\\$", "$").replace("\\/", "/").replace("&nbsp;", " ");
				response = java.net.URLDecoder.decode(response);
				// HTML is not decoded because stack traces do not contain any characters that have to be &escaped;

				Matcher matcher = pattern.matcher(response);

				// Reconstruct the trace (since who knows what might be in between the lines, e.g. "&lt;br&gt;" or "," or "\n")
				String stacktrace = "";
				while (matcher.find()) {
					if ( ! matcher.group(2).contains(".")) {
						// Enforce a dot in the full class name (sanity check)
						continue;
					}
					if ( ! (matcher.group(2).indexOf(matcher.group(3) + "$") >= 2
							|| matcher.group(2).indexOf(matcher.group(3) + ".") >= 2)) {
						// TODO is this check too strict?
						// (It's strict because, if it's too loose, we might submit all sorts of private data to our API)
						// The filename should occur in the first part, either followed by a dollar or by a dot,
						// and it usually does not start with that (so match from position 2 onwards, because
						// there should be at least 1 character and a dot, like "a.test.run(test.java:42)").
						continue;
					}
					String line = matcher.group(0).substring(1);
					if ( ! isBlacklisted(line)) {
						GlobalVars.debug(" " + line);
						stacktrace += " " + line + "\n";
					}
					else {
						GlobalVars.debug(String.format("[filtered out blacklisted class: %s]", matcher.group(2)));
					}
				}

				if (stacktrace.length() == 0) {
					return;
				}

				Instant start = Instant.now();

				// Check the trace with our back-end
				String result = checktrace(stacktrace);

				GlobalVars.debug("checktrace() returned in " + String.valueOf(Duration.between(start, Instant.now()).toMillis()) + "ms");

				// Either some error (already handled) or no results
				if (result == null) {
					return;
				}

				Map args = new HashMap();
				args.put(JsonReader.USE_MAPS, true);
				Map<String,Object> products = (Map<String,Object>)JsonReader.jsonToJava(result, args);

				String issuetext = "";
				String comma = "";

				boolean is_uncertain_cve;
				boolean any_uncertain_cves = false;
				boolean any_certain_cves = false;
				float maxcvss = 0;
				int i = 0;

				String outdated = "";
				String notice = "";

				issuetext += String.format("X41 BeanStack found the following versions based on the stack trace:<br>");
				for (Map.Entry<String,Object> product : products.entrySet()) {
					if (product.getKey().equals("__BeanStack_demo")) {
						notice = "<br><br>Note: CVEs are shown for this stack trace as a demo. To view CVEs with other stack traces, please <a href='https://beanstack.io/signup.html'>request an API key</a>.";
						continue;
					}

					if (product.getKey().equals("__BeanStack_needs_upgrading")) {
						outdated = (String)product.getValue();
						continue;
					}

					i += 1;
					issuetext += String.format("%d. %s<br>" + htmlindent, i, product.getKey());

					Map<String,Object> productmap = (Map<String,Object>)product.getValue();
					Object[] versions = (Object[])productmap.get("versions");
					if (versions.length == 1) {
						issuetext += "version: " + versions[0].toString();
					}
					else {
						issuetext += "matching versions: ";
						comma = "";
						for (Object ver : versions) {
							issuetext += comma + ver.toString();
							comma = ", ";
						}
					}

					if (productmap.containsKey("cves")) {
						Object[] cves = (Object[])productmap.get("cves");
						if (cves.length > 0) {
							issuetext += "<br>" + htmlindent + "CVE(s): ";

							comma = "";
							for (Object cveobj : cves) {
								Map<String,Object> cvemap = (Map<String,Object>)cveobj;
								Map<String,Map> nistobj = (Map<String,Map>)cvemap.get("data");

								String cveid = (((Map<String,Map<String,String>>)nistobj.get("cve")).get("CVE_data_meta")).get("ID");
								is_uncertain_cve = Integer.parseInt(cvemap.get("vermatch").toString()) != 0;
								any_uncertain_cves = is_uncertain_cve ? is_uncertain_cve : any_uncertain_cves;
								any_certain_cves = is_uncertain_cve ? any_certain_cves : ! is_uncertain_cve;
								issuetext += comma + "<a href='" + GlobalVars.CVEURL + cveid + "'>" + cveid + "</a>" + (is_uncertain_cve ? "*" : "");
								comma = ", ";

								String score = "(not given)";
								Map<String,Map> impactmap = nistobj.get("impact");
								if (impactmap.size() > 0) {
									String cvssversion = impactmap.containsKey("baseMetricV3") ? "3" : "2";
									Map<String,Object> scoremap = ((Map<String,Map<String,Object>>)impactmap.get("baseMetricV" + cvssversion)).get("cvssV" + cvssversion);
									score = scoremap.get("baseScore").toString();
									issuetext += " (" + score + ")";
									maxcvss = Math.max(Float.parseFloat(score), maxcvss);
								}

								if (GlobalVars.config.getBoolean("issuepercve") && ! is_uncertain_cve) {
									GlobalVars.debug(String.format("Logging separate issue for %s", cveid));
									GlobalVars.callbacks.addScanIssue(new CustomScanIssue(
										baseRequestResponse.getHttpService(),
										GlobalVars.callbacks.getHelpers().analyzeRequest(baseRequestResponse).getUrl(),
										new IHttpRequestResponse[] { baseRequestResponse },
										String.format("%s (%s)", GlobalVars.config.getString("issuetitle"), cveid),
										String.format("In the stack trace, %s with CVSS score %s was discovered. It is present in %s.", cveid, score, product.getKey()),
										cvssToBurpSeverity(Float.parseFloat(score)),
										"Firm"
									));
								}
							}
							issuetext += "<br>";
						}
					}
					else {
						if (GlobalVars.config.getString("apikey").length() > 4) {
							issuetext += " (no CVEs known)<br>";
						}
						else {
							issuetext += "<br>";
						}
					}
				}

				if (any_uncertain_cves) {
					issuetext += "<br>* These CVEs apply to some versions of the product and may not apply to the version(s) found. We can only do exact version matches and not range "
						+ "comparisons because the version scheme is unknown (e.g. it could be that 1.81 is patch release 1 of version 1.8, or it could be that 1.81 comes after 1.9).";
				}

				if (notice.equals("") && GlobalVars.config.getString("apikey").length() <= 4) {
					notice = "<br><br>Note: to check for CVEs, please <a href='https://beanstack.io/signup.html'>request an API key</a> or <a href='https://beanstack.io/settings.html'>configure your key</a>.";
				}

				String certainty;
				if (any_uncertain_cves || any_certain_cves) {
					// If there are CVEs at all
					if ( ! any_uncertain_cves) {
						// Since the severity is determined by the highest CVSS score, and since that
						// CVSS score might belong to an uncertain CVE (one that might not apply to
						// the product we found, but we don't know because we can't do version
						// comparisons without knowing the versioning scheme), we can only be
						// "certain" if there are no uncertain CVEs.
						certainty = "Certain";
					}
					else if (any_certain_cves) {
						certainty = "Firm";
					}
					else {
						// Not a single one was an exact version match, so this is fairly uncertain
						certainty = "Tentative";
					}
				}
				else {
					// We didn't find any CVEs, so return the standard certainty
					certainty = "Certain";
				}

				IScanIssue issue = new CustomScanIssue(
					baseRequestResponse.getHttpService(),
					GlobalVars.callbacks.getHelpers().analyzeRequest(baseRequestResponse).getUrl(),
					new IHttpRequestResponse[] { baseRequestResponse },
					GlobalVars.config.getString("issuetitle"),
					outdated + issuetext + notice,
					cvssToBurpSeverity(maxcvss),
					certainty
				);

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
				GlobalVars.debug("Logged issue");
			}
		});
	}
}

class SHR {
	public final int status;
	public final String body;
	public final Map<String,String> headers;
	public SHR(int status, Map<String,String> headers, String body) {
		this.status = status;
		this.headers = headers;
		this.body = body;
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
	private String confidence;

    public CustomScanIssue(
            IHttpService httpService,
            URL url,
            IHttpRequestResponse[] httpMessages,
            String name,
            String detail,
            String severity,
			String confidence) {
        this.httpService = httpService;
        this.url = url;
        this.httpMessages = httpMessages;
        this.name = name;
        this.detail = detail;
        this.severity = severity;
		this.confidence = confidence;
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
        return confidence;
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

