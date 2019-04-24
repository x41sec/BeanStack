package burp;

import burp.*;

class GlobalVars {
	// We're all hackers: if you want to hack on this client, that's great!
	// Just include an accurate user agent (there is no UA checking, it only
	// ends up in our logs). If you did not coordinate the release with us,
	// please include a URL so we can reach you in case of problems or if, for
	// example, our API is going to change.
	public static final String USER_AGENT = "X41-BeanStack-BApp";
	public static final String EXTENSION_NAME = "X41 BeanStack (beta)";
	public static final String EXTENSION_NAME_SHORT = "BeanStack";
	public static final String VERSION = "0.4.2";
	public static final String REGURL = "https://beanstack.io";
	public static final String SETTINGDOCURL = "https://beanstack.io/settings.html";
	public static final String CVEURL = "https://nvd.nist.gov/vuln/detail/";

	public static IBurpExtenderCallbacks callbacks;
	public static Config config;
	public static java.io.PrintStream debug = System.out;

	public static void debug(Object o) {
		if (GlobalVars.config.getBoolean("debug")) {
			GlobalVars.debug.print(new java.text.SimpleDateFormat("HH:mm:ss").format(java.util.Calendar.getInstance().getTime()) + " ");
			GlobalVars.debug.println(o);
		}
	}
}

