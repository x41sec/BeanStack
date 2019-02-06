package burp;

import burp.*;

class GlobalVars {
	public static IBurpExtenderCallbacks callbacks;
	public static final String EXTENSION_NAME = "Java Fingerprinting using Stack Traces";
	public static final String EXTENSION_NAME_SHORT = "JavaFP";
	public static Config config;
	public static java.io.PrintStream debug = System.out;

	public static void debug(Object o) {
		if (GlobalVars.config.getBoolean("debug")) {
			GlobalVars.debug.println(o);
		}
	}
}

