// Code taken from https://github.com/PortSwigger/distribute-damage/blob/866eb5a42e455a52b9d9fe553d0bd6527b86b72b/src/burp/Utilities.java
// License: Apache2

//Copyright 2016 PortSwigger Web Security
//Copyright 2016 James Kettle <albinowax@gmail.com>

package burp;
import burp.*;

import javax.swing.*;
import javax.swing.event.MenuEvent;
import javax.swing.event.MenuListener;
import javax.swing.text.NumberFormatter;
import java.awt.*;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.URL;
import java.text.NumberFormat;
import java.util.*;
import java.util.List;
import burp.GlobalVars;
import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;
import java.awt.Cursor;


// ###########################################################################
// The class that actually holds the config
// ###########################################################################
public class Config {
    private LinkedHashMap<String, String> settings;
    private LinkedHashMap<String, String> readableNames;
    private NumberFormatter onlyInt;

    public Config() {
        settings = new LinkedHashMap<>();
		// These put()s determine the order shown on the settings screen
		put("enable", true);
		put("apikey", "none");
		put("classblacklist", "");
		put("debug", true);
		put("logdups", false);
		put("issuetitle", "Stack Trace Fingerprint Found");
		put("apiurl", "http://beanstack.io/api/");

        readableNames = new LinkedHashMap<>();
		readableNames.put("enable", "Enable Lookups");
		readableNames.put("apiurl", "API URL");
		readableNames.put("issuetitle", "Issue Title");
		readableNames.put("debug", "Print Debug Messages to Stdout");
		readableNames.put("logdups", "Log Duplicates");
		readableNames.put("apikey", "API Key");
		readableNames.put("classblacklist", "Blacklisted Class Prefixes");

        for (String key: settings.keySet()) {
            //callbacks.saveExtensionSetting(key, null); // purge saved settings
            String value = GlobalVars.callbacks.loadExtensionSetting(key);
            if (GlobalVars.callbacks.loadExtensionSetting(key) != null) {
                putRaw(key, value);
            }
        }

        NumberFormat format = NumberFormat.getInstance();
        onlyInt = new NumberFormatter(format);
        onlyInt.setValueClass(Integer.class);
        onlyInt.setMinimum(-1);
        onlyInt.setMaximum(Integer.MAX_VALUE);
        onlyInt.setAllowsInvalid(false);
    }

    private Config(Config base) {
        settings = new LinkedHashMap<>(base.settings);
        onlyInt = base.onlyInt;
    }

    void printSettings() {
		GlobalVars.debug("printSettings():");
        for(String key: settings.keySet()) {
            GlobalVars.debug("  - " + getType(key) + " " + key + " = " + settings.get(key));
        }
    }

    public static JFrame getBurpFrame()
    {
        for(Frame f : Frame.getFrames())
        {
            if(f.isVisible() && f.getTitle().startsWith(("Burp Suite")))
            {
                return (JFrame) f;
            }
        }
        return null;
    }

    private String encode(Object value) {
        String encoded;
        if (value instanceof Boolean) {
            encoded = String.valueOf(value);
        }
        else if (value instanceof Integer) {
            encoded = String.valueOf(value);
        }
        else {
            encoded = "\"" + ((String) value).replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
        }
        return encoded;
    }

    private void putRaw(String key, String value) {
        settings.put(key, value);
    }

    private void put(String key, Object value) {
        settings.put(key, encode(value));
    }

	public void putAndSave(String key, Object value) {
        settings.put(key, encode(value));
		GlobalVars.callbacks.saveExtensionSetting(key, encode(value));
	}

    public String getString(String key) {
        String decoded = settings.get(key);
        decoded = decoded.substring(1, decoded.length()-1).replace("\\\"", "\"").replace("\\\\", "\\");
        return decoded;
    }

    public int getInt(String key) {
        return Integer.parseInt(settings.get(key));
    }

    public boolean getBoolean(String key) {
        String val = settings.get(key);
        if (val.equals("true") ) {
            return true;
        }
        else if (val.equals("false")){
            return false;
        }
        throw new RuntimeException();
    }

    String getType(String key) {
        String val = settings.get(key);
        if (val.equals("true") || val.equals("false")) {
            return "boolean";
        }
        else if (val.startsWith("\"")) {
            return "string";
        }
        else {
            return "number";
        }
    }

    void showSettings() {
        JPanel panel = new JPanel();
        panel.setLayout(new GridLayout(0, 2));

		JLabel lbl = new JLabel("<html>" + GlobalVars.EXTENSION_NAME_SHORT + " settings (<a href=''>documentation</a>)</html>");
		lbl.setCursor(new Cursor(Cursor.HAND_CURSOR));
		panel.add(lbl);

		lbl.addMouseListener(new java.awt.event.MouseAdapter() {
			@Override public void mousePressed(java.awt.event.MouseEvent ev) {
				try {
					java.awt.Desktop.getDesktop().browse(new java.net.URI(GlobalVars.SETTINGDOCURL));
				}
				catch (IOException|java.net.URISyntaxException e) {
					e.printStackTrace();
				}
			}
		});

		panel.add(new JLabel());

        HashMap<String, Object> configured = new HashMap<>();

        for(String key: settings.keySet()) {
            String type = getType(key);
            panel.add(new JLabel("\n" + readableNames.get(key) + ": "));

            if (type.equals("boolean")) {
                JCheckBox box = new JCheckBox();
                box.setSelected(getBoolean(key));
                panel.add(box);
                configured.put(key, box);
            }
            else if (type.equals("number")){
                JTextField box = new JFormattedTextField(onlyInt);
                box.setText(String.valueOf(getInt(key)));
                panel.add(box);
                configured.put(key, box);
            }
            else {
                JTextField box = new JTextField(getString(key));
                panel.add(box);
                configured.put(key, box);
            }
        }

        int result = JOptionPane.showConfirmDialog(getBurpFrame(), panel, GlobalVars.EXTENSION_NAME + " settings", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
        if (result == JOptionPane.OK_OPTION) {
            for(String key: configured.keySet()) {
                Object val = configured.get(key);
                if (val instanceof JCheckBox) {
                    val = ((JCheckBox) val).isSelected();
                }
                else if (val instanceof JFormattedTextField) {
                    val = Integer.parseInt(((JFormattedTextField) val).getText().replace(",", ""));
                }
                else {
                    val = ((JTextField) val).getText();
					if (key.equals("apiurl") && ! ((String)val).endsWith("/")) {
						val += "/";
					}
                }
                put(key, val);
                GlobalVars.callbacks.saveExtensionSetting(key, encode(val));
            }

			GlobalVars.debug("Saved settings.");
			printSettings();
        }
		else {
			GlobalVars.debug("Settings cancelled.");
		}
    }
}

// ###########################################################################
// Class to add context menu (right click menu) actions and handle them
// ###########################################################################
class ContextMenuSettingsOptionAdder implements IContextMenuFactory, ActionListener {
    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
		ContextMenuSettingsOptionAdder outer = this;
		// 16 is an undocumented magic number that indicates it was invoked
		// from the Issues list in the Target tab. The place where our events
		// are logged, so that seemed a logical place for the options button.
		// The number was reverse engineered using the highly advanced method
		// of println()ing getToolFlag and right clicking the desired place.
		return invocation.getToolFlag() == 16 ? new ArrayList<JMenuItem>() {{
			add(new JMenuItem(GlobalVars.EXTENSION_NAME_SHORT + " settings") {{
				addActionListener(outer);
			}});
		}} : null;
    }

	public void actionPerformed(ActionEvent e) {
        SwingUtilities.invokeLater(new Runnable() {
            public void run(){
                GlobalVars.config.showSettings();
            }
        });
    }
}

