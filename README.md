# X41 BeanStack (beta)

*Java Fingerprinting using Stack Traces*

<https://beanstack.io>


### Installing the Burp Extension

Download [the latest release](https://github.com/x41sec/BeanStack/releases/latest)
or use your own build from `build/libs/beanstack.jar`.

1. Launch Burp
1. Create a temporary project or select a new/existing one
1. Open the Extender tab
1. Open the Extensions subtab
1. Click the Add button
1. Select the `jar` file
1. Leave all options as default, click "next", and finish the wizard

![Installation screenshot](https://beanstack.io/img/burp-install.png)


### Extension Usage

Browse to a website with a nice stack trace (such as [beanstack.io](https://beanstack.io))
and make sure the response passes through the Burp proxy. It should
automatically be picked up, query the API (in the background), and produce an
"Issue" in the Dashboard or Target tab.

![Example issue screenshot](https://beanstack.io/img/burp-extension.png)


### Building From Source

Dependencies:

    apt install gradle default-jdk-headless

Note that for ancient versions of Gradle (pre-3.4, Feb 2017), you will need to
remove the bottom paragraph from `build.gradle`. Your version of Gradle cannot
produce reproducible builds.

Build:

    make

