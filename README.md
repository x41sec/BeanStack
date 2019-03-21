# X41 BeanStack (beta)

*Java Fingerprinting using Stack Traces*

<https://beanstack.io>


### Setup Build Environment

    apt install gradle


### Build

    make


### Install the Burp Extension

Either download the release or make sure you have jar file
`build/libs/beanstack.jar`.

1. Launch Burp
1. Create a temporary project or select a new/existing one
1. Extender tab
1. Extensions subtab
1. Click the Add button
1. Select the `jar` file
1. Leave all options as default, click "next", and finish the wizard


### Extension Usage

Browse to a website with a nice stack trace and make sure it passes through the
Burp proxy. It should automatically be picked up, query the API (invisible),
and produce an "Issue" in the Dashboard or Target tab.

