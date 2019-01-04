# Java Fingerprinter

### Setup

    apt install gradle

### Build

    gradle build

### Install

Note that you need to modify burp's launcher to use a modern jre, because your
build probably produced a class file too new for Burp's default jre to load.

- Launch Burp
- Open some project or a temporary one maybe
- Extender tab
- Extensions subtab
- Click the Add button
- Select `build/libs/javafp.jar`
- next next yes finish close

### Use

Browse to a website with a nice stack trace and make sure it passes the Burp
proxy. It should automatically be picked up, query the API (invisible), and
produce an "Issue" in the Dashboard tab (see the "Issue activity" frame) titled
"Java Fingerprinter".

### Wishlist

- Threading so it doesn't block
- Perhaps mention detected products in the issue title/name
- Configure debug parameter
- Write documentation to, among other things, inform users that it'll send data
  to our servers and is not to be used when you need to stay quiet...
- See TODOs in code
- What about the SOCKS proxy set in Burp? Fairly sure that our requests will
  not use that. Should we?

