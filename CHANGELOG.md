## Version 0.1.11
- Code refactoring
- Bugfixes

## Version 0.1.10
- Improved containerised stuff
- Switched docker to postgres
- Fixed issue with dynamic filesystem browser
- Added retries to reporter
- Database optimizations
- Added automatic directory cleanup for static analysis
- Documentation and template fixes

## Version 0.1.9
- Bugfixes
- Template fixes
- Fixed broken proxy server by replacing it with mitmproxy


## Version 0.1.8
- Reinstall for incompatible frida versions
- Possibility to start static analyser on remote application
- Possibility to install previously analysed applications
- Improved static code search engine
- Template fixes
- Partially fixed broken proxy server

## Version 0.1.7
- working Docker (including some USB support)
- Template fixes
- Generic fixes
- Better namespace removal for AndroidManifest checks
- Improved logging

## Version 0.1.6
- Create automatic frida patches from static source code (just click on the method and a patch template will automatically be created)
- Improved SSL strip script
- Switched Highlight.js themes
- Docker (yay!)

## Version 0.1.5
- Frida running in a different thread
- Automatically reporting send messages to Kafka (if enabled)
- Viewer for Frida script output
- Made sure default Frida scripts use send() instead of console.log()
- Fixed issue with root checker
- More verbose collector / proxy start messages
- Possibility to kill applications using Frida

## Version 0.1.4
- Updated vulnerability database
- Automated extraction of application icons
- Configurable proxy port/host
- Better scan listing (web)
- Improved static file filtering
- Some other bugfixes (probably)
