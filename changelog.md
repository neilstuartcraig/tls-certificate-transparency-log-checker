# tls-certificate-transparency-log-checker changelog

## v2.3.6
* Fix error with throwing error if no certs found
* More logical(/less repetition of config) NPM test directive

## v2.3.5
* Revert the below and amend tests accordingly (and also as per 2.3.0)

## v2.3.4
* Fix bug in date handling, "valid to before" was the wrong way around

## v2.3.3
* Fix NPM dependencies and associated docs

## v2.3.2
* Fix bug in test assertion

## v2.3.1
* Snyk badge!

## v2.3.0
* Change default for ignoreCertsValidFromBeforeTS to 0 (include all certs) and make ignoreCertsValidToBeforeTS === 0 a magic value which resolves to "now"

## v2.2.0
* Set CLI output to full width of terminal

## v2.1.0
* Add --version CLI argg
## v2.0.1
* Correct typo in CLI argument alias "--pattern" and improve example

## v2.0.0
* Switch http2 lib for core https due to testing and lack of real need
* Move some 3rd party dependencies to the lib as there's no need for them to be userland
* Exposed all lib functions and added unit tests for them
* Modify some errors in callbacks/returns to be TypeErrors

## v1.0.3
* Update changelog for 1.0.1 & 1.0.2

## v1.0.2
* Updates to readme

## v1.0.1
* Updates to readme

## v1.0.0
Initial version
