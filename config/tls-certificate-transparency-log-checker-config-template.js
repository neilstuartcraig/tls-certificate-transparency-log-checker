"use strict";

const nowTS = parseInt(new Date().getTime() / 1000, 10); // Into seconds

module.exports =
{
    // Domain name patters to test for.
    // NOTE on wildcards WRT crt.sh:
    // % is the wildcard char (like SQL)
    // Currently (Aug 2016) only accepts one wildcard per domain name pattern
    // Wildcard searching for e.g. %.example.org is multi-level i.e. it'll return a.example.org and also b.a.example.org and so on
    // Data type is array of strings
    domainNamePatterns:
    [
        "%.example.co.uk",
        "%.example.com"
    ],

    // Timestamp representing the date/time after which certificates whose valid from date is older (less than) will be ignored
    ignoreCertsValidFromBeforeTS: nowTS - (86400), // Ignore certs issued more than 1 day ago

    // Timestamp representing the date/time after which certificates whose valid until date is older (less than) will be ignored
    ignoreCertsValidToBeforeTS: nowTS, // Ignore certs which are already expired

    // Array of regexes to match CAs in certs against. Any CAs which DO NOT match one or more regex will trigger an alert
    // Be as general or as specific as you want here...i.e. expect a CA wholesale or just e.g. EV
    expectedCAs:
    [
        /.*GlobalSign.*/,
        /.*DigiCert.*/
    ]
};
