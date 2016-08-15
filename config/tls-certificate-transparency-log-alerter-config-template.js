"use strict";

const nowTS = new Date().getTime() / 1000; // Into seconds

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
        "%.bbc.co.uk",
        "%.bbc.com"
    ],

    // Check interval - used to filter out previously alerted-on certs, entries with "valid from" < (now - checkIntervalSecs) will be omitted from results
    // Set checkIntervalSecs to 0 to disable filtering
    // Data type is uint32
    checkIntervalSecs: 86400,

    // Timestamp representing the date/time after which certificates whose valid until date is older (less than) will be ignored
    ignoreCertsValidToBeforeTS: nowTS, // Into seconds

    // Array of regexes to match CAs in certs against. Any CAs which DO NOT match one or more regex will trigger an alert
    // Be as general or as specific as you want here...i.e. expect a CA wholesale or just e.g. EV
    expectedCAs:
    [
        /.*Globalsign.*/i,
        /.*DigiCert.*/
    ]
};
