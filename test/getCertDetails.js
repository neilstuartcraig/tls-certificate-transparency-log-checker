"use strict";

// Core deps
import {readFileSync} from "fs";
import {join as pathJoin} from "path";

// 3rd party deps
import test from "ava";

// Local deps
import {getCertDetails} from "../dist/lib/tls-certificate-transparency-log-checker-lib.js";


test("getCertDetails with valid inputs (1)", (t) =>
{
    let summary = readFileSync(pathJoin(__dirname, "fixtures/summary-valid.xml"));

    let expectedOutput =
    {
        "serial": "112196EDB9C269F043CD82DA890166C93DB9",
        "subject":
        {
            "commonName": "careers.bbc.co.uk",
            "countryName": "GB",
            "localityName": "London",
            "organizationName": "British Broadcasting Corporation",
            "organizationalUnitName": "Technology Group",
            "stateOrProvinceName": "London"
        },
        "issuer":
        {
            "commonName": "GlobalSign Organization Validation CA - G2",
            "countryName": "BE",
            "organizationName": "GlobalSign nv-sa"
        },
        "validFrom": "Feb 27 10:40:01 2012 GMT",
        "validFromTS": 1330339201,
        "validTo": "Jun  4 09:08:30 2013 GMT",
        "validToTS": 1370336910,
        "daysRemaining": (Math.floor((1370336910 - new Date().getTime() / 1000) / 86400)),
        "SAN":
        [
            "careers.bbc.co.uk"
        ]
    };

    let rawCertSummary =
    {
        "$t": summary.toString()
    };

    let certDetails = getCertDetails(rawCertSummary);

    t.deepEqual(certDetails, expectedOutput, "certDetails must be exactly the same as expectedOutput");
});


test("getCertDetails with invalid inputs (null)", (t) =>
{
    let rawCertSummary = null;

// NOTE This is pretty horrible but I can't get it to work any other way and there are no decent examples on the interwebs currently so this'll have to do for the mo
    let res = null;

    try
    {
        getCertDetails(rawCertSummary);
    }
    catch(e)
    {
        res = e;
    }

    t.is(res instanceof Error, true, "getCertDetails must throw");
});

test("getCertDetails with invalid inputs (empty object)", (t) =>
{
    let rawCertSummary = {}; // eslint-disable-line object-curly-newline

    let certDetails = getCertDetails(rawCertSummary);

    t.is(certDetails instanceof TypeError, true, "certDetails must be a TypeError");
});

test("getCertDetails with invalid inputs (invalid object - $t gibberish)", (t) =>
{
    let rawCertSummary =
    {
        "$t": "blah blah blah"
    };

    let certDetails = getCertDetails(rawCertSummary);

    t.is(certDetails instanceof TypeError, true, "certDetails must be a TypeError");
});

test("getCertDetails with invalid inputs (invalid object - $t contains invalid x509 cert)", (t) =>
{
    let rawCertSummary =
    {
        "$t": "-----BEGIN CERTIFICATE-----blah blah blah-----END CERTIFICATE-----"
    };

    let certDetails = getCertDetails(rawCertSummary);

    t.is(certDetails instanceof TypeError, true, "certDetails must be a TypeError");
});
