"use strict";

// Core deps

// 3rd party deps
import test from "ava";
import nock from "nock";

// Local deps
import {getRSSXML} from "../dist/lib/tls-certificate-transparency-log-checker-lib.js";

test.cb("getRSSXML with valid inputs (1)", (t) =>
{
    let XML = "abc";

    nock("https://crt.sh")
    .get("/atom?identity=%.bbc.co.uk") // i think this can be a regex
    .reply(200, function replyFn(uri, requestBody) // eslint-disable-line no-unused-vars
    {
        return XML;
    });

    let domainNamePattern = "%.bbc.co.uk";

    getRSSXML(domainNamePattern, (err, res) =>
    {
        t.is(err === null, true, "err must be null");
        t.is(res === XML, true, "res must be '" + XML + "'");

        t.end();
    });
});

test.cb("getRSSXML with invalid inputs (empty domainNamePattern)", (t) =>
{
    let XML = "abc";

    nock("https://crt.sh")
    .get("/atom?identity=%.bbc.co.uk") // i think this can be a regex
    .reply(200, function replyFn(uri, requestBody) // eslint-disable-line no-unused-vars
    {
        return XML;
    });

    let domainNamePattern = "";

    getRSSXML(domainNamePattern, (err, res) =>
    {
        t.is(err instanceof TypeError, true, "err must be a TypeError");
        t.is(res === null, true, "res must be null");

        t.end();
    });
});

test.cb("getRSSXML with invalid inputs (null domainNamePattern)", (t) =>
{
    let domainNamePattern = null;
    let TCErr = null;

    try
    {
        getRSSXML(domainNamePattern, (err, res) => // eslint-disable-line no-unused-vars
        {
            t.is(res === null, true, "res must be null");
        });
    }
    catch(e)
    {
        TCErr = e;
    }

    t.is(TCErr instanceof Error, true, "TCErr must be an Error");
    t.end();
});
