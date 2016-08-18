"use strict";

// Core deps
import {readFileSync} from "fs";
import {join as pathJoin} from "path";

// 3rd party deps
import test from "ava";

// Local deps
import {convertXMLToJSON} from "../dist/lib/tls-certificate-transparency-log-checker-lib.js";

test("convertXMLToJSON with valid inputs", (t) =>
{
    let xml = readFileSync(pathJoin(__dirname, "fixtures/xml-valid-1.xml")).toString();

    convertXMLToJSON(xml, (err, res) =>
    {
        t.is(err === null, true, "err must be null");

        res.feed.entry.forEach((entry) =>
        {
            if(typeof(entry.summary.$t) !== "string")
            {
                t.fail("Every res.feed.entry item must have a string type 'summary.$t' property");
            }
        });
    });
});


test("convertXMLToJSON with invalid input (empty string)", (t) =>
{
    let xml = "";

    convertXMLToJSON(xml, (err, res) =>
    {
        t.is(err instanceof Error, true, "err must be an Error");
        t.is(res === null, true, "res must be null");
    });
});

test("convertXMLToJSON with invalid input (non-XML string)", (t) =>
{
    let xml = "abcedfg";

    convertXMLToJSON(xml, (err, res) =>
    {
        t.is(err instanceof Error, true, "err must be an Error");
        t.is(res === null, true, "res must be null");
    });
});

test("convertXMLToJSON with invalid input (null XML arg)", (t) =>
{
    let TCErr = null;
    let xml = null;

    try
    {
        convertXMLToJSON(xml, (err, res) => // eslint-disable-line no-unused-vars
        {
            t.is(res === null, true, "res must be null");
        });
    }
    catch(e)
    {
        TCErr = e;
    }

    t.is(TCErr instanceof Error, true, "err must be an Error");
});
