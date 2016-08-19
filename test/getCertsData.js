"use strict";

// Core deps
import {readFileSync} from "fs";
import {join as pathJoin} from "path";

// 3rd party deps
import test from "ava";

// Local deps
import {getCertsData} from "../dist/lib/tls-certificate-transparency-log-checker-lib.js";

const ignoreCertsValidFromBeforeTS = 0; // All time
const ignoreCertsValidToBeforeTS = 1373193301; // NOTE: this value is based on the cert in ct-valid.json
const expectedCAs =
[
    /.*GlobalSign.*/,
    /.*VeriSign.*/
];

test.cb("getCertsData with valid inputs (1)", (t) =>
{
    let parsedJSON = JSON.parse(readFileSync(pathJoin(__dirname, "fixtures/ct-valid.json")).toString("utf8"));

    getCertsData(parsedJSON, ignoreCertsValidFromBeforeTS, ignoreCertsValidToBeforeTS, expectedCAs, (err, res) =>
    {
        t.is(err === null, true, "err must be null");
        t.is(Object.keys(res).length, 3, "res must be an Object with exactly 3 keys (allCerts, unexpectedCA, byCA)");
        t.end();
    });
});
/*
test.cb("getCertsData with invalid inputs (empty JSON)", (t) =>
{
    let parsedJSON = {}; // eslint-disable-line object-curly-newline

    getCertsData(parsedJSON, ignoreCertsValidFromBeforeTS, ignoreCertsValidToBeforeTS, expectedCAs, (err, res) =>
    {
        t.is(err instanceof Error, true, "err must be an error");
        t.is(res === null, true, "res must be null");
        t.end();
    });
});

test.cb("getCertsData with invalid inputs (null JSON)", (t) =>
{
    let parsedJSON = null;
    let TCErr = null;

    try
    {
        getCertsData(parsedJSON, ignoreCertsValidFromBeforeTS, ignoreCertsValidToBeforeTS, expectedCAs, (err, res) =>
        {
            t.is(err instanceof Error, true, "err must be an error");
            t.is(res === null, true, "res must be null");

        });
    }
    catch (e)
    {
        TCErr = e;
    }

    t.is(TCErr instanceof Error, true, "must throw an Error");
    t.end();
});
*/
