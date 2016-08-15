"use strict";

// 3rd party deps
import test from "ava";
import {get} from "http2";
import {toJson} from "xml2json";

// Local deps
import checkCTLogs from "../dist/lib/tls-certificate-transparency-log-checker-lib.js";
import config from "../config/tls-certificate-transparency-log-checker-config.js"; // NOTE: Path is relative to build dir (dist/)

test("checkCTLogs with valid inputs (1)", (t) =>
{
    checkCTLogs(get, toJson, config.domainNamePatterns, config.checkIntervalSecs, config.ignoreCertsValidToBeforeTS, config.expectedCAs, (checkCTLogsErr, checkCTLogsRes) =>
    {
        t.is(checkCTLogsErr === null, true, "checkCTLogsErr must be null");
        t.is(typeof(checkCTLogsRes) === "object", true, "checkCTLogsRes must be an object");

// console.log(JSON.stringify(checkCTLogsRes, null, 2));
    });
});
