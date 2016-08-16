"use strict";

// Core deps

// 3rd party deps
import {get} from "http2";
import {toJson} from "xml2json";

// Local deps
import * as config from "../config/tls-certificate-transparency-log-checker-config.js"; // NOTE: Path is relative to build dir (dist/)
import checkCTLogs from "./lib/tls-certificate-transparency-log-checker-lib.js"; // NOTE: Path is relative to build dir (dist/) - local because lib is babel'd

checkCTLogs(get, toJson, config.domainNamePatterns, config.ignoreCertsValidFromBeforeTS, config.ignoreCertsValidToBeforeTS, config.expectedCAs, (checkCTLogsErr, checkCTLogsRes) =>
{
    if(checkCTLogsErr)
    {
        throw checkCTLogsErr;
    }

    console.log(JSON.stringify(checkCTLogsRes, null, 2));
});
