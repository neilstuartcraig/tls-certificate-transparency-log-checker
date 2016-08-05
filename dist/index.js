"use strict";

// Core deps

// 3rd party deps

var _http = require("http2");

var _xml2json = require("xml2json");

// Local deps
// TODO moe to import syntax
const config = require("../config/tls-certificate-transparency-log-alerter-config.js"); // NOTE: Path is relative to build dir (dist/)
const lib = require("./lib/tls-certificate-transparency-log-alerter-lib.js"); // NOTE: Path is relative to build dir (dist/) - local because lib is babel'd

// TODO: Prob rearrange args
lib.checkCTLogs(_http.get, _xml2json.toJson, config.domainNamePatterns, config.checkIntervalSecs, config.expectedCAs, (checkCTLogsErr, checkCTLogsRes) => {
    if (checkCTLogsErr) {
        throw checkCTLogsErr;
    }

    console.log("RES1: " + JSON.stringify(checkCTLogsRes, null, 2));
});
//# sourceMappingURL=/Users/craign04/Documents/BBC/GlobalTrafficMGMT/github/tls-certificate-transparency-log-alerter/index.js.map