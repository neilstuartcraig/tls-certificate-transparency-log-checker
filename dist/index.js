"use strict";

// Core deps

// 3rd party deps

var _http = require("http2");

var _xml2json = require("xml2json");

// Local deps
// TODO moe to import syntax
const config = require("../config/tls-certificate-transparency-log-checker-config.js"); // NOTE: Path is relative to build dir (dist/)
const lib = require("./lib/tls-certificate-transparency-log-checker-lib.js"); // NOTE: Path is relative to build dir (dist/) - local because lib is babel'd

// TODO: Prob rearrange args
// checkCTLogs(get: Object, toJson: Function, domainNamePatterns: Array, checkIntervalSecs: uint32 = defaults.checkIntervalSecs, ignoreCertsValidToBeforeTS: number = defaults.ignoreCertsValidToBeforeTS, expectedCAs: Array = defaults.expectedCAs, callback: Function)
lib.checkCTLogs(_http.get, _xml2json.toJson, config.domainNamePatterns, config.checkIntervalSecs, config.ignoreCertsValidToBeforeTS, config.expectedCAs, (checkCTLogsErr, checkCTLogsRes) => {
    if (checkCTLogsErr) {
        throw checkCTLogsErr;
    }

    console.log(JSON.stringify(checkCTLogsRes, null, 2));
});
//# sourceMappingURL=/Users/craign04/Documents/BBC/GlobalTrafficMGMT/github/tls-certificate-transparency-log-checker/index.js.map