"use strict";

// Core deps

// 3rd party deps

// Local deps

var _tlsCertificateTransparencyLogCheckerConfig = require("../config/tls-certificate-transparency-log-checker-config.js");

var config = _interopRequireWildcard(_tlsCertificateTransparencyLogCheckerConfig);

var _tlsCertificateTransparencyLogCheckerLib = require("./lib/tls-certificate-transparency-log-checker-lib.js");

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) newObj[key] = obj[key]; } } newObj.default = obj; return newObj; } }

// NOTE: Path is relative to build dir (dist/) - local because lib is babel'd

(0, _tlsCertificateTransparencyLogCheckerLib.checkCTLogs)(config.domainNamePatterns, config.ignoreCertsValidFromBeforeTS, config.ignoreCertsValidToBeforeTS, config.expectedCAs, function (checkCTLogsErr, checkCTLogsRes) {
    if (checkCTLogsErr) {
        throw checkCTLogsErr;
    }

    console.log(JSON.stringify(checkCTLogsRes, null, 2));
}); // NOTE: Path is relative to build dir (dist/)