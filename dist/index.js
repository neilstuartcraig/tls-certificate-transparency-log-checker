"use strict";

// Core deps

// 3rd party deps

var _http = require("http2");

var _xml2json = require("xml2json");

var _tlsCertificateTransparencyLogCheckerConfig = require("../config/tls-certificate-transparency-log-checker-config.js");

var config = _interopRequireWildcard(_tlsCertificateTransparencyLogCheckerConfig);

var _tlsCertificateTransparencyLogCheckerLib = require("./lib/tls-certificate-transparency-log-checker-lib.js");

var _tlsCertificateTransparencyLogCheckerLib2 = _interopRequireDefault(_tlsCertificateTransparencyLogCheckerLib);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) newObj[key] = obj[key]; } } newObj.default = obj; return newObj; } }

// NOTE: Path is relative to build dir (dist/) - local because lib is babel'd

// Local deps
(0, _tlsCertificateTransparencyLogCheckerLib2.default)(_http.get, _xml2json.toJson, config.domainNamePatterns, config.ignoreCertsValidFromBeforeTS, config.ignoreCertsValidToBeforeTS, config.expectedCAs, (checkCTLogsErr, checkCTLogsRes) => {
    if (checkCTLogsErr) {
        throw checkCTLogsErr;
    }

    console.log(JSON.stringify(checkCTLogsRes, null, 2));
}); // NOTE: Path is relative to build dir (dist/)
//# sourceMappingURL=/Users/craign04/Documents/BBC/GlobalTrafficMGMT/github/tls-certificate-transparency-log-checker/dist/maps/index.js.map