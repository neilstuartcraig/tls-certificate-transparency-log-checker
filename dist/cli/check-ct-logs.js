#!/user/env/node

"use strict";

// Core deps

// 3rd party deps

var _http = require("http2");

var _xml2json = require("xml2json");

var _tlsCertificateTransparencyLogCheckerLib = require("../lib/tls-certificate-transparency-log-checker-lib.js");

var _tlsCertificateTransparencyLogCheckerLib2 = _interopRequireDefault(_tlsCertificateTransparencyLogCheckerLib);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

const yargs = require("yargs").usage("Usage: $0 [options]").option("config", {
    // NOTE: Not sure why but you have to use --config <path>
    demand: false,
    alias: ["c", "conf"],
    type: "string",
    default: "../../config/tls-certificate-transparency-log-checker-config.js",
    describe: "the (absolute) path to a specific configuration file which overrides defaults"
}).option("no_all_certs", {
    demand: false,
    // alias: ["no-new"], // DOESNT WORK
    type: "boolean",
    default: false,
    describe: "if true, the 'allCerts' certificates (literally all certs found in the CT logs whose valid from data is newer than now - config option 'ignoreCertsValidFromBeforeTS' ) element of the output JSON will be omitted "
}).option("no_unexpected", {
    demand: false,
    // alias: ["no-unexpected"], // DOESNT WORK
    type: "boolean",
    default: false,
    describe: "if true, the 'unexpectedCA' certificates (those certs whose CA does *not* match at least one of the config option 'expectedCAs' ) element of the output JSON will be omitted "
}).option("no_by_ca", {
    demand: false,
    // alias: ["no-cas"], // DOESNT WORK
    type: "boolean",
    default: false,
    describe: "if true, the 'byCA' element of the output JSON will be omitted "
});

// Local deps


let args = yargs.argv;

let config = null;
try {
    config = require(args.config); // NOTE: Path is relative to build dir (dist/cli/)\
} catch (e) {
    throw e;
}

(0, _tlsCertificateTransparencyLogCheckerLib2.default)(_http.get, _xml2json.toJson, config.domainNamePatterns, config.ignoreCertsValidFromBeforeTS, config.ignoreCertsValidToBeforeTS, config.expectedCAs, (checkCTLogsErr, checkCTLogsRes) => {
    if (checkCTLogsErr) {
        throw checkCTLogsErr;
    }

    let output = checkCTLogsRes;

    // Remove undesired output - yeah, this is a crappy method but will do for now
    if (args.no_all_certs) {
        delete output.allCerts;
    }

    if (args.no_unexpected) {
        delete output.unexpectedCA;
    }

    if (args.no_by_ca) {
        delete output.byCA;
    }

    console.log(JSON.stringify(output, null, 2));
});
//# sourceMappingURL=/Users/craign04/Documents/BBC/GlobalTrafficMGMT/github/tls-certificate-transparency-log-checker/cli/check-ct-logs.js.map