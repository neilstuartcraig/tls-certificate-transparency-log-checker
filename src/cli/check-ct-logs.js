#!/user/env/node
"use strict";

// Core deps

// 3rd party deps
import {get} from "http2";
import {toJson} from "xml2json";

// TODO: convert to import syntax
import {checkCTLogs} from "../lib/tls-certificate-transparency-log-alerter-lib.js";

const yargs = require("yargs")
    .usage("Usage: $0 [options]")
    .option("config",
    {
        // NOTE: Not sure why but you have to use --config <path>
        demand: false,
        alias: ["c", "conf"],
        type: "string",
        default: "../../config/tls-certificate-transparency-log-alerter-config.js",
        describe: "the (absolute) path to a specific configuration file which overrides defaults"
    })
    .option("no_certs",
    {
        demand: false,
        // alias: ["no-new"], // DOESNT WORK
        type: "boolean",
        default: false,
        describe: "if true, the 'certs' certificates (those whose valid from data is newer than now - config option 'checkIntervalSecs' ) element of the output JSON will be omitted "
    })
    .option("no_unexpected",
    {
        demand: false,
        // alias: ["no-unexpected"], // DOESNT WORK
        type: "boolean",
        default: false,
        describe: "if true, the 'unexpectedCA' certificates (those whose CA does not match at least one of the config option 'expectedCAs' ) element of the output JSON will be omitted "
    })
    .option("no_by_ca",
    {
        demand: false,
        // alias: ["no-cas"], // DOESNT WORK
        type: "boolean",
        default: false,
        describe: "if true, the 'byCA' element of the output JSON will be omitted "
    }
);

let args = yargs.argv;

let config = null;
try
{
    config = require(args.config); // NOTE: Path is relative to build dir (dist/cli/)\
}
catch(e)
{
    throw e;
}


checkCTLogs(get, toJson, config.domainNamePatterns, config.checkIntervalSecs, config.ignoreCertsValidToBeforeTS, config.expectedCAs, (checkCTLogsErr, checkCTLogsRes) =>
{
    if(checkCTLogsErr)
    {
        throw checkCTLogsErr;
    }

    let output = checkCTLogsRes;

    if(args.no_certs)
    {
        delete output.certs;
    }

    if(args.no_unexpected)
    {
        delete output.unexpectedCA;
    }

    if(args.no_by_ca)
    {
        delete output.byCA;
    }

// let k = Object.keys(output);
// console.dir(k);

    console.log(JSON.stringify(output, null, 2));
});
