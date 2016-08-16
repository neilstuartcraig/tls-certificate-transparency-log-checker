#!/usr/bin/env node
"use strict";

// Core deps

// 3rd party deps
import {get} from "http2";
import {toJson} from "xml2json";

// Local deps
import checkCTLogs from "../lib/tls-certificate-transparency-log-checker-lib.js";

const yargs = require("yargs")
    .usage("Usage: $0 [options]")
    .help("help")
    .option("config",
    {
        // NOTE: Not sure why but you have to use --config <path>
        demand: false,
        alias: ["c", "conf"],
        type: "string",
        default: "../../config/tls-certificate-transparency-log-checker-config.js",
        describe: "the (absolute) path to a specific configuration file which overrides defaults"
    })
    .option("no_all_certs",
    {
        demand: false,
        // alias: ["no-new"], // DOESNT WORK
        type: "boolean",
        default: false,
        describe: "if true, the 'allCerts' certificates (literally all certs found in the CT logs whose valid from data is newer than now - config option 'ignoreCertsValidFromBeforeTS' ) element of the output JSON will be omitted "
    })
    .option("no_unexpected",
    {
        demand: false,
        // alias: ["no-unexpected"], // DOESNT WORK
        type: "boolean",
        default: false,
        describe: "if true, the 'unexpectedCA' certificates (those certs whose CA does *not* match at least one of the config option 'expectedCAs' ) element of the output JSON will be omitted "
    })
    .option("no_by_ca",
    {
        demand: false,
        // alias: ["no-cas"], // DOESNT WORK
        type: "boolean",
        default: false,
        describe: "if true, the 'byCA' element of the output JSON will be omitted "
    })
    .option("no_entries",
    {
        demand: false,
        type: "boolean",
        default: false,
        describe: "if true, the 'entries' property of each allCerts, unexpectedCA and byCA elements of the output JSON will be omitted "
    })
    .option("domain_name_patterns",
    {
        demand: false,
        type: "array",
        alias: ["d", "domains", "pattems"],
        describe: "A space-separated list of (string) domain name patterns to search for e.g. --domain_name_patterns %.example.com b.example.org %.c.example.net"
    })
    .option("expected_cas",
    {
        demand: false,
        type: "string",
        alias: ["ca", "cas"],
        describe: "A comma-separated list of (case-sensitive) stringified regexes to match the Certificate Authorities in the returned certificates against e.g. \".*SomeCA.*, AnotherCA.*\""
    })
    .option("valid_from",
    {
        demand: false,
        type: "number",
        alias: ["vf", "from"],
        describe: "A Unix timestamp (integer number of seconds since the Unix epoch). Certificates whose 'valid from' date is older than this will be omitted from the output"
    })
    .option("valid_to",
    {
        demand: false,
        type: "number",
        alias: ["vt", "to", "valid_to"],
        describe: "A Unix timestamp (integer number of seconds since the Unix epoch). Certificates whose 'valid until' date is newer than this will be omitted from the output"
    })
    .option("error_if_entries",
    {
        demand: false,
        type: "boolean",
        default: false,
        alias: ["e", "error"],
        describe: "A boolean to determine whether or not to exit with a non-zero (1) return code if any entries are found with provided filters"
    })
    .option("help",
    {
        demand: false,
        alias: "h"
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

let domainNamePatterns = args.domain_name_patterns || config.domainNamePatterns;
let ignoreCertsValidFromBeforeTS = args.valid_from || config.ignoreCertsValidFromBeforeTS;
let ignoreCertsValidToBeforeTS = args.valid_to || config.ignoreCertsValidToBeforeTS;

let expectedCAs = config.expectedCAs;

if(args.expected_cas)
{
    expectedCAs = args.expected_cas.split(",").map((c) =>
    {
        return new RegExp(c.trim());
    });
}

checkCTLogs(get, toJson, domainNamePatterns, ignoreCertsValidFromBeforeTS, ignoreCertsValidToBeforeTS, expectedCAs, (checkCTLogsErr, checkCTLogsRes) =>
{
    if(checkCTLogsErr)
    {
        throw checkCTLogsErr;
    }

    let output = checkCTLogsRes;

// Remove undesired output - yeah, this is a crappy method but will do for now
    if(args.no_all_certs)
    {
        delete output.allCerts;
    }

    if(args.no_unexpected)
    {
        delete output.unexpectedCA;
    }

    if(args.no_by_ca)
    {
        delete output.byCA;
    }

    if(args.no_entries)
    {
        for(let el in output)
        {
            delete output[el].entries;
        }
    }

    console.log(JSON.stringify(output, null, 2));

    if(args.error_if_entries === true)
    {
        for(let el in output)
        {
            if(output[el].count > 0)
            {
                process.exit(1);
            }
        }
    }
});
