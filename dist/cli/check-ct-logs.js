#!/usr/bin/env node

"use strict";

// Core deps

// 3rd party deps


// Local deps

var _tlsCertificateTransparencyLogCheckerLib = require("../lib/tls-certificate-transparency-log-checker-lib.js");

var _package = require("../../package.json");

var yargs = require("yargs").usage("Usage: $0 [options]").help("help").option("config", {
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
}).option("no_entries", {
    demand: false,
    type: "boolean",
    default: false,
    describe: "if true, the 'entries' property of each allCerts, unexpectedCA and byCA elements of the output JSON will be omitted "
}).option("domain_name_patterns", {
    demand: false,
    type: "array",
    alias: ["d", "domains", "patterns"],
    describe: "A space-separated list of quoted (string) domain name patterns to search for e.g. --domain_name_patterns \"%.example.com\" \"b.example.org\" \"%.c.example.net\""
}).option("expected_cas", {
    demand: false,
    type: "string",
    alias: ["ca", "cas"],
    describe: "A comma-separated list of (case-sensitive) stringified regexes to match the Certificate Authorities in the returned certificates against e.g. \".*SomeCA.*, AnotherCA.*\""
}).option("valid_from", {
    demand: false,
    type: "number",
    alias: ["vf", "from"],
    describe: "A Unix timestamp (integer number of seconds since the Unix epoch). Certificates whose 'valid from' date is older than this will be omitted from the output. Defaults to your config file value which ships as 0."
}).option("valid_to", {
    demand: false,
    type: "number",
    alias: ["vt", "to", "valid_to"],
    describe: "A Unix timestamp (integer number of seconds since the Unix epoch). Certificates whose 'valid until' date is newer than this will be omitted from the output. Defaults to your config file value which ships as 'now'."
}).option("error_if_entries", {
    demand: false,
    type: "boolean",
    default: false,
    alias: ["e", "error"],
    describe: "A boolean to determine whether or not to exit with a non-zero (1) return code if any entries are found with provided filters"
}).option("help", {
    demand: false,
    alias: "h"
}).option("version", {
    demand: false,
    alias: ["v", "ver"],
    type: "boolean",
    describe: "Show the version number and exit"
});

yargs.wrap(yargs.terminalWidth());

var args = yargs.argv;

// Show version number from package.json and exit with return code 0
if (args.version) {
    console.log(_package.version);
    process.exit();
}

var config = null;
try {
    config = require(args.config); // NOTE: Path is relative to build dir (dist/cli/)\
} catch (e) {
    throw e;
}

var domainNamePatterns = args.domain_name_patterns || config.domainNamePatterns;
var ignoreCertsValidFromBeforeTS = args.valid_from || config.ignoreCertsValidFromBeforeTS;
var ignoreCertsValidToBeforeTS = args.valid_to || config.ignoreCertsValidToBeforeTS;

// if ignoreCertsValidToBeforeTS === 0, set to "now"
if (ignoreCertsValidToBeforeTS === 0) {
    ignoreCertsValidToBeforeTS = parseInt(new Date().getTime() / 1000, 10);
}

var expectedCAs = config.expectedCAs;

if (args.expected_cas) {
    expectedCAs = args.expected_cas.split(",").map(function (c) {
        return new RegExp(c.trim());
    });
}

(0, _tlsCertificateTransparencyLogCheckerLib.checkCTLogs)(domainNamePatterns, ignoreCertsValidFromBeforeTS, ignoreCertsValidToBeforeTS, expectedCAs, function (checkCTLogsErr, checkCTLogsRes) {
    if (checkCTLogsErr) {
        throw checkCTLogsErr;
    }

    var output = checkCTLogsRes;

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

    if (args.no_entries) {
        for (var el in output) {
            delete output[el].entries;
        }
    }

    console.log(JSON.stringify(output, null, 2));

    if (args.error_if_entries === true) {
        for (var _el in output) {
            if (output[_el].count > 0) {
                process.exit(1);
            }
        }
    }
});
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIi4uLy4uL3NyYy9jbGkvY2hlY2stY3QtbG9ncy5qcyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiO0FBQ0E7O0FBRUE7O0FBRUE7OztBQUdBOztBQUNBOztBQUNBOztBQUVBLElBQU0sUUFBUSxRQUFRLE9BQVIsRUFDVCxLQURTLENBQ0gscUJBREcsRUFFVCxJQUZTLENBRUosTUFGSSxFQUdULE1BSFMsQ0FHRixRQUhFLEVBSVY7QUFDSTtBQUNBLFlBQVEsS0FGWjtBQUdJLFdBQU8sQ0FBQyxHQUFELEVBQU0sTUFBTixDQUhYO0FBSUksVUFBTSxRQUpWO0FBS0ksYUFBUyxpRUFMYjtBQU1JLGNBQVU7QUFOZCxDQUpVLEVBWVQsTUFaUyxDQVlGLGNBWkUsRUFhVjtBQUNJLFlBQVEsS0FEWjtBQUVJO0FBQ0EsVUFBTSxTQUhWO0FBSUksYUFBUyxLQUpiO0FBS0ksY0FBVTtBQUxkLENBYlUsRUFvQlQsTUFwQlMsQ0FvQkYsZUFwQkUsRUFxQlY7QUFDSSxZQUFRLEtBRFo7QUFFSTtBQUNBLFVBQU0sU0FIVjtBQUlJLGFBQVMsS0FKYjtBQUtJLGNBQVU7QUFMZCxDQXJCVSxFQTRCVCxNQTVCUyxDQTRCRixVQTVCRSxFQTZCVjtBQUNJLFlBQVEsS0FEWjtBQUVJO0FBQ0EsVUFBTSxTQUhWO0FBSUksYUFBUyxLQUpiO0FBS0ksY0FBVTtBQUxkLENBN0JVLEVBb0NULE1BcENTLENBb0NGLFlBcENFLEVBcUNWO0FBQ0ksWUFBUSxLQURaO0FBRUksVUFBTSxTQUZWO0FBR0ksYUFBUyxLQUhiO0FBSUksY0FBVTtBQUpkLENBckNVLEVBMkNULE1BM0NTLENBMkNGLHNCQTNDRSxFQTRDVjtBQUNJLFlBQVEsS0FEWjtBQUVJLFVBQU0sT0FGVjtBQUdJLFdBQU8sQ0FBQyxHQUFELEVBQU0sU0FBTixFQUFpQixVQUFqQixDQUhYO0FBSUksY0FBVTtBQUpkLENBNUNVLEVBa0RULE1BbERTLENBa0RGLGNBbERFLEVBbURWO0FBQ0ksWUFBUSxLQURaO0FBRUksVUFBTSxRQUZWO0FB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LEtBQUssZ0JBQUwsS0FBMEIsSUFBN0IsRUFDQTtBQUNJLGFBQUksSUFBSSxHQUFSLElBQWMsTUFBZCxFQUNBO0FBQ0ksZ0JBQUcsT0FBTyxHQUFQLEVBQVcsS0FBWCxHQUFtQixDQUF0QixFQUNBO0FBQ0ksd0JBQVEsSUFBUixDQUFhLENBQWI7QUFDSDtBQUNKO0FBQ0o7QUFDSixDQTdDRCIsImZpbGUiOiJjaGVjay1jdC1sb2dzLmpzIiwic291cmNlc0NvbnRlbnQiOlsiXG5cInVzZSBzdHJpY3RcIjtcblxuLy8gQ29yZSBkZXBzXG5cbi8vIDNyZCBwYXJ0eSBkZXBzXG5cblxuLy8gTG9jYWwgZGVwc1xuaW1wb3J0IHtjaGVja0NUTG9nc30gZnJvbSBcIi4uL2xpYi90bHMtY2VydGlmaWNhdGUtdHJhbnNwYXJlbmN5LWxvZy1jaGVja2VyLWxpYi5qc1wiO1xuaW1wb3J0IHt2ZXJzaW9uIGFzIGFwcFZlcnNpb259IGZyb20gXCIuLi8uLi9wYWNrYWdlLmpzb25cIjtcblxuY29uc3QgeWFyZ3MgPSByZXF1aXJlKFwieWFyZ3NcIilcbiAgICAudXNhZ2UoXCJVc2FnZTogJDAgW29wdGlvbnNdXCIpXG4gICAgLmhlbHAoXCJoZWxwXCIpXG4gICAgLm9wdGlvbihcImNvbmZpZ1wiLFxuICAgIHtcbiAgICAgICAgLy8gTk9URTogTm90IHN1cmUgd2h5IGJ1dCB5b3UgaGF2ZSB0byB1c2UgLS1jb25maWcgPHBhdGg+XG4gICAgICAgIGRlbWFuZDogZmFsc2UsXG4gICAgICAgIGFsaWFzOiBbXCJjXCIsIFwiY29uZlwiXSxcbiAgICAgICAgdHlwZTogXCJzdHJpbmdcIixcbiAgICAgICAgZGVmYXVsdDogXCIuLi8uLi9jb25maWcvdGxzLWNlcnRpZmljYXRlLXRyYW5zcGFyZW5jeS1sb2ctY2hlY2tlci1jb25maWcuanNcIixcbiAgICAgICAgZGVzY3JpYmU6IFwidGhlIChhYnNvbHV0ZSkgcGF0aCB0byBhIHNwZWNpZmljIGNvbmZpZ3VyYXRpb24gZmlsZSB3aGljaCBvdmVycmlkZXMgZGVmYXVsdHNcIlxuICAgIH0pXG4gICAgLm9wdGlvbihcIm5vX2FsbF9jZXJ0c1wiLFxuICAgIHtcbiAgICAgICAgZGVtYW5kOiBmYWxzZSxcbiAgICAgICAgLy8gYWxpYXM6IFtcIm5vLW5ld1wiXSwgLy8gRE9FU05UIFdPUktcbiAgICAgICAgdHlwZTogXCJib29sZWFuXCIsXG4gICAgICAgIGRlZmF1bHQ6IGZhbHNlLFxuICAgICAgICBkZXNjcmliZTogXCJpZiB0cnVlLCB0aGUgJ2FsbENlcnRzJyBjZXJ0aWZpY2F0ZXMgKGxpdGVyYWxseSBhbGwgY2VydHMgZm91bmQgaW4gdGhlIENUIGxvZ3Mgd2hvc2UgdmFsaWQgZnJvbSBkYXRhIGlzIG5ld2VyIHRoYW4gbm93IC0gY29uZmlnIG9wdGlvbiAnaWdub3JlQ2VydHNWYWxpZEZyb21CZWZvcmVUUycgKSBlbGVtZW50IG9mIHRoZSBvdXRwdXQgSlNPTiB3aWxsIGJlIG9taXR0ZWQgXCJcbiAgICB9KVxuICAgIC5vcHRpb24oXCJub191bmV4cGVjdGVkXCIsXG4gICAge1xuICAgICAgICBkZW1hbmQ6IGZhbHNlLFxuICAgICAgICAvLyBhbGlhczogW1wibm8tdW5leHBlY3RlZFwiXSwgLy8gRE9FU05UIFdPUktcbiAgICAgICAgdHlwZTogXCJib29sZWFuXCIsXG4gICAgICAgIGRlZmF1bHQ6IGZhbHNlLFxuICAgICAgICBkZXNjcmliZTogXCJpZiB0cnVlLCB0aGUgJ3VuZXhwZWN0ZWRDQScgY2VydGlmaWNhdGVzICh0aG9zZSBjZXJ0cyB3aG9zZSBDQSBkb2VzICpub3QqIG1hdGNoIGF0IGxlYXN0IG9uZSBvZiB0aGUgY29uZmlnIG9wdGlvbiAnZXhwZWN0ZWRDQXMnICkgZWxlbWVudCBvZiB0aGUgb3V0cHV0IEpTT04gd2lsbCBiZSBvbWl0dGVkIFwiXG4gICAgfSlcbiAgICAub3B0aW9uKFwibm9fYnlfY2FcIixcbiAgICB7XG4gICAgICAgIGRlbWFuZDogZmFsc2UsXG4gICAgICAgIC8vIGFsaWFzOiBbXCJuby1jYXNcIl0sIC8vIERPRVNOVCBXT1JLXG4gICAgICAgIHR5cGU6IFwiYm9vbGVhblwiLFxuICAgICAgICBkZWZhdWx0OiBmYWxzZSxcbiAgICAgICAgZGVzY3JpYmU6IFwiaWYgdHJ1ZSwgdGhlICdieUNBJyBlbGVtZW50IG9mIHRoZSBvdXRwdXQgSlNPTiB3aWxsIGJlIG9taXR0ZWQgXCJcbiAgICB9KVxuICAgIC5vcHRpb24oXCJub19lbnRyaWVzXCIsXG4gICAge1xuICAgICAgICBkZW1hbmQ6IGZhbHNlLFxuICAgICAgICB0eXBlOiBcImJvb2xlYW5cIixcbiAgICAgICAgZGVmYXVsdDogZmFsc2UsXG4gICAgICAgIGRlc2NyaWJlOiBcImlmIHRydWUsIHRoZSAnZW50cmllcycgcHJvcGVydHkgb2YgZWFjaCBhbGxDZXJ0cywgdW5leHBlY3RlZENBIGFuZCBieUNBIGVsZW1lbnRzIG9mIHRoZSBvdXRwdXQgSlNPTiB3aWxsIGJlIG9taXR0ZWQgXCJcbiAgICB9KVxuICAgIC5vcHRpb24oXCJkb21haW5fbmFtZV9wYXR0ZXJuc1wiLFxuICAgIHtcbiAgICAgICAgZGVtYW5kOiBmYWxzZSxcbiAgICAgICAgdHlwZTogXCJhcnJheVwiLFxuICAgICAgICBhbGlhczogW1wiZFwiLCBcImRvbWFpbnNcIiwgXCJwYXR0ZXJuc1wiXSxcbiAgICAgICAgZGVzY3JpYmU6IFwiQSBzcGFjZS1zZXBhcmF0ZWQgbGlzdCBvZiBxdW90ZWQgKHN0cmluZykgZG9tYWluIG5hbWUgcGF0dGVybnMgdG8gc2VhcmNoIGZvciBlLmcuIC0tZG9tYWluX25hbWVfcGF0dGVybnMgXFxcIiUuZXhhbXBsZS5jb21cXFwiIFxcXCJiLmV4YW1wbGUub3JnXFxcIiBcXFwiJS5jLmV4YW1wbGUubmV0XFxcIlwiXG4gICAgfSlcbiAgICAub3B0aW9uKFwiZXhwZWN0ZWRfY2FzXCIsXG4gICAge1xuICAgICAgICBkZW1hbmQ6IGZhbHNlLFxuICAgICAgICB0eXBlOiBcInN0cmluZ1wiLFxuICAgICAgICBhbGlhczogW1wiY2FcIiwgXCJjYXNcIl0sXG4gICAgICAgIGRlc2NyaWJlOiBcIkEgY29tbWEtc2VwYXJhdGVkIGxpc3Qgb2YgKGNhc2Utc2Vuc2l0aXZlKSBzdHJpbmdpZmllZCByZWdleGVzIHRvIG1hdGNoIHRoZSBDZXJ0aWZpY2F0ZSBBdXRob3JpdGllcyBpbiB0aGUgcmV0dXJuZWQgY2VydGlmaWNhdGVzIGFnYWluc3QgZS5nLiBcXFwiLipTb21lQ0EuKiwgQW5vdGhlckNBLipcXFwiXCJcbiAgICB9KVxuICAgIC5vcHRpb24oXCJ2YWxpZF9mcm9tXCIsXG4gICAge1xuICAgICAgICBkZW1hbmQ6IGZhbHNlLFxuICAgICAgICB0eXBlOiBcIm51bWJlclwiLFxuICAgICAgICBhbGlhczogW1widmZcIiwgXCJmcm9tXCJdLFxuICAgICAgICBkZXNjcmliZTogXCJBIFVuaXggdGltZXN0YW1wIChpbnRlZ2VyIG51bWJlciBvZiBzZWNvbmRzIHNpbmNlIHRoZSBVbml4IGVwb2NoKS4gQ2VydGlmaWNhdGVzIHdob3NlICd2YWxpZCBmcm9tJyBkYXRlIGlzIG9sZGVyIHRoYW4gdGhpcyB3aWxsIGJlIG9taXR0ZWQgZnJvbSB0aGUgb3V0cHV0LiBEZWZhdWx0cyB0byB5b3VyIGNvbmZpZyBmaWxlIHZhbHVlIHdoaWNoIHNoaXBzIGFzIDAuXCJcbiAgICB9KVxuICAgIC5vcHRpb24oXCJ2YWxpZF90b1wiLFxuICAgIHtcbiAgICAgICAgZGVtYW5kOiBmYWxzZSxcbiAgICAgICAgdHlwZTogXCJudW1iZXJcIixcbiAgICAgICAgYWxpYXM6IFtcInZ0XCIsIFwidG9cIiwgXCJ2YWxpZF90b1wiXSxcbiAgICAgICAgZGVzY3JpYmU6IFwiQSBVbml4IHRpbWVzdGFtcCAoaW50ZWdlciBudW1iZXIgb2Ygc2Vjb25kcyBzaW5jZSB0aGUgVW5peCBlcG9jaCkuIENlcnRpZmljYXRlcyB3aG9zZSAndmFsaWQgdW50aWwnIGRhdGUgaXMgbmV3ZXIgdGhhbiB0aGlzIHdpbGwgYmUgb21pdHRlZCBmcm9tIHRoZSBvdXRwdXQuIERlZmF1bHRzIHRvIHlvdXIgY29uZmlnIGZpbGUgdmFsdWUgd2hpY2ggc2hpcHMgYXMgJ25vdycuXCJcbiAgICB9KVxuICAgIC5vcHRpb24oXCJlcnJvcl9pZl9lbnRyaWVzXCIsXG4gICAge1xuICAgICAgICBkZW1hbmQ6IGZhbHNlLFxuICAgICAgICB0eXBlOiBcImJvb2xlYW5cIixcbiAgICAgICAgZGVmYXVsdDogZmFsc2UsXG4gICAgICAgIGFsaWFzOiBbXCJlXCIsIFwiZXJyb3JcIl0sXG4gICAgICAgIGRlc2NyaWJlOiBcIkEgYm9vbGVhbiB0byBkZXRlcm1pbmUgd2hldGhlciBvciBub3QgdG8gZXhpdCB3aXRoIGEgbm9uLXplcm8gKDEpIHJldHVybiBjb2RlIGlmIGFueSBlbnRyaWVzIGFyZSBmb3VuZCB3aXRoIHByb3ZpZGVkIGZpbHRlcnNcIlxuICAgIH0pXG4gICAgLm9wdGlvbihcImhlbHBcIixcbiAgICB7XG4gICAgICAgIGRlbWFuZDogZmFsc2UsXG4gICAgICAgIGFsaWFzOiBcImhcIlxuICAgIH0pLm9wdGlvbihcInZlcnNpb25cIixcbiAgICB7XG4gICAgICAgIGRlbWFuZDogZmFsc2UsXG4gICAgICAgIGFsaWFzOiBbXCJ2XCIsIFwidmVyXCJdLFxuICAgICAgICB0eXBlOiBcImJvb2xlYW5cIixcbiAgICAgICAgZGVzY3JpYmU6IFwiU2hvdyB0aGUgdmVyc2lvbiBudW1iZXIgYW5kIGV4aXRcIlxuICAgIH1cbik7XG5cbnlhcmdzLndyYXAoeWFyZ3MudGVybWluYWxXaWR0aCgpKTtcblxubGV0IGFyZ3MgPSB5YXJncy5hcmd2O1xuXG4vLyBTaG93IHZlcnNpb24gbnVtYmVyIGZyb20gcGFja2FnZS5qc29uIGFuZCBleGl0IHdpdGggcmV0dXJuIGNvZGUgMFxuaWYoYXJncy52ZXJzaW9uKVxue1xuICAgIGNvbnNvbGUubG9nKGFwcFZlcnNpb24pO1xuICAgIHByb2Nlc3MuZXhpdCgpO1xufVxuXG5sZXQgY29uZmlnID0gbnVsbDtcbnRyeVxue1xuICAgIGNvbmZpZyA9IHJlcXVpcmUoYXJncy5jb25maWcpOyAvLyBOT1RFOiBQYXRoIGlzIHJlbGF0aXZlIHRvIGJ1aWxkIGRpciAoZGlzdC9jbGkvKVxcXG59XG5jYXRjaChlKVxue1xuICAgIHRocm93IGU7XG59XG5cbmxldCBkb21haW5OYW1lUGF0dGVybnMgPSBhcmdzLmRvbWFpbl9uYW1lX3BhdHRlcm5zIHx8IGNvbmZpZy5kb21haW5OYW1lUGF0dGVybnM7XG5sZXQgaWdub3JlQ2VydHNWYWxpZEZyb21CZWZvcmVUUyA9IGFyZ3MudmFsaWRfZnJvbSB8fCBjb25maWcuaWdub3JlQ2VydHNWYWxpZEZyb21CZWZvcmVUUztcbmxldCBpZ25vcmVDZXJ0c1ZhbGlkVG9CZWZvcmVUUyA9IGFyZ3MudmFsaWRfdG8gfHwgY29uZmlnLmlnbm9yZUNlcnRzVmFsaWRUb0JlZm9yZVRTO1xuXG4vLyBpZiBpZ25vcmVDZXJ0c1ZhbGlkVG9CZWZvcmVUUyA9PT0gMCwgc2V0IHRvIFwibm93XCJcbmlmKGlnbm9yZUNlcnRzVmFsaWRUb0JlZm9yZVRTID09PSAwKVxue1xuICAgIGlnbm9yZUNlcnRzVmFsaWRUb0JlZm9yZVRTID0gcGFyc2VJbnQobmV3IERhdGUoKS5nZXRUaW1lKCkgLyAxMDAwLCAxMCk7XG59XG5cbmxldCBleHBlY3RlZENBcyA9IGNvbmZpZy5leHBlY3RlZENBcztcblxuaWYoYXJncy5leHBlY3RlZF9jYXMpXG57XG4gICAgZXhwZWN0ZWRDQXMgPSBhcmdzLmV4cGVjdGVkX2Nhcy5zcGxpdChcIixcIikubWFwKChjKSA9PlxuICAgIHtcbiAgICAgICAgcmV0dXJuIG5ldyBSZWdFeHAoYy50cmltKCkpO1xuICAgIH0pO1xufVxuXG5jaGVja0NUTG9ncyhkb21haW5OYW1lUGF0dGVybnMsIGlnbm9yZUNlcnRzVmFsaWRGcm9tQmVmb3JlVFMsIGlnbm9yZUNlcnRzVmFsaWRUb0JlZm9yZVRTLCBleHBlY3RlZENBcywgKGNoZWNrQ1RMb2dzRXJyLCBjaGVja0NUTG9nc1JlcykgPT5cbntcbiAgICBpZihjaGVja0NUTG9nc0VycilcbiAgICB7XG4gICAgICAgIHRocm93IGNoZWNrQ1RMb2dzRXJyO1xuICAgIH1cblxuICAgIGxldCBvdXRwdXQgPSBjaGVja0NUTG9nc1JlcztcblxuLy8gUmVtb3ZlIHVuZGVzaXJlZCBvdXRwdXQgLSB5ZWFoLCB0aGlzIGlzIGEgY3JhcHB5IG1ldGhvZCBidXQgd2lsbCBkbyBmb3Igbm93XG4gICAgaWYoYXJncy5ub19hbGxfY2VydHMpXG4gICAge1xuICAgICAgICBkZWxldGUgb3V0cHV0LmFsbENlcnRzO1xuICAgIH1cblxuICAgIGlmKGFyZ3Mubm9fdW5leHBlY3RlZClcbiAgICB7XG4gICAgICAgIGRlbGV0ZSBvdXRwdXQudW5leHBlY3RlZENBO1xuICAgIH1cblxuICAgIGlmKGFyZ3Mubm9fYnlfY2EpXG4gICAge1xuICAgICAgICBkZWxldGUgb3V0cHV0LmJ5Q0E7XG4gICAgfVxuXG4gICAgaWYoYXJncy5ub19lbnRyaWVzKVxuICAgIHtcbiAgICAgICAgZm9yKGxldCBlbCBpbiBvdXRwdXQpXG4gICAgICAgIHtcbiAgICAgICAgICAgIGRlbGV0ZSBvdXRwdXRbZWxdLmVudHJpZXM7XG4gICAgICAgIH1cbiAgICB9XG5cbiAgICBjb25zb2xlLmxvZyhKU09OLnN0cmluZ2lmeShvdXRwdXQsIG51bGwsIDIpKTtcblxuICAgIGlmKGFyZ3MuZXJyb3JfaWZfZW50cmllcyA9PT0gdHJ1ZSlcbiAgICB7XG4gICAgICAgIGZvcihsZXQgZWwgaW4gb3V0cHV0KVxuICAgICAgICB7XG4gICAgICAgICAgICBpZihvdXRwdXRbZWxdLmNvdW50ID4gMClcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBwcm9jZXNzLmV4aXQoMSk7XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICB9XG59KTtcbiJdfQ==