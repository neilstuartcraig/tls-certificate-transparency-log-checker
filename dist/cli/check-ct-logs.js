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
    describe: "A Unix timestamp (integer number of seconds since the Unix epoch). Certificates whose 'valid from' date is older than this will be omitted from the output"
}).option("valid_to", {
    demand: false,
    type: "number",
    alias: ["vt", "to", "valid_to"],
    describe: "A Unix timestamp (integer number of seconds since the Unix epoch). Certificates whose 'valid until' date is newer than this will be omitted from the output"
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
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIi4uLy4uL3NyYy9jbGkvY2hlY2stY3QtbG9ncy5qcyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiO0FBQ0E7O0FBRUE7O0FBRUE7OztBQUdBOztBQUNBOztBQUNBOztBQUVBLElBQU0sUUFBUSxRQUFRLE9BQVIsRUFDVCxLQURTLENBQ0gscUJBREcsRUFFVCxJQUZTLENBRUosTUFGSSxFQUdULE1BSFMsQ0FHRixRQUhFLEVBSVY7QUFDSTtBQUNBLFlBQVEsS0FGWjtBQUdJLFdBQU8sQ0FBQyxHQUFELEVBQU0sTUFBTixDQUhYO0FBSUksVUFBTSxRQUpWO0FBS0ksYUFBUyxpRUFMYjtBQU1JLGNBQVU7QUFOZCxDQUpVLEVBWVQsTUFaUyxDQVlGLGNBWkUsRUFhVjtBQUNJLFlBQVEsS0FEWjtBQUVJO0FBQ0EsVUFBTSxTQUhWO0FBSUksYUFBUyxLQUpiO0FBS0ksY0FBVTtBQUxkLENBYlUsRUFvQlQsTUFwQlMsQ0FvQkYsZUFwQkUsRUFxQlY7QUFDSSxZQUFRLEtBRFo7QUFFSTtBQUNBLFVBQU0sU0FIVjtBQUlJLGFBQVMsS0FKYjtBQUtJLGNBQVU7QUFMZCxDQXJCVSxFQTRCVCxNQTVCUyxDQTRCRixVQTVCRSxFQTZCVjtBQUNJLFlBQVEsS0FEWjtBQUVJO0FBQ0EsVUFBTSxTQUhWO0FBSUksYUFBUyxLQUpiO0FBS0ksY0FBVTtBQUxkLENBN0JVLEVBb0NULE1BcENTLENBb0NGLFlBcENFLEVBcUNWO0FBQ0ksWUFBUSxLQURaO0FBRUksVUFBTSxTQUZWO0FBR0ksYUFBUyxLQUhiO0FBSUksY0FBVTtBQUpkLENBckNVLEVBMkNULE1BM0NTLENBMkNGLHNCQTNDRSxFQTRDVjtBQUNJLFlBQVEsS0FEWjtBQUVJLFVBQU0sT0FGVjtBQUdJLFdBQU8sQ0FBQyxHQUFELEVBQU0sU0FBTixFQUFpQixVQUFqQixDQUhYO0FBSUksY0FBVTtBQUpkLENBNUNVLEVBa0RULE1BbERTLENBa0RGLGNBbERFLEVBbURWO0FBQ0ksWUFBUSxLQURaO0FBRUksVUFBTSxRQUZWO0FB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LEtBQUssZ0JBQUwsS0FBMEIsSUFBN0IsRUFDQTtBQUNJLGFBQUksSUFBSSxHQUFSLElBQWMsTUFBZCxFQUNBO0FBQ0ksZ0JBQUcsT0FBTyxHQUFQLEVBQVcsS0FBWCxHQUFtQixDQUF0QixFQUNBO0FBQ0ksd0JBQVEsSUFBUixDQUFhLENBQWI7QUFDSDtBQUNKO0FBQ0o7QUFDSixDQTdDRCIsImZpbGUiOiJjaGVjay1jdC1sb2dzLmpzIiwic291cmNlc0NvbnRlbnQiOlsiXG5cInVzZSBzdHJpY3RcIjtcblxuLy8gQ29yZSBkZXBzXG5cbi8vIDNyZCBwYXJ0eSBkZXBzXG5cblxuLy8gTG9jYWwgZGVwc1xuaW1wb3J0IHtjaGVja0NUTG9nc30gZnJvbSBcIi4uL2xpYi90bHMtY2VydGlmaWNhdGUtdHJhbnNwYXJlbmN5LWxvZy1jaGVja2VyLWxpYi5qc1wiO1xuaW1wb3J0IHt2ZXJzaW9uIGFzIGFwcFZlcnNpb259IGZyb20gXCIuLi8uLi9wYWNrYWdlLmpzb25cIjtcblxuY29uc3QgeWFyZ3MgPSByZXF1aXJlKFwieWFyZ3NcIilcbiAgICAudXNhZ2UoXCJVc2FnZTogJDAgW29wdGlvbnNdXCIpXG4gICAgLmhlbHAoXCJoZWxwXCIpXG4gICAgLm9wdGlvbihcImNvbmZpZ1wiLFxuICAgIHtcbiAgICAgICAgLy8gTk9URTogTm90IHN1cmUgd2h5IGJ1dCB5b3UgaGF2ZSB0byB1c2UgLS1jb25maWcgPHBhdGg+XG4gICAgICAgIGRlbWFuZDogZmFsc2UsXG4gICAgICAgIGFsaWFzOiBbXCJjXCIsIFwiY29uZlwiXSxcbiAgICAgICAgdHlwZTogXCJzdHJpbmdcIixcbiAgICAgICAgZGVmYXVsdDogXCIuLi8uLi9jb25maWcvdGxzLWNlcnRpZmljYXRlLXRyYW5zcGFyZW5jeS1sb2ctY2hlY2tlci1jb25maWcuanNcIixcbiAgICAgICAgZGVzY3JpYmU6IFwidGhlIChhYnNvbHV0ZSkgcGF0aCB0byBhIHNwZWNpZmljIGNvbmZpZ3VyYXRpb24gZmlsZSB3aGljaCBvdmVycmlkZXMgZGVmYXVsdHNcIlxuICAgIH0pXG4gICAgLm9wdGlvbihcIm5vX2FsbF9jZXJ0c1wiLFxuICAgIHtcbiAgICAgICAgZGVtYW5kOiBmYWxzZSxcbiAgICAgICAgLy8gYWxpYXM6IFtcIm5vLW5ld1wiXSwgLy8gRE9FU05UIFdPUktcbiAgICAgICAgdHlwZTogXCJib29sZWFuXCIsXG4gICAgICAgIGRlZmF1bHQ6IGZhbHNlLFxuICAgICAgICBkZXNjcmliZTogXCJpZiB0cnVlLCB0aGUgJ2FsbENlcnRzJyBjZXJ0aWZpY2F0ZXMgKGxpdGVyYWxseSBhbGwgY2VydHMgZm91bmQgaW4gdGhlIENUIGxvZ3Mgd2hvc2UgdmFsaWQgZnJvbSBkYXRhIGlzIG5ld2VyIHRoYW4gbm93IC0gY29uZmlnIG9wdGlvbiAnaWdub3JlQ2VydHNWYWxpZEZyb21CZWZvcmVUUycgKSBlbGVtZW50IG9mIHRoZSBvdXRwdXQgSlNPTiB3aWxsIGJlIG9taXR0ZWQgXCJcbiAgICB9KVxuICAgIC5vcHRpb24oXCJub191bmV4cGVjdGVkXCIsXG4gICAge1xuICAgICAgICBkZW1hbmQ6IGZhbHNlLFxuICAgICAgICAvLyBhbGlhczogW1wibm8tdW5leHBlY3RlZFwiXSwgLy8gRE9FU05UIFdPUktcbiAgICAgICAgdHlwZTogXCJib29sZWFuXCIsXG4gICAgICAgIGRlZmF1bHQ6IGZhbHNlLFxuICAgICAgICBkZXNjcmliZTogXCJpZiB0cnVlLCB0aGUgJ3VuZXhwZWN0ZWRDQScgY2VydGlmaWNhdGVzICh0aG9zZSBjZXJ0cyB3aG9zZSBDQSBkb2VzICpub3QqIG1hdGNoIGF0IGxlYXN0IG9uZSBvZiB0aGUgY29uZmlnIG9wdGlvbiAnZXhwZWN0ZWRDQXMnICkgZWxlbWVudCBvZiB0aGUgb3V0cHV0IEpTT04gd2lsbCBiZSBvbWl0dGVkIFwiXG4gICAgfSlcbiAgICAub3B0aW9uKFwibm9fYnlfY2FcIixcbiAgICB7XG4gICAgICAgIGRlbWFuZDogZmFsc2UsXG4gICAgICAgIC8vIGFsaWFzOiBbXCJuby1jYXNcIl0sIC8vIERPRVNOVCBXT1JLXG4gICAgICAgIHR5cGU6IFwiYm9vbGVhblwiLFxuICAgICAgICBkZWZhdWx0OiBmYWxzZSxcbiAgICAgICAgZGVzY3JpYmU6IFwiaWYgdHJ1ZSwgdGhlICdieUNBJyBlbGVtZW50IG9mIHRoZSBvdXRwdXQgSlNPTiB3aWxsIGJlIG9taXR0ZWQgXCJcbiAgICB9KVxuICAgIC5vcHRpb24oXCJub19lbnRyaWVzXCIsXG4gICAge1xuICAgICAgICBkZW1hbmQ6IGZhbHNlLFxuICAgICAgICB0eXBlOiBcImJvb2xlYW5cIixcbiAgICAgICAgZGVmYXVsdDogZmFsc2UsXG4gICAgICAgIGRlc2NyaWJlOiBcImlmIHRydWUsIHRoZSAnZW50cmllcycgcHJvcGVydHkgb2YgZWFjaCBhbGxDZXJ0cywgdW5leHBlY3RlZENBIGFuZCBieUNBIGVsZW1lbnRzIG9mIHRoZSBvdXRwdXQgSlNPTiB3aWxsIGJlIG9taXR0ZWQgXCJcbiAgICB9KVxuICAgIC5vcHRpb24oXCJkb21haW5fbmFtZV9wYXR0ZXJuc1wiLFxuICAgIHtcbiAgICAgICAgZGVtYW5kOiBmYWxzZSxcbiAgICAgICAgdHlwZTogXCJhcnJheVwiLFxuICAgICAgICBhbGlhczogW1wiZFwiLCBcImRvbWFpbnNcIiwgXCJwYXR0ZXJuc1wiXSxcbiAgICAgICAgZGVzY3JpYmU6IFwiQSBzcGFjZS1zZXBhcmF0ZWQgbGlzdCBvZiBxdW90ZWQgKHN0cmluZykgZG9tYWluIG5hbWUgcGF0dGVybnMgdG8gc2VhcmNoIGZvciBlLmcuIC0tZG9tYWluX25hbWVfcGF0dGVybnMgXFxcIiUuZXhhbXBsZS5jb21cXFwiIFxcXCJiLmV4YW1wbGUub3JnXFxcIiBcXFwiJS5jLmV4YW1wbGUubmV0XFxcIlwiXG4gICAgfSlcbiAgICAub3B0aW9uKFwiZXhwZWN0ZWRfY2FzXCIsXG4gICAge1xuICAgICAgICBkZW1hbmQ6IGZhbHNlLFxuICAgICAgICB0eXBlOiBcInN0cmluZ1wiLFxuICAgICAgICBhbGlhczogW1wiY2FcIiwgXCJjYXNcIl0sXG4gICAgICAgIGRlc2NyaWJlOiBcIkEgY29tbWEtc2VwYXJhdGVkIGxpc3Qgb2YgKGNhc2Utc2Vuc2l0aXZlKSBzdHJpbmdpZmllZCByZWdleGVzIHRvIG1hdGNoIHRoZSBDZXJ0aWZpY2F0ZSBBdXRob3JpdGllcyBpbiB0aGUgcmV0dXJuZWQgY2VydGlmaWNhdGVzIGFnYWluc3QgZS5nLiBcXFwiLipTb21lQ0EuKiwgQW5vdGhlckNBLipcXFwiXCJcbiAgICB9KVxuICAgIC5vcHRpb24oXCJ2YWxpZF9mcm9tXCIsXG4gICAge1xuICAgICAgICBkZW1hbmQ6IGZhbHNlLFxuICAgICAgICB0eXBlOiBcIm51bWJlclwiLFxuICAgICAgICBhbGlhczogW1widmZcIiwgXCJmcm9tXCJdLFxuICAgICAgICBkZXNjcmliZTogXCJBIFVuaXggdGltZXN0YW1wIChpbnRlZ2VyIG51bWJlciBvZiBzZWNvbmRzIHNpbmNlIHRoZSBVbml4IGVwb2NoKS4gQ2VydGlmaWNhdGVzIHdob3NlICd2YWxpZCBmcm9tJyBkYXRlIGlzIG9sZGVyIHRoYW4gdGhpcyB3aWxsIGJlIG9taXR0ZWQgZnJvbSB0aGUgb3V0cHV0XCJcbiAgICB9KVxuICAgIC5vcHRpb24oXCJ2YWxpZF90b1wiLFxuICAgIHtcbiAgICAgICAgZGVtYW5kOiBmYWxzZSxcbiAgICAgICAgdHlwZTogXCJudW1iZXJcIixcbiAgICAgICAgYWxpYXM6IFtcInZ0XCIsIFwidG9cIiwgXCJ2YWxpZF90b1wiXSxcbiAgICAgICAgZGVzY3JpYmU6IFwiQSBVbml4IHRpbWVzdGFtcCAoaW50ZWdlciBudW1iZXIgb2Ygc2Vjb25kcyBzaW5jZSB0aGUgVW5peCBlcG9jaCkuIENlcnRpZmljYXRlcyB3aG9zZSAndmFsaWQgdW50aWwnIGRhdGUgaXMgbmV3ZXIgdGhhbiB0aGlzIHdpbGwgYmUgb21pdHRlZCBmcm9tIHRoZSBvdXRwdXRcIlxuICAgIH0pXG4gICAgLm9wdGlvbihcImVycm9yX2lmX2VudHJpZXNcIixcbiAgICB7XG4gICAgICAgIGRlbWFuZDogZmFsc2UsXG4gICAgICAgIHR5cGU6IFwiYm9vbGVhblwiLFxuICAgICAgICBkZWZhdWx0OiBmYWxzZSxcbiAgICAgICAgYWxpYXM6IFtcImVcIiwgXCJlcnJvclwiXSxcbiAgICAgICAgZGVzY3JpYmU6IFwiQSBib29sZWFuIHRvIGRldGVybWluZSB3aGV0aGVyIG9yIG5vdCB0byBleGl0IHdpdGggYSBub24temVybyAoMSkgcmV0dXJuIGNvZGUgaWYgYW55IGVudHJpZXMgYXJlIGZvdW5kIHdpdGggcHJvdmlkZWQgZmlsdGVyc1wiXG4gICAgfSlcbiAgICAub3B0aW9uKFwiaGVscFwiLFxuICAgIHtcbiAgICAgICAgZGVtYW5kOiBmYWxzZSxcbiAgICAgICAgYWxpYXM6IFwiaFwiXG4gICAgfSkub3B0aW9uKFwidmVyc2lvblwiLFxuICAgIHtcbiAgICAgICAgZGVtYW5kOiBmYWxzZSxcbiAgICAgICAgYWxpYXM6IFtcInZcIiwgXCJ2ZXJcIl0sXG4gICAgICAgIHR5cGU6IFwiYm9vbGVhblwiLFxuICAgICAgICBkZXNjcmliZTogXCJTaG93IHRoZSB2ZXJzaW9uIG51bWJlciBhbmQgZXhpdFwiXG4gICAgfVxuKTtcblxueWFyZ3Mud3JhcCh5YXJncy50ZXJtaW5hbFdpZHRoKCkpO1xuXG5sZXQgYXJncyA9IHlhcmdzLmFyZ3Y7XG5cbi8vIFNob3cgdmVyc2lvbiBudW1iZXIgZnJvbSBwYWNrYWdlLmpzb24gYW5kIGV4aXQgd2l0aCByZXR1cm4gY29kZSAwXG5pZihhcmdzLnZlcnNpb24pXG57XG4gICAgY29uc29sZS5sb2coYXBwVmVyc2lvbik7XG4gICAgcHJvY2Vzcy5leGl0KCk7XG59XG5cbmxldCBjb25maWcgPSBudWxsO1xudHJ5XG57XG4gICAgY29uZmlnID0gcmVxdWlyZShhcmdzLmNvbmZpZyk7IC8vIE5PVEU6IFBhdGggaXMgcmVsYXRpdmUgdG8gYnVpbGQgZGlyIChkaXN0L2NsaS8pXFxcbn1cbmNhdGNoKGUpXG57XG4gICAgdGhyb3cgZTtcbn1cblxubGV0IGRvbWFpbk5hbWVQYXR0ZXJucyA9IGFyZ3MuZG9tYWluX25hbWVfcGF0dGVybnMgfHwgY29uZmlnLmRvbWFpbk5hbWVQYXR0ZXJucztcbmxldCBpZ25vcmVDZXJ0c1ZhbGlkRnJvbUJlZm9yZVRTID0gYXJncy52YWxpZF9mcm9tIHx8IGNvbmZpZy5pZ25vcmVDZXJ0c1ZhbGlkRnJvbUJlZm9yZVRTO1xubGV0IGlnbm9yZUNlcnRzVmFsaWRUb0JlZm9yZVRTID0gYXJncy52YWxpZF90byB8fCBjb25maWcuaWdub3JlQ2VydHNWYWxpZFRvQmVmb3JlVFM7XG5cbi8vIGlmIGlnbm9yZUNlcnRzVmFsaWRUb0JlZm9yZVRTID09PSAwLCBzZXQgdG8gXCJub3dcIlxuaWYoaWdub3JlQ2VydHNWYWxpZFRvQmVmb3JlVFMgPT09IDApXG57XG4gICAgaWdub3JlQ2VydHNWYWxpZFRvQmVmb3JlVFMgPSBwYXJzZUludChuZXcgRGF0ZSgpLmdldFRpbWUoKSAvIDEwMDAsIDEwKTtcbn1cblxubGV0IGV4cGVjdGVkQ0FzID0gY29uZmlnLmV4cGVjdGVkQ0FzO1xuXG5pZihhcmdzLmV4cGVjdGVkX2NhcylcbntcbiAgICBleHBlY3RlZENBcyA9IGFyZ3MuZXhwZWN0ZWRfY2FzLnNwbGl0KFwiLFwiKS5tYXAoKGMpID0+XG4gICAge1xuICAgICAgICByZXR1cm4gbmV3IFJlZ0V4cChjLnRyaW0oKSk7XG4gICAgfSk7XG59XG5cbmNoZWNrQ1RMb2dzKGRvbWFpbk5hbWVQYXR0ZXJucywgaWdub3JlQ2VydHNWYWxpZEZyb21CZWZvcmVUUywgaWdub3JlQ2VydHNWYWxpZFRvQmVmb3JlVFMsIGV4cGVjdGVkQ0FzLCAoY2hlY2tDVExvZ3NFcnIsIGNoZWNrQ1RMb2dzUmVzKSA9Plxue1xuICAgIGlmKGNoZWNrQ1RMb2dzRXJyKVxuICAgIHtcbiAgICAgICAgdGhyb3cgY2hlY2tDVExvZ3NFcnI7XG4gICAgfVxuXG4gICAgbGV0IG91dHB1dCA9IGNoZWNrQ1RMb2dzUmVzO1xuXG4vLyBSZW1vdmUgdW5kZXNpcmVkIG91dHB1dCAtIHllYWgsIHRoaXMgaXMgYSBjcmFwcHkgbWV0aG9kIGJ1dCB3aWxsIGRvIGZvciBub3dcbiAgICBpZihhcmdzLm5vX2FsbF9jZXJ0cylcbiAgICB7XG4gICAgICAgIGRlbGV0ZSBvdXRwdXQuYWxsQ2VydHM7XG4gICAgfVxuXG4gICAgaWYoYXJncy5ub191bmV4cGVjdGVkKVxuICAgIHtcbiAgICAgICAgZGVsZXRlIG91dHB1dC51bmV4cGVjdGVkQ0E7XG4gICAgfVxuXG4gICAgaWYoYXJncy5ub19ieV9jYSlcbiAgICB7XG4gICAgICAgIGRlbGV0ZSBvdXRwdXQuYnlDQTtcbiAgICB9XG5cbiAgICBpZihhcmdzLm5vX2VudHJpZXMpXG4gICAge1xuICAgICAgICBmb3IobGV0IGVsIGluIG91dHB1dClcbiAgICAgICAge1xuICAgICAgICAgICAgZGVsZXRlIG91dHB1dFtlbF0uZW50cmllcztcbiAgICAgICAgfVxuICAgIH1cblxuICAgIGNvbnNvbGUubG9nKEpTT04uc3RyaW5naWZ5KG91dHB1dCwgbnVsbCwgMikpO1xuXG4gICAgaWYoYXJncy5lcnJvcl9pZl9lbnRyaWVzID09PSB0cnVlKVxuICAgIHtcbiAgICAgICAgZm9yKGxldCBlbCBpbiBvdXRwdXQpXG4gICAgICAgIHtcbiAgICAgICAgICAgIGlmKG91dHB1dFtlbF0uY291bnQgPiAwKVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHByb2Nlc3MuZXhpdCgxKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgIH1cbn0pO1xuIl19