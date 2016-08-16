#!/usr/bin/env node

"use strict";

// Core deps

// 3rd party deps

var _http = require("http2");

var _xml2json = require("xml2json");

var _tlsCertificateTransparencyLogCheckerLib = require("../lib/tls-certificate-transparency-log-checker-lib.js");

var _tlsCertificateTransparencyLogCheckerLib2 = _interopRequireDefault(_tlsCertificateTransparencyLogCheckerLib);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

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
}).option("help", {
    demand: false,
    alias: "h"
});

// Local deps


var args = yargs.argv;

var config = null;
try {
    config = require(args.config); // NOTE: Path is relative to build dir (dist/cli/)\
} catch (e) {
    throw e;
}

(0, _tlsCertificateTransparencyLogCheckerLib2.default)(_http.get, _xml2json.toJson, config.domainNamePatterns, config.ignoreCertsValidFromBeforeTS, config.ignoreCertsValidToBeforeTS, config.expectedCAs, function (checkCTLogsErr, checkCTLogsRes) {
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
});
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIi4uLy4uL3NyYy9jbGkvY2hlY2stY3QtbG9ncy5qcyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiO0FBQ0E7O0FBRUE7O0FBRUE7O0FBQ0E7O0FBQ0E7O0FBR0E7Ozs7OztBQUVBLElBQU0sUUFBUSxRQUFRLE9BQVIsRUFDVCxLQURTLENBQ0gscUJBREcsRUFFVCxJQUZTLENBRUosTUFGSSxFQUdULE1BSFMsQ0FHRixRQUhFLEVBSVY7QUFDSTtBQUNBLFlBQVEsS0FGWjtBQUdJLFdBQU8sQ0FBQyxHQUFELEVBQU0sTUFBTixDQUhYO0FBSUksVUFBTSxRQUpWO0FBS0ksYUFBUyxpRUFMYjtBQU1JLGNBQVU7QUFOZCxDQUpVLEVBWVQsTUFaUyxDQVlGLGNBWkUsRUFhVjtBQUNJLFlBQVEsS0FEWjtBQUVJO0FBQ0EsVUFBTSxTQUhWO0FBSUksYUFBUyxLQUpiO0FBS0ksY0FBVTtBQUxkLENBYlUsRUFvQlQsTUFwQlMsQ0FvQkYsZUFwQkUsRUFxQlY7QUFDSSxZQUFRLEtBRFo7QUFFSTtBQUNBLFVBQU0sU0FIVjtBQUlJLGFBQVMsS0FKYjtBQUtJLGNBQVU7QUFMZCxDQXJCVSxFQTRCVCxNQTVCUyxDQTRCRixVQTVCRSxFQTZCVjtBQUNJLFlBQVEsS0FEWjtBQUVJO0FBQ0EsVUFBTSxTQUhWO0FBSUksYUFBUyxLQUpiO0FBS0ksY0FBVTtBQUxkLENBN0JVLEVBb0NULE1BcENTLENBb0NGLFlBcENFLEVBcUNWO0FBQ0ksWUFBUSxLQURaO0FBRUksVUFBTSxTQUZWO0FBR0ksYUFBUyxLQUhiO0FBSUksY0FBVTtBQUpkLENBckNVLEVBMkNULE1BM0NTLENBMkNGLE1BM0NFLEVBNENWO0FBQ0ksWUFBUSxLQURaO0FBRUksV0FBTztBQUZYLENBNUNVLENBQWQ7O0FBSEE7OztBQXFEQSxJQUFJLE9BQU8sTUFBTSxJQUFqQjs7QUFFQSxJQUFJLFNBQVMsSUFBYjtBQUNBLElBQ0E7QUFDSSxhQUFTLFFBQVEsS0FBSyxNQUFiLENBQVQsQ0FESixDQUNtQztBQUNsQyxDQUhELENBSUEsT0FBTSxDQUFOLEVBQ0E7QUFDSSxVQUFNLENBQU47QUFDSDs7QUFFRCxvRkFBeUIsT0FBTyxrQkFBaEMsRUFBb0QsT0FBTyw0QkFBM0QsRUFBeUYsT0FBTywwQkFBaEcsRUFBNEgsT0FBTyxXQUFuSSxFQUFnSixVQUFDLGNBQUQsRUFBaUIsY0FBakIsRUFDaEo7QUFDSSxRQUFHLGNBQUgsRUFDQTtBQUNJLGNBQU0sY0FBTjtBQUNIOztBQUVELFFBQUksU0FBUyxjQUFiOztBQUVKO0FBQ0ksUUFBRyxLQUFLLFlBQVIsRUFDQTtBQUNJLGVBQU8sT0FBTyxRQUFkO0FBQ0g7O0FBRUQsUUFBRyxLQUFLLGFBQVIsRUFDQTtBQUNJLGVBQU8sT0FBTyxZQUFkO0FBQ0g7O0FBRUQsUUFBRyxLQUFLLFFBQVIsRUFDQTtBQUNJLGVBQU8sT0FBTyxJQUFkO0FBQ0g7O0FBRUQsUUFBRyxLQUFLLFVBQVIsRUFDQTtBQUNJLGFBQUksSUFBSSxFQUFSLElBQWMsTUFBZCxFQUNBO0FBQ0ksbUJBQU8sT0FBTyxFQUFQLEVBQVcsT0FBbEI7QUFDSDtBQUNKOztBQUVELFlBQVEsR0FBUixDQUFZLEtBQUssU0FBTCxDQUFlLE1BQWYsRUFBdUIsSUFBdkIsRUFBNkIsQ0FBN0IsQ0FBWjtBQUNILENBbENEIiwiZmlsZSI6ImNoZWNrLWN0LWxvZ3MuanMiLCJzb3VyY2VzQ29udGVudCI6WyJcblwidXNlIHN0cmljdFwiO1xuXG4vLyBDb3JlIGRlcHNcblxuLy8gM3JkIHBhcnR5IGRlcHNcbmltcG9ydCB7Z2V0fSBmcm9tIFwiaHR0cDJcIjtcbmltcG9ydCB7dG9Kc29ufSBmcm9tIFwieG1sMmpzb25cIjtcblxuLy8gTG9jYWwgZGVwc1xuaW1wb3J0IGNoZWNrQ1RMb2dzIGZyb20gXCIuLi9saWIvdGxzLWNlcnRpZmljYXRlLXRyYW5zcGFyZW5jeS1sb2ctY2hlY2tlci1saWIuanNcIjtcblxuY29uc3QgeWFyZ3MgPSByZXF1aXJlKFwieWFyZ3NcIilcbiAgICAudXNhZ2UoXCJVc2FnZTogJDAgW29wdGlvbnNdXCIpXG4gICAgLmhlbHAoXCJoZWxwXCIpXG4gICAgLm9wdGlvbihcImNvbmZpZ1wiLFxuICAgIHtcbiAgICAgICAgLy8gTk9URTogTm90IHN1cmUgd2h5IGJ1dCB5b3UgaGF2ZSB0byB1c2UgLS1jb25maWcgPHBhdGg+XG4gICAgICAgIGRlbWFuZDogZmFsc2UsXG4gICAgICAgIGFsaWFzOiBbXCJjXCIsIFwiY29uZlwiXSxcbiAgICAgICAgdHlwZTogXCJzdHJpbmdcIixcbiAgICAgICAgZGVmYXVsdDogXCIuLi8uLi9jb25maWcvdGxzLWNlcnRpZmljYXRlLXRyYW5zcGFyZW5jeS1sb2ctY2hlY2tlci1jb25maWcuanNcIixcbiAgICAgICAgZGVzY3JpYmU6IFwidGhlIChhYnNvbHV0ZSkgcGF0aCB0byBhIHNwZWNpZmljIGNvbmZpZ3VyYXRpb24gZmlsZSB3aGljaCBvdmVycmlkZXMgZGVmYXVsdHNcIlxuICAgIH0pXG4gICAgLm9wdGlvbihcIm5vX2FsbF9jZXJ0c1wiLFxuICAgIHtcbiAgICAgICAgZGVtYW5kOiBmYWxzZSxcbiAgICAgICAgLy8gYWxpYXM6IFtcIm5vLW5ld1wiXSwgLy8gRE9FU05UIFdPUktcbiAgICAgICAgdHlwZTogXCJib29sZWFuXCIsXG4gICAgICAgIGRlZmF1bHQ6IGZhbHNlLFxuICAgICAgICBkZXNjcmliZTogXCJpZiB0cnVlLCB0aGUgJ2FsbENlcnRzJyBjZXJ0aWZpY2F0ZXMgKGxpdGVyYWxseSBhbGwgY2VydHMgZm91bmQgaW4gdGhlIENUIGxvZ3Mgd2hvc2UgdmFsaWQgZnJvbSBkYXRhIGlzIG5ld2VyIHRoYW4gbm93IC0gY29uZmlnIG9wdGlvbiAnaWdub3JlQ2VydHNWYWxpZEZyb21CZWZvcmVUUycgKSBlbGVtZW50IG9mIHRoZSBvdXRwdXQgSlNPTiB3aWxsIGJlIG9taXR0ZWQgXCJcbiAgICB9KVxuICAgIC5vcHRpb24oXCJub191bmV4cGVjdGVkXCIsXG4gICAge1xuICAgICAgICBkZW1hbmQ6IGZhbHNlLFxuICAgICAgICAvLyBhbGlhczogW1wibm8tdW5leHBlY3RlZFwiXSwgLy8gRE9FU05UIFdPUktcbiAgICAgICAgdHlwZTogXCJib29sZWFuXCIsXG4gICAgICAgIGRlZmF1bHQ6IGZhbHNlLFxuICAgICAgICBkZXNjcmliZTogXCJpZiB0cnVlLCB0aGUgJ3VuZXhwZWN0ZWRDQScgY2VydGlmaWNhdGVzICh0aG9zZSBjZXJ0cyB3aG9zZSBDQSBkb2VzICpub3QqIG1hdGNoIGF0IGxlYXN0IG9uZSBvZiB0aGUgY29uZmlnIG9wdGlvbiAnZXhwZWN0ZWRDQXMnICkgZWxlbWVudCBvZiB0aGUgb3V0cHV0IEpTT04gd2lsbCBiZSBvbWl0dGVkIFwiXG4gICAgfSlcbiAgICAub3B0aW9uKFwibm9fYnlfY2FcIixcbiAgICB7XG4gICAgICAgIGRlbWFuZDogZmFsc2UsXG4gICAgICAgIC8vIGFsaWFzOiBbXCJuby1jYXNcIl0sIC8vIERPRVNOVCBXT1JLXG4gICAgICAgIHR5cGU6IFwiYm9vbGVhblwiLFxuICAgICAgICBkZWZhdWx0OiBmYWxzZSxcbiAgICAgICAgZGVzY3JpYmU6IFwiaWYgdHJ1ZSwgdGhlICdieUNBJyBlbGVtZW50IG9mIHRoZSBvdXRwdXQgSlNPTiB3aWxsIGJlIG9taXR0ZWQgXCJcbiAgICB9KVxuICAgIC5vcHRpb24oXCJub19lbnRyaWVzXCIsXG4gICAge1xuICAgICAgICBkZW1hbmQ6IGZhbHNlLFxuICAgICAgICB0eXBlOiBcImJvb2xlYW5cIixcbiAgICAgICAgZGVmYXVsdDogZmFsc2UsXG4gICAgICAgIGRlc2NyaWJlOiBcImlmIHRydWUsIHRoZSAnZW50cmllcycgcHJvcGVydHkgb2YgZWFjaCBhbGxDZXJ0cywgdW5leHBlY3RlZENBIGFuZCBieUNBIGVsZW1lbnRzIG9mIHRoZSBvdXRwdXQgSlNPTiB3aWxsIGJlIG9taXR0ZWQgXCJcbiAgICB9KVxuICAgIC5vcHRpb24oXCJoZWxwXCIsXG4gICAge1xuICAgICAgICBkZW1hbmQ6IGZhbHNlLFxuICAgICAgICBhbGlhczogXCJoXCJcbiAgICB9XG4pO1xuXG5sZXQgYXJncyA9IHlhcmdzLmFyZ3Y7XG5cbmxldCBjb25maWcgPSBudWxsO1xudHJ5XG57XG4gICAgY29uZmlnID0gcmVxdWlyZShhcmdzLmNvbmZpZyk7IC8vIE5PVEU6IFBhdGggaXMgcmVsYXRpdmUgdG8gYnVpbGQgZGlyIChkaXN0L2NsaS8pXFxcbn1cbmNhdGNoKGUpXG57XG4gICAgdGhyb3cgZTtcbn1cblxuY2hlY2tDVExvZ3MoZ2V0LCB0b0pzb24sIGNvbmZpZy5kb21haW5OYW1lUGF0dGVybnMsIGNvbmZpZy5pZ25vcmVDZXJ0c1ZhbGlkRnJvbUJlZm9yZVRTLCBjb25maWcuaWdub3JlQ2VydHNWYWxpZFRvQmVmb3JlVFMsIGNvbmZpZy5leHBlY3RlZENBcywgKGNoZWNrQ1RMb2dzRXJyLCBjaGVja0NUTG9nc1JlcykgPT5cbntcbiAgICBpZihjaGVja0NUTG9nc0VycilcbiAgICB7XG4gICAgICAgIHRocm93IGNoZWNrQ1RMb2dzRXJyO1xuICAgIH1cblxuICAgIGxldCBvdXRwdXQgPSBjaGVja0NUTG9nc1JlcztcblxuLy8gUmVtb3ZlIHVuZGVzaXJlZCBvdXRwdXQgLSB5ZWFoLCB0aGlzIGlzIGEgY3JhcHB5IG1ldGhvZCBidXQgd2lsbCBkbyBmb3Igbm93XG4gICAgaWYoYXJncy5ub19hbGxfY2VydHMpXG4gICAge1xuICAgICAgICBkZWxldGUgb3V0cHV0LmFsbENlcnRzO1xuICAgIH1cblxuICAgIGlmKGFyZ3Mubm9fdW5leHBlY3RlZClcbiAgICB7XG4gICAgICAgIGRlbGV0ZSBvdXRwdXQudW5leHBlY3RlZENBO1xuICAgIH1cblxuICAgIGlmKGFyZ3Mubm9fYnlfY2EpXG4gICAge1xuICAgICAgICBkZWxldGUgb3V0cHV0LmJ5Q0E7XG4gICAgfVxuXG4gICAgaWYoYXJncy5ub19lbnRyaWVzKVxuICAgIHtcbiAgICAgICAgZm9yKGxldCBlbCBpbiBvdXRwdXQpXG4gICAgICAgIHtcbiAgICAgICAgICAgIGRlbGV0ZSBvdXRwdXRbZWxdLmVudHJpZXM7XG4gICAgICAgIH1cbiAgICB9XG5cbiAgICBjb25zb2xlLmxvZyhKU09OLnN0cmluZ2lmeShvdXRwdXQsIG51bGwsIDIpKTtcbn0pO1xuIl19