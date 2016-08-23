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
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIi4uL3NyYy9leGFtcGxlLWxpYi11c2FnZS5qcyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiQUFBQTs7QUFFQTs7QUFFQTs7QUFFQTs7QUFDQTs7SUFBWSxNOztBQUNaOzs7O0FBQW1GOztBQUVuRiwwREFBWSxPQUFPLGtCQUFuQixFQUF1QyxPQUFPLDRCQUE5QyxFQUE0RSxPQUFPLDBCQUFuRixFQUErRyxPQUFPLFdBQXRILEVBQW1JLFVBQUMsY0FBRCxFQUFpQixjQUFqQixFQUNuSTtBQUNJLFFBQUcsY0FBSCxFQUNBO0FBQ0ksY0FBTSxjQUFOO0FBQ0g7O0FBRUQsWUFBUSxHQUFSLENBQVksS0FBSyxTQUFMLENBQWUsY0FBZixFQUErQixJQUEvQixFQUFxQyxDQUFyQyxDQUFaO0FBQ0gsQ0FSRCxFLENBSHdGIiwiZmlsZSI6ImV4YW1wbGUtbGliLXVzYWdlLmpzIiwic291cmNlc0NvbnRlbnQiOlsiXCJ1c2Ugc3RyaWN0XCI7XG5cbi8vIENvcmUgZGVwc1xuXG4vLyAzcmQgcGFydHkgZGVwc1xuXG4vLyBMb2NhbCBkZXBzXG5pbXBvcnQgKiBhcyBjb25maWcgZnJvbSBcIi4uL2NvbmZpZy90bHMtY2VydGlmaWNhdGUtdHJhbnNwYXJlbmN5LWxvZy1jaGVja2VyLWNvbmZpZy5qc1wiOyAvLyBOT1RFOiBQYXRoIGlzIHJlbGF0aXZlIHRvIGJ1aWxkIGRpciAoZGlzdC8pXG5pbXBvcnQge2NoZWNrQ1RMb2dzfSBmcm9tIFwiLi9saWIvdGxzLWNlcnRpZmljYXRlLXRyYW5zcGFyZW5jeS1sb2ctY2hlY2tlci1saWIuanNcIjsgLy8gTk9URTogUGF0aCBpcyByZWxhdGl2ZSB0byBidWlsZCBkaXIgKGRpc3QvKSAtIGxvY2FsIGJlY2F1c2UgbGliIGlzIGJhYmVsJ2RcblxuY2hlY2tDVExvZ3MoY29uZmlnLmRvbWFpbk5hbWVQYXR0ZXJucywgY29uZmlnLmlnbm9yZUNlcnRzVmFsaWRGcm9tQmVmb3JlVFMsIGNvbmZpZy5pZ25vcmVDZXJ0c1ZhbGlkVG9CZWZvcmVUUywgY29uZmlnLmV4cGVjdGVkQ0FzLCAoY2hlY2tDVExvZ3NFcnIsIGNoZWNrQ1RMb2dzUmVzKSA9Plxue1xuICAgIGlmKGNoZWNrQ1RMb2dzRXJyKVxuICAgIHtcbiAgICAgICAgdGhyb3cgY2hlY2tDVExvZ3NFcnI7XG4gICAgfVxuXG4gICAgY29uc29sZS5sb2coSlNPTi5zdHJpbmdpZnkoY2hlY2tDVExvZ3NSZXMsIG51bGwsIDIpKTtcbn0pO1xuIl19