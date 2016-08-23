"use strict";

// Core deps sss

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
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIi4uL3NyYy9leGFtcGxlLWxpYi11c2FnZS5qcyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiQUFBQTs7QUFFQTs7QUFFQTs7QUFFQTs7QUFDQTs7SUFBWSxNOztBQUNaOzs7O0FBQW1GOztBQUVuRiwwREFBWSxPQUFPLGtCQUFuQixFQUF1QyxPQUFPLDRCQUE5QyxFQUE0RSxPQUFPLDBCQUFuRixFQUErRyxPQUFPLFdBQXRILEVBQW1JLFVBQUMsY0FBRCxFQUFpQixjQUFqQixFQUNuSTtBQUNJLFFBQUcsY0FBSCxFQUNBO0FBQ0ksY0FBTSxjQUFOO0FBQ0g7O0FBRUQsWUFBUSxHQUFSLENBQVksS0FBSyxTQUFMLENBQWUsY0FBZixFQUErQixJQUEvQixFQUFxQyxDQUFyQyxDQUFaO0FBQ0gsQ0FSRCxFLENBSHdGIiwiZmlsZSI6ImV4YW1wbGUtbGliLXVzYWdlLmpzIiwic291cmNlc0NvbnRlbnQiOlsiXCJ1c2Ugc3RyaWN0XCI7XG5cbi8vIENvcmUgZGVwcyBzc3NcblxuLy8gM3JkIHBhcnR5IGRlcHNcblxuLy8gTG9jYWwgZGVwc1xuaW1wb3J0ICogYXMgY29uZmlnIGZyb20gXCIuLi9jb25maWcvdGxzLWNlcnRpZmljYXRlLXRyYW5zcGFyZW5jeS1sb2ctY2hlY2tlci1jb25maWcuanNcIjsgLy8gTk9URTogUGF0aCBpcyByZWxhdGl2ZSB0byBidWlsZCBkaXIgKGRpc3QvKVxuaW1wb3J0IHtjaGVja0NUTG9nc30gZnJvbSBcIi4vbGliL3Rscy1jZXJ0aWZpY2F0ZS10cmFuc3BhcmVuY3ktbG9nLWNoZWNrZXItbGliLmpzXCI7IC8vIE5PVEU6IFBhdGggaXMgcmVsYXRpdmUgdG8gYnVpbGQgZGlyIChkaXN0LykgLSBsb2NhbCBiZWNhdXNlIGxpYiBpcyBiYWJlbCdkXG5cbmNoZWNrQ1RMb2dzKGNvbmZpZy5kb21haW5OYW1lUGF0dGVybnMsIGNvbmZpZy5pZ25vcmVDZXJ0c1ZhbGlkRnJvbUJlZm9yZVRTLCBjb25maWcuaWdub3JlQ2VydHNWYWxpZFRvQmVmb3JlVFMsIGNvbmZpZy5leHBlY3RlZENBcywgKGNoZWNrQ1RMb2dzRXJyLCBjaGVja0NUTG9nc1JlcykgPT5cbntcbiAgICBpZihjaGVja0NUTG9nc0VycilcbiAgICB7XG4gICAgICAgIHRocm93IGNoZWNrQ1RMb2dzRXJyO1xuICAgIH1cblxuICAgIGNvbnNvbGUubG9nKEpTT04uc3RyaW5naWZ5KGNoZWNrQ1RMb2dzUmVzLCBudWxsLCAyKSk7XG59KTtcbiJdfQ==