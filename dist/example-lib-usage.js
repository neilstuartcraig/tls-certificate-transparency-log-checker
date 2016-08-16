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
(0, _tlsCertificateTransparencyLogCheckerLib2.default)(_http.get, _xml2json.toJson, config.domainNamePatterns, config.ignoreCertsValidFromBeforeTS, config.ignoreCertsValidToBeforeTS, config.expectedCAs, function (checkCTLogsErr, checkCTLogsRes) {
    if (checkCTLogsErr) {
        throw checkCTLogsErr;
    }

    console.log(JSON.stringify(checkCTLogsRes, null, 2));
}); // NOTE: Path is relative to build dir (dist/)
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIi4uL3NyYy9leGFtcGxlLWxpYi11c2FnZS5qcyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiQUFBQTs7QUFFQTs7QUFFQTs7QUFDQTs7QUFDQTs7QUFHQTs7SUFBWSxNOztBQUNaOzs7Ozs7OztBQUFpRjs7QUFGakY7QUFJQSxvRkFBeUIsT0FBTyxrQkFBaEMsRUFBb0QsT0FBTyw0QkFBM0QsRUFBeUYsT0FBTywwQkFBaEcsRUFBNEgsT0FBTyxXQUFuSSxFQUFnSixVQUFDLGNBQUQsRUFBaUIsY0FBakIsRUFDaEo7QUFDSSxRQUFHLGNBQUgsRUFDQTtBQUNJLGNBQU0sY0FBTjtBQUNIOztBQUVELFlBQVEsR0FBUixDQUFZLEtBQUssU0FBTCxDQUFlLGNBQWYsRUFBK0IsSUFBL0IsRUFBcUMsQ0FBckMsQ0FBWjtBQUNILENBUkQsRSxDQUh3RiIsImZpbGUiOiJleGFtcGxlLWxpYi11c2FnZS5qcyIsInNvdXJjZXNDb250ZW50IjpbIlwidXNlIHN0cmljdFwiO1xuXG4vLyBDb3JlIGRlcHNcblxuLy8gM3JkIHBhcnR5IGRlcHNcbmltcG9ydCB7Z2V0fSBmcm9tIFwiaHR0cDJcIjtcbmltcG9ydCB7dG9Kc29ufSBmcm9tIFwieG1sMmpzb25cIjtcblxuLy8gTG9jYWwgZGVwc1xuaW1wb3J0ICogYXMgY29uZmlnIGZyb20gXCIuLi9jb25maWcvdGxzLWNlcnRpZmljYXRlLXRyYW5zcGFyZW5jeS1sb2ctY2hlY2tlci1jb25maWcuanNcIjsgLy8gTk9URTogUGF0aCBpcyByZWxhdGl2ZSB0byBidWlsZCBkaXIgKGRpc3QvKVxuaW1wb3J0IGNoZWNrQ1RMb2dzIGZyb20gXCIuL2xpYi90bHMtY2VydGlmaWNhdGUtdHJhbnNwYXJlbmN5LWxvZy1jaGVja2VyLWxpYi5qc1wiOyAvLyBOT1RFOiBQYXRoIGlzIHJlbGF0aXZlIHRvIGJ1aWxkIGRpciAoZGlzdC8pIC0gbG9jYWwgYmVjYXVzZSBsaWIgaXMgYmFiZWwnZFxuXG5jaGVja0NUTG9ncyhnZXQsIHRvSnNvbiwgY29uZmlnLmRvbWFpbk5hbWVQYXR0ZXJucywgY29uZmlnLmlnbm9yZUNlcnRzVmFsaWRGcm9tQmVmb3JlVFMsIGNvbmZpZy5pZ25vcmVDZXJ0c1ZhbGlkVG9CZWZvcmVUUywgY29uZmlnLmV4cGVjdGVkQ0FzLCAoY2hlY2tDVExvZ3NFcnIsIGNoZWNrQ1RMb2dzUmVzKSA9Plxue1xuICAgIGlmKGNoZWNrQ1RMb2dzRXJyKVxuICAgIHtcbiAgICAgICAgdGhyb3cgY2hlY2tDVExvZ3NFcnI7XG4gICAgfVxuXG4gICAgY29uc29sZS5sb2coSlNPTi5zdHJpbmdpZnkoY2hlY2tDVExvZ3NSZXMsIG51bGwsIDIpKTtcbn0pO1xuIl19