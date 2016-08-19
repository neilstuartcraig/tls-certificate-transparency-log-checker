"use strict";

// Core deps

var _typeof = typeof Symbol === "function" && typeof Symbol.iterator === "symbol" ? function (obj) { return typeof obj; } : function (obj) { return obj && typeof Symbol === "function" && obj.constructor === Symbol ? "symbol" : typeof obj; };

// 3rd party deps


var _os = require("os");

var _os2 = _interopRequireDefault(_os);

var _x7 = require("x509.js");

var _xml2json = require("xml2json");

var _https = require("https");

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

// Defaults (used in function definitions)
var nowTS = parseInt(new Date().getTime() / 1000, 10); // NOTE: JS timestamps are in msec
var defaults = {
    ignoreCertsValidFromBeforeTS: nowTS - 86400, // 1 day ago
    ignoreCertsValidToBeforeTS: nowTS,
    expectedCAs: [] // Default is expect none
};

// NOTE: This is sync for the moment which is probably a bad idea - making async will need work on getCertsData() (below)
function getCertDetails(rawCertSummary) {
    if (!(rawCertSummary instanceof Object)) {
        throw new TypeError("Value of argument \"rawCertSummary\" violates contract.\n\nExpected:\nObject\n\nGot:\n" + _inspect(rawCertSummary));
    }

    var ret = null;

    if ("$t" in rawCertSummary) {
        var rawCertText = rawCertSummary["$t"].match(/.*(-----BEGIN CERTIFICATE-----.*-----END CERTIFICATE-----).*/);

        if (rawCertText instanceof Array) {
            var certText = rawCertText[1].replace(/<br>/g, _os2.default.EOL);

            var parsedCertJSON = null;

            try {
                parsedCertJSON = (0, _x7.parseCert)(certText);
            } catch (e) {
                // Don't think there's anything sensible we can do here (?)
            }

            if (parsedCertJSON instanceof Object) {
                var certJSON = {
                    serial: parsedCertJSON.serial || null,
                    subject: parsedCertJSON.subject || {}, // eslint-disable-line object-curly-newline
                    issuer: parsedCertJSON.issuer || {}, // eslint-disable-line object-curly-newline
                    validFrom: parsedCertJSON.notBefore || null,
                    validFromTS: 0, // Will be updated below
                    validTo: parsedCertJSON.notAfter || null,
                    validToTS: 0, // Will be updated below
                    daysRemaining: 0, // Will be updated below
                    SAN: parsedCertJSON.altNames || []
                };

                try {
                    certJSON.validFromTS = parseInt(new Date(certJSON.validFrom).getTime() / 1000, 10); // need to remove last 3 chars as JS use MSec TS's
                } catch (e) {
                    certJSON.validFromTS = 0; // Is there anything more sensible which could be done?
                }

                try {
                    certJSON.validToTS = parseInt(new Date(certJSON.validTo).getTime() / 1000, 10); // need to remove last 3 chars as JS use MSec TS's
                } catch (e) {
                    certJSON.validFromTS = 0; // Is there anything more sensible which could be done?
                }

                certJSON.daysRemaining = Math.floor((certJSON.validToTS - nowTS) / 86400);

                ret = certJSON;
            } else {
                ret = new TypeError("rawCertSummary.$t does not contain a valid x509 certificate");
            }
        } else {
            ret = new TypeError("rawCertSummary.$t does not contain an x509 certificate");
        }
    } else {
        ret = new TypeError("rawCertSummary must contain a property named '$t'");
    }

    return ret; // TypeError if error, object otherwise
}

function getCertsData(parsedJSON) {
    var ignoreCertsValidFromBeforeTS = arguments.length <= 1 || arguments[1] === undefined ? defaults.ignoreCertsValidFromBeforeTS : arguments[1];
    var ignoreCertsValidToBeforeTS = arguments.length <= 2 || arguments[2] === undefined ? defaults.ignoreCertsValidToBeforeTS : arguments[2];
    var expectedCAs = arguments.length <= 3 || arguments[3] === undefined ? defaults.expectedCAs : arguments[3];
    var callback = arguments[4];

    if (!(parsedJSON instanceof Object)) {
        throw new TypeError("Value of argument \"parsedJSON\" violates contract.\n\nExpected:\nObject\n\nGot:\n" + _inspect(parsedJSON));
    }

    if (!(typeof ignoreCertsValidFromBeforeTS === 'number')) {
        throw new TypeError("Value of argument \"ignoreCertsValidFromBeforeTS\" violates contract.\n\nExpected:\nnumber\n\nGot:\n" + _inspect(ignoreCertsValidFromBeforeTS));
    }

    if (!(typeof ignoreCertsValidToBeforeTS === 'number')) {
        throw new TypeError("Value of argument \"ignoreCertsValidToBeforeTS\" violates contract.\n\nExpected:\nnumber\n\nGot:\n" + _inspect(ignoreCertsValidToBeforeTS));
    }

    if (!Array.isArray(expectedCAs)) {
        throw new TypeError("Value of argument \"expectedCAs\" violates contract.\n\nExpected:\nArray\n\nGot:\n" + _inspect(expectedCAs));
    }

    if (!(typeof callback === 'function')) {
        throw new TypeError("Value of argument \"callback\" violates contract.\n\nExpected:\nFunction\n\nGot:\n" + _inspect(callback));
    }

    /* NOTE: JSON structure of parsedJSON is:
    {
        feed:
        {
            xmlns: 'http://www.w3.org/2005/Atom',
            'xml:lang': 'en',
            author: { name: 'crt.sh', uri: 'https://crt.sh/' },
            icon: 'https://crt.sh/favicon.ico',
            id: 'https://crt.sh/?identity=%25.bbc.com&exclude=expired',
            link: [ [Object], [Object] ],
            title: 'identity=%.bbc.com; exclude=expired',
            updated: '2016-08-04T11:06:47Z',
            entry:
            [
                [Object],
                [Object],
                ...
            ]
        }
    }
    */

    var err = new Error("Either your JSON is malformed or there are no valid certificates in the data (versus filter criteria)");
    var certsData = {
        allCerts: {
            count: 0,
            entries: []
        },
        unexpectedCA: {
            count: 0,
            entries: []
        },
        byCA: {
            count: 0,
            entries: {}
        }
    };

    if (parsedJSON.feed) {
        if (parsedJSON.feed.entry instanceof Array) {
            parsedJSON.feed.entry.forEach(function (cert) {
                // Use x509.js to parse the raw cert string into consistent JSON
                var certDetailsJSON = getCertDetails(cert.summary);

                if (certDetailsJSON instanceof Object) {
                    // console.log("Cert valid from %d -- ignore from: %d -- diff %d", certDetailsJSON.validToTS, ignoreCertsValidToBeforeTS, (certDetailsJSON.validToTS - ignoreCertsValidToBeforeTS) );
                    // Ignore certs whose validToTS is < ignoreCertsValidToBeforeTS
                    if (certDetailsJSON.validToTS >= ignoreCertsValidToBeforeTS) {
                        // console.log("cert OK");
                        // NOTE: This may be too coarse
                        err = null;

                        // Only include certs which have been issued since the last run, unless the user has opted to return all by setting ignoreCertsValidFromBeforeTS to (exactly) 0
                        if (certDetailsJSON.validFromTS >= ignoreCertsValidFromBeforeTS || ignoreCertsValidFromBeforeTS === 0) {
                            // All certs
                            certsData.allCerts.entries.push(certDetailsJSON);

                            // Certs with an "unexpected" CA
                            var expectedCAMatch = false;
                            if (Object.keys(certDetailsJSON.issuer).length > 0) {
                                expectedCAs.forEach(function (ECA) {
                                    if (certDetailsJSON.issuer.commonName.match(ECA)) {
                                        expectedCAMatch = true;
                                    }
                                });
                            }

                            if (expectedCAMatch === false) {
                                certsData.unexpectedCA.entries.push(certDetailsJSON);
                            }

                            // All certs, grouped by CA
                            if (certsData.byCA.entries[certDetailsJSON.issuer.commonName] === undefined) {
                                certsData.byCA.entries[certDetailsJSON.issuer.commonName] = [];
                            }

                            certsData.byCA.entries[certDetailsJSON.issuer.commonName].push(certDetailsJSON);
                        }
                    }
                } else {
                    err = new TypeError("JSON is malformed, rejecting");
                }
            });
        }
    }

    // Counts (totals)
    certsData.allCerts.count = certsData.allCerts.entries.length;
    certsData.unexpectedCA.count = certsData.unexpectedCA.entries.length;
    certsData.byCA.count = Object.keys(certsData.byCA.entries).length;

    if (err !== null) {
        certsData = null;
    }

    return callback(err, certsData);
}

function convertXMLToJSON(XML, callback) {
    if (!(typeof XML === 'string')) {
        throw new TypeError("Value of argument \"XML\" violates contract.\n\nExpected:\nstring\n\nGot:\n" + _inspect(XML));
    }

    if (!(typeof callback === 'function')) {
        throw new TypeError("Value of argument \"callback\" violates contract.\n\nExpected:\nFunction\n\nGot:\n" + _inspect(callback));
    }

    var err = null;
    var parsedJSON = null;

    // We try/catch so that the toJson lib fn can throw if it need to without us throwing
    try {
        // NOTE: toJson is a 3rd party dep (xml2json)
        var rawJSON = (0, _xml2json.toJson)(XML);

        // Somewhat oddly, toJson returns a stringified JSON object
        parsedJSON = JSON.parse(rawJSON);

        if (Object.keys(parsedJSON).length === 0) {
            err = new TypeError("Argument 'XML' resulted in no JSON output, it's probably not XML");
            parsedJSON = null;
        }
    } catch (e) {
        err = e;
    }

    return callback(err, parsedJSON);
}

function getRSSXML(domainNamePattern, callback) // eslint-disable-line consistent-return
{
    if (!(typeof domainNamePattern === 'string')) {
        throw new TypeError("Value of argument \"domainNamePattern\" violates contract.\n\nExpected:\nstring\n\nGot:\n" + _inspect(domainNamePattern));
    }

    if (!(typeof callback === 'function')) {
        throw new TypeError("Value of argument \"callback\" violates contract.\n\nExpected:\nFunction\n\nGot:\n" + _inspect(callback));
    }

    if (domainNamePattern.length > 0) {
        (function () {
            var xml = "";

            // NOTE: We're doing a plain (not if-modified-since) GET on the URL and are NOT using the built-in "ignore expired certs" as we do that programmativally via ignoreCertsValidToBeforeTS
            (0, _https.get)("https://crt.sh/atom?identity=" + domainNamePattern, function (response) {
                response.on("data", function (d) {
                    xml += d.toString("utf8");
                });

                response.on("end", function (e) {
                    var err = e;
                    if (e === undefined) {
                        err = null;
                    } else // if there's been an error, we want to nullify xml
                        {
                            xml = null;
                        }

                    return callback(err, xml);
                });
            });
        })();
    } else {
        var err = new TypeError("Argument 'domainNamePattern' must not be empty");
        return callback(err, null);
    }
}

// Maybe this should be an option obj? for at least e.g. config-type options
function checkCTLogs(domainNamePatterns) {
    var ignoreCertsValidFromBeforeTS = arguments.length <= 1 || arguments[1] === undefined ? defaults.ignoreCertsValidFromBeforeTS : arguments[1];
    var ignoreCertsValidToBeforeTS = arguments.length <= 2 || arguments[2] === undefined ? defaults.ignoreCertsValidToBeforeTS : arguments[2];
    var expectedCAs = arguments.length <= 3 || arguments[3] === undefined ? defaults.expectedCAs : arguments[3];
    var callback = arguments[4];

    if (!Array.isArray(domainNamePatterns)) {
        throw new TypeError("Value of argument \"domainNamePatterns\" violates contract.\n\nExpected:\nArray\n\nGot:\n" + _inspect(domainNamePatterns));
    }

    if (!(typeof ignoreCertsValidFromBeforeTS === 'number')) {
        throw new TypeError("Value of argument \"ignoreCertsValidFromBeforeTS\" violates contract.\n\nExpected:\nnumber\n\nGot:\n" + _inspect(ignoreCertsValidFromBeforeTS));
    }

    if (!(typeof ignoreCertsValidToBeforeTS === 'number')) {
        throw new TypeError("Value of argument \"ignoreCertsValidToBeforeTS\" violates contract.\n\nExpected:\nnumber\n\nGot:\n" + _inspect(ignoreCertsValidToBeforeTS));
    }

    if (!Array.isArray(expectedCAs)) {
        throw new TypeError("Value of argument \"expectedCAs\" violates contract.\n\nExpected:\nArray\n\nGot:\n" + _inspect(expectedCAs));
    }

    if (!(typeof callback === 'function')) {
        throw new TypeError("Value of argument \"callback\" violates contract.\n\nExpected:\nFunction\n\nGot:\n" + _inspect(callback));
    }

    var totalNumDomainNamePatterns = domainNamePatterns.length;
    var totalNumDomainNamePatternsCompleted = 0;

    domainNamePatterns.forEach(function (domainNamePattern) {
        // HTTP2-capable GET of the specific XML feed for the relevant domain name pattern (e.g. %.bbc.co.uk - where % is a wildcard)
        getRSSXML(domainNamePattern, function (RSSError, RSSXML) // eslint-disable-line consistent-return
        {
            if (RSSError) {
                return callback(RSSError, null);
            }

            // Raw conversion from XML to JSON
            convertXMLToJSON(RSSXML, function (convertErr, RSSJSON) // eslint-disable-line consistent-return
            {
                if (convertErr) {
                    return callback(convertErr, null);
                }

                // Downloading of RSS feed from crt.sh with filtering and parsing
                getCertsData(RSSJSON, ignoreCertsValidFromBeforeTS, ignoreCertsValidToBeforeTS, expectedCAs, function (getCertsDataErr, certsData) // eslint-disable-line consistent-return
                {
                    if (getCertsDataErr) {
                        return callback(getCertsDataErr, null);
                    }

                    // Track how many of the configured domainNamePatterns we've completed and...
                    totalNumDomainNamePatternsCompleted++;

                    // ...exit when all domainNamePatterns are complete (because this is async)
                    if (totalNumDomainNamePatternsCompleted >= totalNumDomainNamePatterns) {
                        return callback(null, certsData);
                    }
                });
            });
        });
    });
}

// We *should* only need to export the user-facing function
module.exports = {
    getCertDetails: getCertDetails,
    getCertsData: getCertsData,
    convertXMLToJSON: convertXMLToJSON,
    getRSSXML: getRSSXML,
    checkCTLogs: checkCTLogs
};

function _inspect(input, depth) {
    var maxDepth = 4;
    var maxKeys = 15;

    if (depth === undefined) {
        depth = 0;
    }

    depth += 1;

    if (input === null) {
        return 'null';
    } else if (input === undefined) {
        return 'void';
    } else if (typeof input === 'string' || typeof input === 'number' || typeof input === 'boolean') {
        return typeof input === "undefined" ? "undefined" : _typeof(input);
    } else if (Array.isArray(input)) {
        if (input.length > 0) {
            var _ret2 = function () {
                if (depth > maxDepth) return {
                        v: '[...]'
                    };

                var first = _inspect(input[0], depth);

                if (input.every(function (item) {
                    return _inspect(item, depth) === first;
                })) {
                    return {
                        v: first.trim() + '[]'
                    };
                } else {
                    return {
                        v: '[' + input.slice(0, maxKeys).map(function (item) {
                            return _inspect(item, depth);
                        }).join(', ') + (input.length >= maxKeys ? ', ...' : '') + ']'
                    };
                }
            }();

            if ((typeof _ret2 === "undefined" ? "undefined" : _typeof(_ret2)) === "object") return _ret2.v;
        } else {
            return 'Array';
        }
    } else {
        var keys = Object.keys(input);

        if (!keys.length) {
            if (input.constructor && input.constructor.name && input.constructor.name !== 'Object') {
                return input.constructor.name;
            } else {
                return 'Object';
            }
        }

        if (depth > maxDepth) return '{...}';
        var indent = '  '.repeat(depth - 1);
        var entries = keys.slice(0, maxKeys).map(function (key) {
            return (/^([A-Z_$][A-Z0-9_$]*)$/i.test(key) ? key : JSON.stringify(key)) + ': ' + _inspect(input[key], depth) + ';';
        }).join('\n  ' + indent);

        if (keys.length >= maxKeys) {
            entries += '\n  ' + indent + '...';
        }

        if (input.constructor && input.constructor.name && input.constructor.name !== 'Object') {
            return input.constructor.name + ' {\n  ' + indent + entries + '\n' + indent + '}';
        } else {
            return '{\n  ' + indent + entries + '\n' + indent + '}';
        }
    }
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIi4uLy4uL3NyYy9saWIvdGxzLWNlcnRpZmljYXRlLXRyYW5zcGFyZW5jeS1sb2ctY2hlY2tlci1saWIuanMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6IkFBQUE7O0FBRUE7Ozs7QUFHQTs7O0FBRkE7Ozs7QUFHQTs7QUFDQTs7QUFDQTs7OztBQUVBO0FBQ0EsSUFBTSxRQUFRLFNBQVMsSUFBSSxJQUFKLEdBQVcsT0FBWCxLQUF1QixJQUFoQyxFQUFzQyxFQUF0QyxDQUFkLEMsQ0FBeUQ7QUFDekQsSUFBTSxXQUNOO0FBQ0ksa0NBQThCLFFBQVEsS0FEMUMsRUFDaUQ7QUFDN0MsZ0NBQTRCLEtBRmhDO0FBR0ksaUJBQWEsRUFIakIsQ0FHb0I7QUFIcEIsQ0FEQTs7QUFRQTtBQUNBLFNBQVMsY0FBVCxDQUF3QixjQUF4QixFQUNBO0FBQUEsVUFEd0IsY0FDeEIsWUFEd0MsTUFDeEM7QUFBQSxnSUFEd0IsY0FDeEI7QUFBQTs7QUFDSSxRQUFJLE1BQU0sSUFBVjs7QUFFQSxRQUFHLFFBQVEsY0FBWCxFQUNBO0FBQ0ksWUFBSSxjQUFjLGVBQWUsSUFBZixFQUFxQixLQUFyQixDQUEyQiw4REFBM0IsQ0FBbEI7O0FBRUEsWUFBRyx1QkFBdUIsS0FBMUIsRUFDQTtBQUNJLGdCQUFJLFdBQVcsWUFBWSxDQUFaLEVBQWUsT0FBZixDQUF1QixPQUF2QixFQUFnQyxhQUFHLEdBQW5DLENBQWY7O0FBRUEsZ0JBQUksaUJBQWlCLElBQXJCOztBQUVBLGdCQUNBO0FBQ0ksaUNBQWlCLG1CQUFVLFFBQVYsQ0FBakI7QUFDSCxhQUhELENBSUEsT0FBTSxDQUFOLEVBQ0E7QUFDSTtBQUNIOztBQUVELGdCQUFHLDBCQUEwQixNQUE3QixFQUNBO0FBQ0ksb0JBQUksV0FDSjtBQUNJLDRCQUFRLGVBQWUsTUFBZixJQUF5QixJQURyQztBQUVJLDZCQUFTLGVBQWUsT0FBZixJQUEwQixFQUZ2QyxFQUUyQztBQUN2Qyw0QkFBUSxlQUFlLE1BQWYsSUFBeUIsRUFIckMsRUFHeUM7QUFD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RUFDM0I7QUFDSTtBQUNBLGtCQUFVLGlCQUFWLEVBQTZCLFVBQUMsUUFBRCxFQUFXLE1BQVgsRUFBc0I7QUFDbkQ7QUFDSSxnQkFBRyxRQUFILEVBQ0E7QUFDSSx1QkFBTyxTQUFTLFFBQVQsRUFBbUIsSUFBbkIsQ0FBUDtBQUNIOztBQUVEO0FBQ0EsNkJBQWlCLE1BQWpCLEVBQXlCLFVBQUMsVUFBRCxFQUFhLE9BQWIsRUFBeUI7QUFDbEQ7QUFDSSxvQkFBRyxVQUFILEVBQ0E7QUFDSSwyQkFBTyxTQUFTLFVBQVQsRUFBcUIsSUFBckIsQ0FBUDtBQUNIOztBQUVEO0FBQ0EsNkJBQWEsT0FBYixFQUFzQiw0QkFBdEIsRUFBb0QsMEJBQXBELEVBQWdGLFdBQWhGLEVBQTZGLFVBQUMsZUFBRCxFQUFrQixTQUFsQixFQUFnQztBQUM3SDtBQUNJLHdCQUFHLGVBQUgsRUFDQTtBQUNJLCtCQUFPLFNBQVMsZUFBVCxFQUEwQixJQUExQixDQUFQO0FBQ0g7O0FBRUQ7QUFDQTs7QUFFQTtBQUNBLHdCQUFHLHVDQUF1QywwQkFBMUMsRUFDQTtBQUNJLCtCQUFPLFNBQVMsSUFBVCxFQUFlLFNBQWYsQ0FBUDtBQUNIO0FBQ0osaUJBZkQ7QUFnQkgsYUF4QkQ7QUF5QkgsU0FqQ0Q7QUFrQ0gsS0FyQ0Q7QUFzQ0g7O0FBRUQ7QUFDQSxPQUFPLE9BQVAsR0FDQTtBQUNJLG9CQUFnQixjQURwQjtBQUVJLGtCQUFjLFlBRmxCO0FBR0ksc0JBQWtCLGdCQUh0QjtBQUlJLGVBQVcsU0FKZjtBQUtJLGlCQUFhO0FBTGpCLENBREEiLCJmaWxlIjoidGxzLWNlcnRpZmljYXRlLXRyYW5zcGFyZW5jeS1sb2ctY2hlY2tlci1saWIuanMiLCJzb3VyY2VzQ29udGVudCI6WyJcInVzZSBzdHJpY3RcIjtcblxuLy8gQ29yZSBkZXBzXG5pbXBvcnQgT1MgZnJvbSBcIm9zXCI7XG5cbi8vIDNyZCBwYXJ0eSBkZXBzXG5pbXBvcnQge3BhcnNlQ2VydH0gZnJvbSBcIng1MDkuanNcIjtcbmltcG9ydCB7dG9Kc29ufSBmcm9tIFwieG1sMmpzb25cIjtcbmltcG9ydCB7Z2V0fSBmcm9tIFwiaHR0cHNcIjtcblxuLy8gRGVmYXVsdHMgKHVzZWQgaW4gZnVuY3Rpb24gZGVmaW5pdGlvbnMpXG5jb25zdCBub3dUUyA9IHBhcnNlSW50KG5ldyBEYXRlKCkuZ2V0VGltZSgpIC8gMTAwMCwgMTApOyAvLyBOT1RFOiBKUyB0aW1lc3RhbXBzIGFyZSBpbiBtc2VjXG5jb25zdCBkZWZhdWx0cyA9XG57XG4gICAgaWdub3JlQ2VydHNWYWxpZEZyb21CZWZvcmVUUzogbm93VFMgLSA4NjQwMCwgLy8gMSBkYXkgYWdvXG4gICAgaWdub3JlQ2VydHNWYWxpZFRvQmVmb3JlVFM6IG5vd1RTLFxuICAgIGV4cGVjdGVkQ0FzOiBbXSAvLyBEZWZhdWx0IGlzIGV4cGVjdCBub25lXG59O1xuXG5cbi8vIE5PVEU6IFRoaXMgaXMgc3luYyBmb3IgdGhlIG1vbWVudCB3aGljaCBpcyBwcm9iYWJseSBhIGJhZCBpZGVhIC0gbWFraW5nIGFzeW5jIHdpbGwgbmVlZCB3b3JrIG9uIGdldENlcnRzRGF0YSgpIChiZWxvdylcbmZ1bmN0aW9uIGdldENlcnREZXRhaWxzKHJhd0NlcnRTdW1tYXJ5OiBPYmplY3QpXG57XG4gICAgbGV0IHJldCA9IG51bGw7XG5cbiAgICBpZihcIiR0XCIgaW4gcmF3Q2VydFN1bW1hcnkpXG4gICAge1xuICAgICAgICBsZXQgcmF3Q2VydFRleHQgPSByYXdDZXJ0U3VtbWFyeVtcIiR0XCJdLm1hdGNoKC8uKigtLS0tLUJFR0lOIENFUlRJRklDQVRFLS0tLS0uKi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0pLiovKTtcblxuICAgICAgICBpZihyYXdDZXJ0VGV4dCBpbnN0YW5jZW9mIEFycmF5KVxuICAgICAgICB7XG4gICAgICAgICAgICBsZXQgY2VydFRleHQgPSByYXdDZXJ0VGV4dFsxXS5yZXBsYWNlKC88YnI+L2csIE9TLkVPTCk7XG5cbiAgICAgICAgICAgIGxldCBwYXJzZWRDZXJ0SlNPTiA9IG51bGw7XG5cbiAgICAgICAgICAgIHRyeVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHBhcnNlZENlcnRKU09OID0gcGFyc2VDZXJ0KGNlcnRUZXh0KTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGNhdGNoKGUpXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgLy8gRG9uJ3QgdGhpbmsgdGhlcmUncyBhbnl0aGluZyBzZW5zaWJsZSB3ZSBjYW4gZG8gaGVyZSAoPylcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgaWYocGFyc2VkQ2VydEpTT04gaW5zdGFuY2VvZiBPYmplY3QpXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgbGV0IGNlcnRKU09OID1cbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHNlcmlhbDogcGFyc2VkQ2VydEpTT04uc2VyaWFsIHx8IG51bGwsXG4gICAgICAgICAgICAgICAgICAgIHN1YmplY3Q6IHBhcnNlZENlcnRKU09OLnN1YmplY3QgfHwge30sIC8vIGVzbGludC1kaXNhYmxlLWxpbmUgb2JqZWN0LWN1cmx5LW5ld2xpbmVcbiAgICAgICAgICAgICAgICAgICAgaXNzdWVyOiBwYXJzZWRDZXJ0SlNPTi5pc3N1ZXIgfHwge30sIC8vIGVzbGludC1kaXNhYmxlLWxpbmUgb2JqZWN0LWN1cmx5LW5ld2xpbmVcbiAgICAgICAgICAgICAgICAgICAgdmFsaWRGcm9tOiBwYXJzZWRDZXJ0SlNPTi5ub3RCZWZvcmUgfHwgbnVsbCxcbiAgICAgICAgICAgICAgICAgICAgdmFsaWRGcm9tVFM6IDAsIC8vIFdpbGwgYmUgdXBkYXRlZCBiZWxvd1xuICAgICAgICAgICAgICAgICAgICB2YWxpZFRvOiBwYXJzZWRDZXJ0SlNPTi5ub3RBZnRlciB8fCBudWxsLFxuICAgICAgICAgICAgICAgICAgICB2YWxpZFRvVFM6IDAsIC8vIFdpbGwgYmUgdXBkYXRlZCBiZWxvd1xuICAgICAgICAgICAgICAgICAgICBkYXlzUmVtYWluaW5nOiAwLCAvLyBXaWxsIGJlIHVwZGF0ZWQgYmVsb3dcbiAgICAgICAgICAgICAgICAgICAgU0FOOiBwYXJzZWRDZXJ0SlNPTi5hbHROYW1lcyB8fCBbXVxuICAgICAgICAgICAgICAgIH07XG5cbiAgICAgICAgICAgICAgICB0cnlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGNlcnRKU09OLnZhbGlkRnJvbVRTID0gcGFyc2VJbnQobmV3IERhdGUoY2VydEpTT04udmFsaWRGcm9tKS5nZXRUaW1lKCkgLyAxMDAwLCAxMCk7IC8vIG5lZWQgdG8gcmVtb3ZlIGxhc3QgMyBjaGFycyBhcyBKUyB1c2UgTVNlYyBUUydzXG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGNhdGNoKGUpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBjZXJ0SlNPTi52YWxpZEZyb21UUyA9IDA7IC8vIElzIHRoZXJlIGFueXRoaW5nIG1vcmUgc2Vuc2libGUgd2hpY2ggY291bGQgYmUgZG9uZT9cbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICB0cnlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGNlcnRKU09OLnZhbGlkVG9UUyA9IHBhcnNlSW50KG5ldyBEYXRlKGNlcnRKU09OLnZhbGlkVG8pLmdldFRpbWUoKSAvIDEwMDAsIDEwKTsgLy8gbmVlZCB0byByZW1vdmUgbGFzdCAzIGNoYXJzIGFzIEpTIHVzZSBNU2VjIFRTJ3NcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgY2F0Y2goZSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGNlcnRKU09OLnZhbGlkRnJvbVRTID0gMDsgLy8gSXMgdGhlcmUgYW55dGhpbmcgbW9yZSBzZW5zaWJsZSB3aGljaCBjb3VsZCBiZSBkb25lP1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIGNlcnRKU09OLmRheXNSZW1haW5pbmcgPSBNYXRoLmZsb29yKChjZXJ0SlNPTi52YWxpZFRvVFMgLSBub3dUUykgLyA4NjQwMCk7XG5cbiAgICAgICAgICAgICAgICByZXQgPSBjZXJ0SlNPTjtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICByZXQgPSBuZXcgVHlwZUVycm9yKFwicmF3Q2VydFN1bW1hcnkuJHQgZG9lcyBub3QgY29udGFpbiBhIHZhbGlkIHg1MDkgY2VydGlmaWNhdGVcIik7XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICAgICAgZWxzZVxuICAgICAgICB7XG4gICAgICAgICAgICByZXQgPSBuZXcgVHlwZUVycm9yKFwicmF3Q2VydFN1bW1hcnkuJHQgZG9lcyBub3QgY29udGFpbiBhbiB4NTA5IGNlcnRpZmljYXRlXCIpO1xuICAgICAgICB9XG4gICAgfVxuICAgIGVsc2VcbiAgICB7XG4gICAgICAgIHJldCA9IG5ldyBUeXBlRXJyb3IoXCJyYXdDZXJ0U3VtbWFyeSBtdXN0IGNvbnRhaW4gYSBwcm9wZXJ0eSBuYW1lZCAnJHQnXCIpO1xuICAgIH1cblxuICAgIHJldHVybiByZXQ7IC8vIFR5cGVFcnJvciBpZiBlcnJvciwgb2JqZWN0IG90aGVyd2lzZVxufVxuXG5mdW5jdGlvbiBnZXRDZXJ0c0RhdGEocGFyc2VkSlNPTjogT2JqZWN0LCBpZ25vcmVDZXJ0c1ZhbGlkRnJvbUJlZm9yZVRTOiBudW1iZXIgPSBkZWZhdWx0cy5pZ25vcmVDZXJ0c1ZhbGlkRnJvbUJlZm9yZVRTLCBpZ25vcmVDZXJ0c1ZhbGlkVG9CZWZvcmVUUzogbnVtYmVyID0gZGVmYXVsdHMuaWdub3JlQ2VydHNWYWxpZFRvQmVmb3JlVFMsIGV4cGVjdGVkQ0FzOiBBcnJheSA9IGRlZmF1bHRzLmV4cGVjdGVkQ0FzLCBjYWxsYmFjazogRnVuY3Rpb24pXG57XG4gICAgLyogTk9URTogSlNPTiBzdHJ1Y3R1cmUgb2YgcGFyc2VkSlNPTiBpczpcbiAgICB7XG4gICAgICAgIGZlZWQ6XG4gICAgICAgIHtcbiAgICAgICAgICAgIHhtbG5zOiAnaHR0cDovL3d3dy53My5vcmcvMjAwNS9BdG9tJyxcbiAgICAgICAgICAgICd4bWw6bGFuZyc6ICdlbicsXG4gICAgICAgICAgICBhdXRob3I6IHsgbmFtZTogJ2NydC5zaCcsIHVyaTogJ2h0dHBzOi8vY3J0LnNoLycgfSxcbiAgICAgICAgICAgIGljb246ICdodHRwczovL2NydC5zaC9mYXZpY29uLmljbycsXG4gICAgICAgICAgICBpZDogJ2h0dHBzOi8vY3J0LnNoLz9pZGVudGl0eT0lMjUuYmJjLmNvbSZleGNsdWRlPWV4cGlyZWQnLFxuICAgICAgICAgICAgbGluazogWyBbT2JqZWN0XSwgW09iamVjdF0gXSxcbiAgICAgICAgICAgIHRpdGxlOiAnaWRlbnRpdHk9JS5iYmMuY29tOyBleGNsdWRlPWV4cGlyZWQnLFxuICAgICAgICAgICAgdXBkYXRlZDogJzIwMTYtMDgtMDRUMTE6MDY6NDdaJyxcbiAgICAgICAgICAgIGVudHJ5OlxuICAgICAgICAgICAgW1xuICAgICAgICAgICAgICAgIFtPYmplY3RdLFxuICAgICAgICAgICAgICAgIFtPYmplY3RdLFxuICAgICAgICAgICAgICAgIC4uLlxuICAgICAgICAgICAgXVxuICAgICAgICB9XG4gICAgfVxuICAgICovXG5cbiAgICBsZXQgZXJyID0gbmV3IEVycm9yKFwiRWl0aGVyIHlvdXIgSlNPTiBpcyBtYWxmb3JtZWQgb3IgdGhlcmUgYXJlIG5vIHZhbGlkIGNlcnRpZmljYXRlcyBpbiB0aGUgZGF0YSAodmVyc3VzIGZpbHRlciBjcml0ZXJpYSlcIik7XG4gICAgbGV0IGNlcnRzRGF0YSA9XG4gICAge1xuICAgICAgICBhbGxDZXJ0czpcbiAgICAgICAge1xuICAgICAgICAgICAgY291bnQ6IDAsXG4gICAgICAgICAgICBlbnRyaWVzOiBbXVxuICAgICAgICB9LFxuICAgICAgICB1bmV4cGVjdGVkQ0E6XG4gICAgICAgIHtcbiAgICAgICAgICAgIGNvdW50OiAwLFxuICAgICAgICAgICAgZW50cmllczogW11cbiAgICAgICAgfSxcbiAgICAgICAgYnlDQTpcbiAgICAgICAge1xuICAgICAgICAgICAgY291bnQ6IDAsXG4gICAgICAgICAgICBlbnRyaWVzOlxuICAgICAgICAgICAge1xuXG4gICAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICB9O1xuXG4gICAgaWYocGFyc2VkSlNPTi5mZWVkKVxuICAgIHtcbiAgICAgICAgaWYocGFyc2VkSlNPTi5mZWVkLmVudHJ5IGluc3RhbmNlb2YgQXJyYXkpXG4gICAgICAgIHtcbiAgICAgICAgICAgIHBhcnNlZEpTT04uZmVlZC5lbnRyeS5mb3JFYWNoKChjZXJ0KSA9PlxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIC8vIFVzZSB4NTA5LmpzIHRvIHBhcnNlIHRoZSByYXcgY2VydCBzdHJpbmcgaW50byBjb25zaXN0ZW50IEpTT05cbiAgICAgICAgICAgICAgICBsZXQgY2VydERldGFpbHNKU09OID0gZ2V0Q2VydERldGFpbHMoY2VydC5zdW1tYXJ5KTtcblxuICAgICAgICAgICAgICAgIGlmKGNlcnREZXRhaWxzSlNPTiBpbnN0YW5jZW9mIE9iamVjdClcbiAgICAgICAgICAgICAgICB7XG4vLyBjb25zb2xlLmxvZyhcIkNlcnQgdmFsaWQgZnJvbSAlZCAtLSBpZ25vcmUgZnJvbTogJWQgLS0gZGlmZiAlZFwiLCBjZXJ0RGV0YWlsc0pTT04udmFsaWRUb1RTLCBpZ25vcmVDZXJ0c1ZhbGlkVG9CZWZvcmVUUywgKGNlcnREZXRhaWxzSlNPTi52YWxpZFRvVFMgLSBpZ25vcmVDZXJ0c1ZhbGlkVG9CZWZvcmVUUykgKTtcbiAgICAgICAgICAgICAgICAgICAgLy8gSWdub3JlIGNlcnRzIHdob3NlIHZhbGlkVG9UUyBpcyA8IGlnbm9yZUNlcnRzVmFsaWRUb0JlZm9yZVRTXG4gICAgICAgICAgICAgICAgICAgIGlmKGNlcnREZXRhaWxzSlNPTi52YWxpZFRvVFMgPj0gaWdub3JlQ2VydHNWYWxpZFRvQmVmb3JlVFMpXG4gICAgICAgICAgICAgICAgICAgIHtcbi8vIGNvbnNvbGUubG9nKFwiY2VydCBPS1wiKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIC8vIE5PVEU6IFRoaXMgbWF5IGJlIHRvbyBjb2Fyc2VcbiAgICAgICAgICAgICAgICAgICAgICAgIGVyciA9IG51bGw7XG5cbiAgICAgICAgICAgICAgICAgICAgICAgIC8vIE9ubHkgaW5jbHVkZSBjZXJ0cyB3aGljaCBoYXZlIGJlZW4gaXNzdWVkIHNpbmNlIHRoZSBsYXN0IHJ1biwgdW5sZXNzIHRoZSB1c2VyIGhhcyBvcHRlZCB0byByZXR1cm4gYWxsIGJ5IHNldHRpbmcgaWdub3JlQ2VydHNWYWxpZEZyb21CZWZvcmVUUyB0byAoZXhhY3RseSkgMFxuICAgICAgICAgICAgICAgICAgICAgICAgaWYoY2VydERldGFpbHNKU09OLnZhbGlkRnJvbVRTID49IGlnbm9yZUNlcnRzVmFsaWRGcm9tQmVmb3JlVFMgfHwgaWdub3JlQ2VydHNWYWxpZEZyb21CZWZvcmVUUyA9PT0gMClcbiAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAvLyBBbGwgY2VydHNcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBjZXJ0c0RhdGEuYWxsQ2VydHMuZW50cmllcy5wdXNoKGNlcnREZXRhaWxzSlNPTik7XG5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAvLyBDZXJ0cyB3aXRoIGFuIFwidW5leHBlY3RlZFwiIENBXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgbGV0IGV4cGVjdGVkQ0FNYXRjaCA9IGZhbHNlO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmKE9iamVjdC5rZXlzKGNlcnREZXRhaWxzSlNPTi5pc3N1ZXIpLmxlbmd0aCA+IDApXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBleHBlY3RlZENBcy5mb3JFYWNoKChFQ0EpID0+XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmKGNlcnREZXRhaWxzSlNPTi5pc3N1ZXIuY29tbW9uTmFtZS5tYXRjaChFQ0EpKVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGV4cGVjdGVkQ0FNYXRjaCA9IHRydWU7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmKGV4cGVjdGVkQ0FNYXRjaCA9PT0gZmFsc2UpXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjZXJ0c0RhdGEudW5leHBlY3RlZENBLmVudHJpZXMucHVzaChjZXJ0RGV0YWlsc0pTT04pO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIC8vIEFsbCBjZXJ0cywgZ3JvdXBlZCBieSBDQVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmKGNlcnRzRGF0YS5ieUNBLmVudHJpZXNbY2VydERldGFpbHNKU09OLmlzc3Vlci5jb21tb25OYW1lXSA9PT0gdW5kZWZpbmVkKVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY2VydHNEYXRhLmJ5Q0EuZW50cmllc1tjZXJ0RGV0YWlsc0pTT04uaXNzdWVyLmNvbW1vbk5hbWVdID0gW107XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgY2VydHNEYXRhLmJ5Q0EuZW50cmllc1tjZXJ0RGV0YWlsc0pTT04uaXNzdWVyLmNvbW1vbk5hbWVdLnB1c2goY2VydERldGFpbHNKU09OKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBlcnIgPSBuZXcgVHlwZUVycm9yKFwiSlNPTiBpcyBtYWxmb3JtZWQsIHJlamVjdGluZ1wiKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfVxuICAgIH1cblxuICAgIC8vIENvdW50cyAodG90YWxzKVxuICAgIGNlcnRzRGF0YS5hbGxDZXJ0cy5jb3VudCA9IGNlcnRzRGF0YS5hbGxDZXJ0cy5lbnRyaWVzLmxlbmd0aDtcbiAgICBjZXJ0c0RhdGEudW5leHBlY3RlZENBLmNvdW50ID0gY2VydHNEYXRhLnVuZXhwZWN0ZWRDQS5lbnRyaWVzLmxlbmd0aDtcbiAgICBjZXJ0c0RhdGEuYnlDQS5jb3VudCA9IE9iamVjdC5rZXlzKGNlcnRzRGF0YS5ieUNBLmVudHJpZXMpLmxlbmd0aDtcblxuICAgIGlmKGVyciAhPT0gbnVsbClcbiAgICB7XG4gICAgICAgIGNlcnRzRGF0YSA9IG51bGw7XG4gICAgfVxuXG4gICAgcmV0dXJuIGNhbGxiYWNrKGVyciwgY2VydHNEYXRhKTtcbn1cblxuXG5mdW5jdGlvbiBjb252ZXJ0WE1MVG9KU09OKFhNTDogc3RyaW5nLCBjYWxsYmFjazogRnVuY3Rpb24pXG57XG4gICAgbGV0IGVyciA9IG51bGw7XG4gICAgbGV0IHBhcnNlZEpTT04gPSBudWxsO1xuXG4gICAgLy8gV2UgdHJ5L2NhdGNoIHNvIHRoYXQgdGhlIHRvSnNvbiBsaWIgZm4gY2FuIHRocm93IGlmIGl0IG5lZWQgdG8gd2l0aG91dCB1cyB0aHJvd2luZ1xuICAgIHRyeVxuICAgIHtcbiAgICAgICAgLy8gTk9URTogdG9Kc29uIGlzIGEgM3JkIHBhcnR5IGRlcCAoeG1sMmpzb24pXG4gICAgICAgIGxldCByYXdKU09OID0gdG9Kc29uKFhNTCk7XG5cbiAgICAgICAgLy8gU29tZXdoYXQgb2RkbHksIHRvSnNvbiByZXR1cm5zIGEgc3RyaW5naWZpZWQgSlNPTiBvYmplY3RcbiAgICAgICAgcGFyc2VkSlNPTiA9IEpTT04ucGFyc2UocmF3SlNPTik7XG5cbiAgICAgICAgaWYoT2JqZWN0LmtleXMocGFyc2VkSlNPTikubGVuZ3RoID09PSAwKVxuICAgICAgICB7XG4gICAgICAgICAgICBlcnIgPSBuZXcgVHlwZUVycm9yKFwiQXJndW1lbnQgJ1hNTCcgcmVzdWx0ZWQgaW4gbm8gSlNPTiBvdXRwdXQsIGl0J3MgcHJvYmFibHkgbm90IFhNTFwiKTtcbiAgICAgICAgICAgIHBhcnNlZEpTT04gPSBudWxsO1xuICAgICAgICB9XG4gICAgfVxuICAgIGNhdGNoIChlKVxuICAgIHtcbiAgICAgICAgZXJyID0gZTtcbiAgICB9XG5cblxuICAgIHJldHVybiBjYWxsYmFjayhlcnIsIHBhcnNlZEpTT04pO1xufVxuXG5cbmZ1bmN0aW9uIGdldFJTU1hNTChkb21haW5OYW1lUGF0dGVybjogc3RyaW5nLCBjYWxsYmFjazogRnVuY3Rpb24pIC8vIGVzbGludC1kaXNhYmxlLWxpbmUgY29uc2lzdGVudC1yZXR1cm5cbntcbiAgICBpZihkb21haW5OYW1lUGF0dGVybi5sZW5ndGggPiAwKVxuICAgIHtcbiAgICAgICAgbGV0IHhtbCA9IFwiXCI7XG5cbiAgICAgICAgLy8gTk9URTogV2UncmUgZG9pbmcgYSBwbGFpbiAobm90IGlmLW1vZGlmaWVkLXNpbmNlKSBHRVQgb24gdGhlIFVSTCBhbmQgYXJlIE5PVCB1c2luZyB0aGUgYnVpbHQtaW4gXCJpZ25vcmUgZXhwaXJlZCBjZXJ0c1wiIGFzIHdlIGRvIHRoYXQgcHJvZ3JhbW1hdGl2YWxseSB2aWEgaWdub3JlQ2VydHNWYWxpZFRvQmVmb3JlVFNcbiAgICAgICAgZ2V0KFwiaHR0cHM6Ly9jcnQuc2gvYXRvbT9pZGVudGl0eT1cIiArIGRvbWFpbk5hbWVQYXR0ZXJuLCAocmVzcG9uc2UpID0+XG4gICAgICAgIHtcbiAgICAgICAgICAgIHJlc3BvbnNlLm9uKFwiZGF0YVwiLCAoZCkgPT5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB4bWwgKz0gZC50b1N0cmluZyhcInV0ZjhcIik7XG4gICAgICAgICAgICB9KTtcblxuICAgICAgICAgICAgcmVzcG9uc2Uub24oXCJlbmRcIiwgKGUpID0+XG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgbGV0IGVyciA9IGU7XG4gICAgICAgICAgICAgICAgaWYoZSA9PT0gdW5kZWZpbmVkKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgZXJyID0gbnVsbDtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZSAvLyBpZiB0aGVyZSdzIGJlZW4gYW4gZXJyb3IsIHdlIHdhbnQgdG8gbnVsbGlmeSB4bWxcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHhtbCA9IG51bGw7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgcmV0dXJuIGNhbGxiYWNrKGVyciwgeG1sKTtcbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9KTtcbiAgICB9XG4gICAgZWxzZVxuICAgIHtcbiAgICAgICAgbGV0IGVyciA9IG5ldyBUeXBlRXJyb3IoXCJBcmd1bWVudCAnZG9tYWluTmFtZVBhdHRlcm4nIG11c3Qgbm90IGJlIGVtcHR5XCIpO1xuICAgICAgICByZXR1cm4gY2FsbGJhY2soZXJyLCBudWxsKTtcbiAgICB9XG59XG5cblxuLy8gTWF5YmUgdGhpcyBzaG91bGQgYmUgYW4gb3B0aW9uIG9iaj8gZm9yIGF0IGxlYXN0IGUuZy4gY29uZmlnLXR5cGUgb3B0aW9uc1xuZnVuY3Rpb24gY2hlY2tDVExvZ3MoZG9tYWluTmFtZVBhdHRlcm5zOiBBcnJheSwgaWdub3JlQ2VydHNWYWxpZEZyb21CZWZvcmVUUzogbnVtYmVyID0gZGVmYXVsdHMuaWdub3JlQ2VydHNWYWxpZEZyb21CZWZvcmVUUywgaWdub3JlQ2VydHNWYWxpZFRvQmVmb3JlVFM6IG51bWJlciA9IGRlZmF1bHRzLmlnbm9yZUNlcnRzVmFsaWRUb0JlZm9yZVRTLCBleHBlY3RlZENBczogQXJyYXkgPSBkZWZhdWx0cy5leHBlY3RlZENBcywgY2FsbGJhY2s6IEZ1bmN0aW9uKVxue1xuICAgIGNvbnN0IHRvdGFsTnVtRG9tYWluTmFtZVBhdHRlcm5zID0gZG9tYWluTmFtZVBhdHRlcm5zLmxlbmd0aDtcbiAgICBsZXQgdG90YWxOdW1Eb21haW5OYW1lUGF0dGVybnNDb21wbGV0ZWQgPSAwO1xuXG4gICAgZG9tYWluTmFtZVBhdHRlcm5zLmZvckVhY2goKGRvbWFpbk5hbWVQYXR0ZXJuKSA9PlxuICAgIHtcbiAgICAgICAgLy8gSFRUUDItY2FwYWJsZSBHRVQgb2YgdGhlIHNwZWNpZmljIFhNTCBmZWVkIGZvciB0aGUgcmVsZXZhbnQgZG9tYWluIG5hbWUgcGF0dGVybiAoZS5nLiAlLmJiYy5jby51ayAtIHdoZXJlICUgaXMgYSB3aWxkY2FyZClcbiAgICAgICAgZ2V0UlNTWE1MKGRvbWFpbk5hbWVQYXR0ZXJuLCAoUlNTRXJyb3IsIFJTU1hNTCkgPT4gLy8gZXNsaW50LWRpc2FibGUtbGluZSBjb25zaXN0ZW50LXJldHVyblxuICAgICAgICB7XG4gICAgICAgICAgICBpZihSU1NFcnJvcilcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gY2FsbGJhY2soUlNTRXJyb3IsIG51bGwpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAvLyBSYXcgY29udmVyc2lvbiBmcm9tIFhNTCB0byBKU09OXG4gICAgICAgICAgICBjb252ZXJ0WE1MVG9KU09OKFJTU1hNTCwgKGNvbnZlcnRFcnIsIFJTU0pTT04pID0+IC8vIGVzbGludC1kaXNhYmxlLWxpbmUgY29uc2lzdGVudC1yZXR1cm5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZihjb252ZXJ0RXJyKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGNhbGxiYWNrKGNvbnZlcnRFcnIsIG51bGwpO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIERvd25sb2FkaW5nIG9mIFJTUyBmZWVkIGZyb20gY3J0LnNoIHdpdGggZmlsdGVyaW5nIGFuZCBwYXJzaW5nXG4gICAgICAgICAgICAgICAgZ2V0Q2VydHNEYXRhKFJTU0pTT04sIGlnbm9yZUNlcnRzVmFsaWRGcm9tQmVmb3JlVFMsIGlnbm9yZUNlcnRzVmFsaWRUb0JlZm9yZVRTLCBleHBlY3RlZENBcywgKGdldENlcnRzRGF0YUVyciwgY2VydHNEYXRhKSA9PiAvLyBlc2xpbnQtZGlzYWJsZS1saW5lIGNvbnNpc3RlbnQtcmV0dXJuXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBpZihnZXRDZXJ0c0RhdGFFcnIpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBjYWxsYmFjayhnZXRDZXJ0c0RhdGFFcnIsIG51bGwpO1xuICAgICAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAgICAgLy8gVHJhY2sgaG93IG1hbnkgb2YgdGhlIGNvbmZpZ3VyZWQgZG9tYWluTmFtZVBhdHRlcm5zIHdlJ3ZlIGNvbXBsZXRlZCBhbmQuLi5cbiAgICAgICAgICAgICAgICAgICAgdG90YWxOdW1Eb21haW5OYW1lUGF0dGVybnNDb21wbGV0ZWQrKztcblxuICAgICAgICAgICAgICAgICAgICAvLyAuLi5leGl0IHdoZW4gYWxsIGRvbWFpbk5hbWVQYXR0ZXJucyBhcmUgY29tcGxldGUgKGJlY2F1c2UgdGhpcyBpcyBhc3luYylcbiAgICAgICAgICAgICAgICAgICAgaWYodG90YWxOdW1Eb21haW5OYW1lUGF0dGVybnNDb21wbGV0ZWQgPj0gdG90YWxOdW1Eb21haW5OYW1lUGF0dGVybnMpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBjYWxsYmFjayhudWxsLCBjZXJ0c0RhdGEpO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfSk7XG4gICAgfSk7XG59XG5cbi8vIFdlICpzaG91bGQqIG9ubHkgbmVlZCB0byBleHBvcnQgdGhlIHVzZXItZmFjaW5nIGZ1bmN0aW9uXG5tb2R1bGUuZXhwb3J0cyA9XG57XG4gICAgZ2V0Q2VydERldGFpbHM6IGdldENlcnREZXRhaWxzLFxuICAgIGdldENlcnRzRGF0YTogZ2V0Q2VydHNEYXRhLFxuICAgIGNvbnZlcnRYTUxUb0pTT046IGNvbnZlcnRYTUxUb0pTT04sXG4gICAgZ2V0UlNTWE1MOiBnZXRSU1NYTUwsXG4gICAgY2hlY2tDVExvZ3M6IGNoZWNrQ1RMb2dzXG59O1xuIl19