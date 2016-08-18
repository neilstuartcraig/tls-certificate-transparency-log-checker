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
                    // Ignore certs whose validToTS is < ignoreCertsValidToBeforeTS
                    if (certDetailsJSON.validToTS >= ignoreCertsValidToBeforeTS) {
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
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIi4uLy4uL3NyYy9saWIvdGxzLWNlcnRpZmljYXRlLXRyYW5zcGFyZW5jeS1sb2ctY2hlY2tlci1saWIuanMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6IkFBQUE7O0FBRUE7Ozs7QUFHQTs7O0FBRkE7Ozs7QUFHQTs7QUFDQTs7QUFDQTs7OztBQUVBO0FBQ0EsSUFBTSxRQUFRLFNBQVMsSUFBSSxJQUFKLEdBQVcsT0FBWCxLQUF1QixJQUFoQyxFQUFzQyxFQUF0QyxDQUFkLEMsQ0FBeUQ7QUFDekQsSUFBTSxXQUNOO0FBQ0ksa0NBQThCLFFBQVEsS0FEMUMsRUFDaUQ7QUFDN0MsZ0NBQTRCLEtBRmhDO0FBR0ksaUJBQWEsRUFIakIsQ0FHb0I7QUFIcEIsQ0FEQTs7QUFRQTtBQUNBLFNBQVMsY0FBVCxDQUF3QixjQUF4QixFQUNBO0FBQUEsVUFEd0IsY0FDeEIsWUFEd0MsTUFDeEM7QUFBQSxnSUFEd0IsY0FDeEI7QUFBQTs7QUFDSSxRQUFJLE1BQU0sSUFBVjs7QUFFQSxRQUFHLFFBQVEsY0FBWCxFQUNBO0FBQ0ksWUFBSSxjQUFjLGVBQWUsSUFBZixFQUFxQixLQUFyQixDQUEyQiw4REFBM0IsQ0FBbEI7O0FBRUEsWUFBRyx1QkFBdUIsS0FBMUIsRUFDQTtBQUNJLGdCQUFJLFdBQVcsWUFBWSxDQUFaLEVBQWUsT0FBZixDQUF1QixPQUF2QixFQUFnQyxhQUFHLEdBQW5DLENBQWY7O0FBRUEsZ0JBQUksaUJBQWlCLElBQXJCOztBQUVBLGdCQUNBO0FBQ0ksaUNBQWlCLG1CQUFVLFFBQVYsQ0FBakI7QUFDSCxhQUhELENBSUEsT0FBTSxDQUFOLEVBQ0E7QUFDSTtBQUNIOztBQUVELGdCQUFHLDBCQUEwQixNQUE3QixFQUNBO0FBQ0ksb0JBQUksV0FDSjtBQUNJLDRCQUFRLGVBQWUsTUFBZixJQUF5QixJQURyQztBQUVJLDZCQUFTLGVBQWUsT0FBZixJQUEwQixFQUZ2QyxFQUUyQztBQUN2Qyw0QkFBUSxlQUFlLE1BQWYsSUFBeUIsRUFIckMsRUFHeUM7QUFD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QSxrQkFBVSxpQkFBVixFQUE2QixVQUFDLFFBQUQsRUFBVyxNQUFYLEVBQXNCO0FBQ25EO0FBQ0ksZ0JBQUcsUUFBSCxFQUNBO0FBQ0ksdUJBQU8sU0FBUyxRQUFULEVBQW1CLElBQW5CLENBQVA7QUFDSDs7QUFFRDtBQUNBLDZCQUFpQixNQUFqQixFQUF5QixVQUFDLFVBQUQsRUFBYSxPQUFiLEVBQXlCO0FBQ2xEO0FBQ0ksb0JBQUcsVUFBSCxFQUNBO0FBQ0ksMkJBQU8sU0FBUyxVQUFULEVBQXFCLElBQXJCLENBQVA7QUFDSDs7QUFFRDtBQUNBLDZCQUFhLE9BQWIsRUFBc0IsNEJBQXRCLEVBQW9ELDBCQUFwRCxFQUFnRixXQUFoRixFQUE2RixVQUFDLGVBQUQsRUFBa0IsU0FBbEIsRUFBZ0M7QUFDN0g7QUFDSSx3QkFBRyxlQUFILEVBQ0E7QUFDSSwrQkFBTyxTQUFTLGVBQVQsRUFBMEIsSUFBMUIsQ0FBUDtBQUNIOztBQUVEO0FBQ0E7O0FBRUE7QUFDQSx3QkFBRyx1Q0FBdUMsMEJBQTFDLEVBQ0E7QUFDSSwrQkFBTyxTQUFTLElBQVQsRUFBZSxTQUFmLENBQVA7QUFDSDtBQUNKLGlCQWZEO0FBZ0JILGFBeEJEO0FBeUJILFNBakNEO0FBa0NILEtBckNEO0FBc0NIOztBQUVEO0FBQ0EsT0FBTyxPQUFQLEdBQ0E7QUFDSSxvQkFBZ0IsY0FEcEI7QUFFSSxrQkFBYyxZQUZsQjtBQUdJLHNCQUFrQixnQkFIdEI7QUFJSSxlQUFXLFNBSmY7QUFLSSxpQkFBYTtBQUxqQixDQURBIiwiZmlsZSI6InRscy1jZXJ0aWZpY2F0ZS10cmFuc3BhcmVuY3ktbG9nLWNoZWNrZXItbGliLmpzIiwic291cmNlc0NvbnRlbnQiOlsiXCJ1c2Ugc3RyaWN0XCI7XG5cbi8vIENvcmUgZGVwc1xuaW1wb3J0IE9TIGZyb20gXCJvc1wiO1xuXG4vLyAzcmQgcGFydHkgZGVwc1xuaW1wb3J0IHtwYXJzZUNlcnR9IGZyb20gXCJ4NTA5LmpzXCI7XG5pbXBvcnQge3RvSnNvbn0gZnJvbSBcInhtbDJqc29uXCI7XG5pbXBvcnQge2dldH0gZnJvbSBcImh0dHBzXCI7XG5cbi8vIERlZmF1bHRzICh1c2VkIGluIGZ1bmN0aW9uIGRlZmluaXRpb25zKVxuY29uc3Qgbm93VFMgPSBwYXJzZUludChuZXcgRGF0ZSgpLmdldFRpbWUoKSAvIDEwMDAsIDEwKTsgLy8gTk9URTogSlMgdGltZXN0YW1wcyBhcmUgaW4gbXNlY1xuY29uc3QgZGVmYXVsdHMgPVxue1xuICAgIGlnbm9yZUNlcnRzVmFsaWRGcm9tQmVmb3JlVFM6IG5vd1RTIC0gODY0MDAsIC8vIDEgZGF5IGFnb1xuICAgIGlnbm9yZUNlcnRzVmFsaWRUb0JlZm9yZVRTOiBub3dUUyxcbiAgICBleHBlY3RlZENBczogW10gLy8gRGVmYXVsdCBpcyBleHBlY3Qgbm9uZVxufTtcblxuXG4vLyBOT1RFOiBUaGlzIGlzIHN5bmMgZm9yIHRoZSBtb21lbnQgd2hpY2ggaXMgcHJvYmFibHkgYSBiYWQgaWRlYSAtIG1ha2luZyBhc3luYyB3aWxsIG5lZWQgd29yayBvbiBnZXRDZXJ0c0RhdGEoKSAoYmVsb3cpXG5mdW5jdGlvbiBnZXRDZXJ0RGV0YWlscyhyYXdDZXJ0U3VtbWFyeTogT2JqZWN0KVxue1xuICAgIGxldCByZXQgPSBudWxsO1xuXG4gICAgaWYoXCIkdFwiIGluIHJhd0NlcnRTdW1tYXJ5KVxuICAgIHtcbiAgICAgICAgbGV0IHJhd0NlcnRUZXh0ID0gcmF3Q2VydFN1bW1hcnlbXCIkdFwiXS5tYXRjaCgvLiooLS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tLiotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tKS4qLyk7XG5cbiAgICAgICAgaWYocmF3Q2VydFRleHQgaW5zdGFuY2VvZiBBcnJheSlcbiAgICAgICAge1xuICAgICAgICAgICAgbGV0IGNlcnRUZXh0ID0gcmF3Q2VydFRleHRbMV0ucmVwbGFjZSgvPGJyPi9nLCBPUy5FT0wpO1xuXG4gICAgICAgICAgICBsZXQgcGFyc2VkQ2VydEpTT04gPSBudWxsO1xuXG4gICAgICAgICAgICB0cnlcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBwYXJzZWRDZXJ0SlNPTiA9IHBhcnNlQ2VydChjZXJ0VGV4dCk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBjYXRjaChlKVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIC8vIERvbid0IHRoaW5rIHRoZXJlJ3MgYW55dGhpbmcgc2Vuc2libGUgd2UgY2FuIGRvIGhlcmUgKD8pXG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIGlmKHBhcnNlZENlcnRKU09OIGluc3RhbmNlb2YgT2JqZWN0KVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGxldCBjZXJ0SlNPTiA9XG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBzZXJpYWw6IHBhcnNlZENlcnRKU09OLnNlcmlhbCB8fCBudWxsLFxuICAgICAgICAgICAgICAgICAgICBzdWJqZWN0OiBwYXJzZWRDZXJ0SlNPTi5zdWJqZWN0IHx8IHt9LCAvLyBlc2xpbnQtZGlzYWJsZS1saW5lIG9iamVjdC1jdXJseS1uZXdsaW5lXG4gICAgICAgICAgICAgICAgICAgIGlzc3VlcjogcGFyc2VkQ2VydEpTT04uaXNzdWVyIHx8IHt9LCAvLyBlc2xpbnQtZGlzYWJsZS1saW5lIG9iamVjdC1jdXJseS1uZXdsaW5lXG4gICAgICAgICAgICAgICAgICAgIHZhbGlkRnJvbTogcGFyc2VkQ2VydEpTT04ubm90QmVmb3JlIHx8IG51bGwsXG4gICAgICAgICAgICAgICAgICAgIHZhbGlkRnJvbVRTOiAwLCAvLyBXaWxsIGJlIHVwZGF0ZWQgYmVsb3dcbiAgICAgICAgICAgICAgICAgICAgdmFsaWRUbzogcGFyc2VkQ2VydEpTT04ubm90QWZ0ZXIgfHwgbnVsbCxcbiAgICAgICAgICAgICAgICAgICAgdmFsaWRUb1RTOiAwLCAvLyBXaWxsIGJlIHVwZGF0ZWQgYmVsb3dcbiAgICAgICAgICAgICAgICAgICAgZGF5c1JlbWFpbmluZzogMCwgLy8gV2lsbCBiZSB1cGRhdGVkIGJlbG93XG4gICAgICAgICAgICAgICAgICAgIFNBTjogcGFyc2VkQ2VydEpTT04uYWx0TmFtZXMgfHwgW11cbiAgICAgICAgICAgICAgICB9O1xuXG4gICAgICAgICAgICAgICAgdHJ5XG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBjZXJ0SlNPTi52YWxpZEZyb21UUyA9IHBhcnNlSW50KG5ldyBEYXRlKGNlcnRKU09OLnZhbGlkRnJvbSkuZ2V0VGltZSgpIC8gMTAwMCwgMTApOyAvLyBuZWVkIHRvIHJlbW92ZSBsYXN0IDMgY2hhcnMgYXMgSlMgdXNlIE1TZWMgVFMnc1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBjYXRjaChlKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgY2VydEpTT04udmFsaWRGcm9tVFMgPSAwOyAvLyBJcyB0aGVyZSBhbnl0aGluZyBtb3JlIHNlbnNpYmxlIHdoaWNoIGNvdWxkIGJlIGRvbmU/XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgdHJ5XG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBjZXJ0SlNPTi52YWxpZFRvVFMgPSBwYXJzZUludChuZXcgRGF0ZShjZXJ0SlNPTi52YWxpZFRvKS5nZXRUaW1lKCkgLyAxMDAwLCAxMCk7IC8vIG5lZWQgdG8gcmVtb3ZlIGxhc3QgMyBjaGFycyBhcyBKUyB1c2UgTVNlYyBUUydzXG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGNhdGNoKGUpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBjZXJ0SlNPTi52YWxpZEZyb21UUyA9IDA7IC8vIElzIHRoZXJlIGFueXRoaW5nIG1vcmUgc2Vuc2libGUgd2hpY2ggY291bGQgYmUgZG9uZT9cbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBjZXJ0SlNPTi5kYXlzUmVtYWluaW5nID0gTWF0aC5mbG9vcigoY2VydEpTT04udmFsaWRUb1RTIC0gbm93VFMpIC8gODY0MDApO1xuXG4gICAgICAgICAgICAgICAgcmV0ID0gY2VydEpTT047XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgcmV0ID0gbmV3IFR5cGVFcnJvcihcInJhd0NlcnRTdW1tYXJ5LiR0IGRvZXMgbm90IGNvbnRhaW4gYSB2YWxpZCB4NTA5IGNlcnRpZmljYXRlXCIpO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG4gICAgICAgIGVsc2VcbiAgICAgICAge1xuICAgICAgICAgICAgcmV0ID0gbmV3IFR5cGVFcnJvcihcInJhd0NlcnRTdW1tYXJ5LiR0IGRvZXMgbm90IGNvbnRhaW4gYW4geDUwOSBjZXJ0aWZpY2F0ZVwiKTtcbiAgICAgICAgfVxuICAgIH1cbiAgICBlbHNlXG4gICAge1xuICAgICAgICByZXQgPSBuZXcgVHlwZUVycm9yKFwicmF3Q2VydFN1bW1hcnkgbXVzdCBjb250YWluIGEgcHJvcGVydHkgbmFtZWQgJyR0J1wiKTtcbiAgICB9XG5cbiAgICByZXR1cm4gcmV0OyAvLyBUeXBlRXJyb3IgaWYgZXJyb3IsIG9iamVjdCBvdGhlcndpc2Vcbn1cblxuZnVuY3Rpb24gZ2V0Q2VydHNEYXRhKHBhcnNlZEpTT046IE9iamVjdCwgaWdub3JlQ2VydHNWYWxpZEZyb21CZWZvcmVUUzogbnVtYmVyID0gZGVmYXVsdHMuaWdub3JlQ2VydHNWYWxpZEZyb21CZWZvcmVUUywgaWdub3JlQ2VydHNWYWxpZFRvQmVmb3JlVFM6IG51bWJlciA9IGRlZmF1bHRzLmlnbm9yZUNlcnRzVmFsaWRUb0JlZm9yZVRTLCBleHBlY3RlZENBczogQXJyYXkgPSBkZWZhdWx0cy5leHBlY3RlZENBcywgY2FsbGJhY2s6IEZ1bmN0aW9uKVxue1xuICAgIC8qIE5PVEU6IEpTT04gc3RydWN0dXJlIG9mIHBhcnNlZEpTT04gaXM6XG4gICAge1xuICAgICAgICBmZWVkOlxuICAgICAgICB7XG4gICAgICAgICAgICB4bWxuczogJ2h0dHA6Ly93d3cudzMub3JnLzIwMDUvQXRvbScsXG4gICAgICAgICAgICAneG1sOmxhbmcnOiAnZW4nLFxuICAgICAgICAgICAgYXV0aG9yOiB7IG5hbWU6ICdjcnQuc2gnLCB1cmk6ICdodHRwczovL2NydC5zaC8nIH0sXG4gICAgICAgICAgICBpY29uOiAnaHR0cHM6Ly9jcnQuc2gvZmF2aWNvbi5pY28nLFxuICAgICAgICAgICAgaWQ6ICdodHRwczovL2NydC5zaC8/aWRlbnRpdHk9JTI1LmJiYy5jb20mZXhjbHVkZT1leHBpcmVkJyxcbiAgICAgICAgICAgIGxpbms6IFsgW09iamVjdF0sIFtPYmplY3RdIF0sXG4gICAgICAgICAgICB0aXRsZTogJ2lkZW50aXR5PSUuYmJjLmNvbTsgZXhjbHVkZT1leHBpcmVkJyxcbiAgICAgICAgICAgIHVwZGF0ZWQ6ICcyMDE2LTA4LTA0VDExOjA2OjQ3WicsXG4gICAgICAgICAgICBlbnRyeTpcbiAgICAgICAgICAgIFtcbiAgICAgICAgICAgICAgICBbT2JqZWN0XSxcbiAgICAgICAgICAgICAgICBbT2JqZWN0XSxcbiAgICAgICAgICAgICAgICAuLi5cbiAgICAgICAgICAgIF1cbiAgICAgICAgfVxuICAgIH1cbiAgICAqL1xuXG4gICAgbGV0IGVyciA9IG5ldyBFcnJvcihcIkVpdGhlciB5b3VyIEpTT04gaXMgbWFsZm9ybWVkIG9yIHRoZXJlIGFyZSBubyB2YWxpZCBjZXJ0aWZpY2F0ZXMgaW4gdGhlIGRhdGEgKHZlcnN1cyBmaWx0ZXIgY3JpdGVyaWEpXCIpO1xuICAgIGxldCBjZXJ0c0RhdGEgPVxuICAgIHtcbiAgICAgICAgYWxsQ2VydHM6XG4gICAgICAgIHtcbiAgICAgICAgICAgIGNvdW50OiAwLFxuICAgICAgICAgICAgZW50cmllczogW11cbiAgICAgICAgfSxcbiAgICAgICAgdW5leHBlY3RlZENBOlxuICAgICAgICB7XG4gICAgICAgICAgICBjb3VudDogMCxcbiAgICAgICAgICAgIGVudHJpZXM6IFtdXG4gICAgICAgIH0sXG4gICAgICAgIGJ5Q0E6XG4gICAgICAgIHtcbiAgICAgICAgICAgIGNvdW50OiAwLFxuICAgICAgICAgICAgZW50cmllczpcbiAgICAgICAgICAgIHtcblxuICAgICAgICAgICAgfVxuICAgICAgICB9XG4gICAgfTtcblxuICAgIGlmKHBhcnNlZEpTT04uZmVlZClcbiAgICB7XG4gICAgICAgIGlmKHBhcnNlZEpTT04uZmVlZC5lbnRyeSBpbnN0YW5jZW9mIEFycmF5KVxuICAgICAgICB7XG4gICAgICAgICAgICBwYXJzZWRKU09OLmZlZWQuZW50cnkuZm9yRWFjaCgoY2VydCkgPT5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAvLyBVc2UgeDUwOS5qcyB0byBwYXJzZSB0aGUgcmF3IGNlcnQgc3RyaW5nIGludG8gY29uc2lzdGVudCBKU09OXG4gICAgICAgICAgICAgICAgbGV0IGNlcnREZXRhaWxzSlNPTiA9IGdldENlcnREZXRhaWxzKGNlcnQuc3VtbWFyeSk7XG5cbiAgICAgICAgICAgICAgICBpZihjZXJ0RGV0YWlsc0pTT04gaW5zdGFuY2VvZiBPYmplY3QpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAvLyBJZ25vcmUgY2VydHMgd2hvc2UgdmFsaWRUb1RTIGlzIDwgaWdub3JlQ2VydHNWYWxpZFRvQmVmb3JlVFNcbiAgICAgICAgICAgICAgICAgICAgaWYoY2VydERldGFpbHNKU09OLnZhbGlkVG9UUyA+PSBpZ25vcmVDZXJ0c1ZhbGlkVG9CZWZvcmVUUylcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgLy8gTk9URTogVGhpcyBtYXkgYmUgdG9vIGNvYXJzZVxuICAgICAgICAgICAgICAgICAgICAgICAgZXJyID0gbnVsbDtcblxuICAgICAgICAgICAgICAgICAgICAgICAgLy8gT25seSBpbmNsdWRlIGNlcnRzIHdoaWNoIGhhdmUgYmVlbiBpc3N1ZWQgc2luY2UgdGhlIGxhc3QgcnVuLCB1bmxlc3MgdGhlIHVzZXIgaGFzIG9wdGVkIHRvIHJldHVybiBhbGwgYnkgc2V0dGluZyBpZ25vcmVDZXJ0c1ZhbGlkRnJvbUJlZm9yZVRTIHRvIChleGFjdGx5KSAwXG4gICAgICAgICAgICAgICAgICAgICAgICBpZihjZXJ0RGV0YWlsc0pTT04udmFsaWRGcm9tVFMgPj0gaWdub3JlQ2VydHNWYWxpZEZyb21CZWZvcmVUUyB8fCBpZ25vcmVDZXJ0c1ZhbGlkRnJvbUJlZm9yZVRTID09PSAwKVxuICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIC8vIEFsbCBjZXJ0c1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNlcnRzRGF0YS5hbGxDZXJ0cy5lbnRyaWVzLnB1c2goY2VydERldGFpbHNKU09OKTtcblxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIC8vIENlcnRzIHdpdGggYW4gXCJ1bmV4cGVjdGVkXCIgQ0FcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBsZXQgZXhwZWN0ZWRDQU1hdGNoID0gZmFsc2U7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYoT2JqZWN0LmtleXMoY2VydERldGFpbHNKU09OLmlzc3VlcikubGVuZ3RoID4gMClcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGV4cGVjdGVkQ0FzLmZvckVhY2goKEVDQSkgPT5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYoY2VydERldGFpbHNKU09OLmlzc3Vlci5jb21tb25OYW1lLm1hdGNoKEVDQSkpXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZXhwZWN0ZWRDQU1hdGNoID0gdHJ1ZTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYoZXhwZWN0ZWRDQU1hdGNoID09PSBmYWxzZSlcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNlcnRzRGF0YS51bmV4cGVjdGVkQ0EuZW50cmllcy5wdXNoKGNlcnREZXRhaWxzSlNPTik7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgLy8gQWxsIGNlcnRzLCBncm91cGVkIGJ5IENBXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYoY2VydHNEYXRhLmJ5Q0EuZW50cmllc1tjZXJ0RGV0YWlsc0pTT04uaXNzdWVyLmNvbW1vbk5hbWVdID09PSB1bmRlZmluZWQpXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjZXJ0c0RhdGEuYnlDQS5lbnRyaWVzW2NlcnREZXRhaWxzSlNPTi5pc3N1ZXIuY29tbW9uTmFtZV0gPSBbXTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBjZXJ0c0RhdGEuYnlDQS5lbnRyaWVzW2NlcnREZXRhaWxzSlNPTi5pc3N1ZXIuY29tbW9uTmFtZV0ucHVzaChjZXJ0RGV0YWlsc0pTT04pO1xuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGVyciA9IG5ldyBUeXBlRXJyb3IoXCJKU09OIGlzIG1hbGZvcm1lZCwgcmVqZWN0aW5nXCIpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9XG4gICAgfVxuXG4gICAgLy8gQ291bnRzICh0b3RhbHMpXG4gICAgY2VydHNEYXRhLmFsbENlcnRzLmNvdW50ID0gY2VydHNEYXRhLmFsbENlcnRzLmVudHJpZXMubGVuZ3RoO1xuICAgIGNlcnRzRGF0YS51bmV4cGVjdGVkQ0EuY291bnQgPSBjZXJ0c0RhdGEudW5leHBlY3RlZENBLmVudHJpZXMubGVuZ3RoO1xuICAgIGNlcnRzRGF0YS5ieUNBLmNvdW50ID0gT2JqZWN0LmtleXMoY2VydHNEYXRhLmJ5Q0EuZW50cmllcykubGVuZ3RoO1xuXG4gICAgaWYoZXJyICE9PSBudWxsKVxuICAgIHtcbiAgICAgICAgY2VydHNEYXRhID0gbnVsbDtcbiAgICB9XG5cbiAgICByZXR1cm4gY2FsbGJhY2soZXJyLCBjZXJ0c0RhdGEpO1xufVxuXG5cbmZ1bmN0aW9uIGNvbnZlcnRYTUxUb0pTT04oWE1MOiBzdHJpbmcsIGNhbGxiYWNrOiBGdW5jdGlvbilcbntcbiAgICBsZXQgZXJyID0gbnVsbDtcbiAgICBsZXQgcGFyc2VkSlNPTiA9IG51bGw7XG5cbiAgICAvLyBXZSB0cnkvY2F0Y2ggc28gdGhhdCB0aGUgdG9Kc29uIGxpYiBmbiBjYW4gdGhyb3cgaWYgaXQgbmVlZCB0byB3aXRob3V0IHVzIHRocm93aW5nXG4gICAgdHJ5XG4gICAge1xuICAgICAgICAvLyBOT1RFOiB0b0pzb24gaXMgYSAzcmQgcGFydHkgZGVwICh4bWwyanNvbilcbiAgICAgICAgbGV0IHJhd0pTT04gPSB0b0pzb24oWE1MKTtcblxuICAgICAgICAvLyBTb21ld2hhdCBvZGRseSwgdG9Kc29uIHJldHVybnMgYSBzdHJpbmdpZmllZCBKU09OIG9iamVjdFxuICAgICAgICBwYXJzZWRKU09OID0gSlNPTi5wYXJzZShyYXdKU09OKTtcblxuICAgICAgICBpZihPYmplY3Qua2V5cyhwYXJzZWRKU09OKS5sZW5ndGggPT09IDApXG4gICAgICAgIHtcbiAgICAgICAgICAgIGVyciA9IG5ldyBUeXBlRXJyb3IoXCJBcmd1bWVudCAnWE1MJyByZXN1bHRlZCBpbiBubyBKU09OIG91dHB1dCwgaXQncyBwcm9iYWJseSBub3QgWE1MXCIpO1xuICAgICAgICAgICAgcGFyc2VkSlNPTiA9IG51bGw7XG4gICAgICAgIH1cbiAgICB9XG4gICAgY2F0Y2ggKGUpXG4gICAge1xuICAgICAgICBlcnIgPSBlO1xuICAgIH1cblxuXG4gICAgcmV0dXJuIGNhbGxiYWNrKGVyciwgcGFyc2VkSlNPTik7XG59XG5cblxuZnVuY3Rpb24gZ2V0UlNTWE1MKGRvbWFpbk5hbWVQYXR0ZXJuOiBzdHJpbmcsIGNhbGxiYWNrOiBGdW5jdGlvbikgLy8gZXNsaW50LWRpc2FibGUtbGluZSBjb25zaXN0ZW50LXJldHVyblxue1xuICAgIGlmKGRvbWFpbk5hbWVQYXR0ZXJuLmxlbmd0aCA+IDApXG4gICAge1xuICAgICAgICBsZXQgeG1sID0gXCJcIjtcblxuICAgICAgICAvLyBOT1RFOiBXZSdyZSBkb2luZyBhIHBsYWluIChub3QgaWYtbW9kaWZpZWQtc2luY2UpIEdFVCBvbiB0aGUgVVJMIGFuZCBhcmUgTk9UIHVzaW5nIHRoZSBidWlsdC1pbiBcImlnbm9yZSBleHBpcmVkIGNlcnRzXCIgYXMgd2UgZG8gdGhhdCBwcm9ncmFtbWF0aXZhbGx5IHZpYSBpZ25vcmVDZXJ0c1ZhbGlkVG9CZWZvcmVUU1xuICAgICAgICBnZXQoXCJodHRwczovL2NydC5zaC9hdG9tP2lkZW50aXR5PVwiICsgZG9tYWluTmFtZVBhdHRlcm4sIChyZXNwb25zZSkgPT5cbiAgICAgICAge1xuICAgICAgICAgICAgcmVzcG9uc2Uub24oXCJkYXRhXCIsIChkKSA9PlxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHhtbCArPSBkLnRvU3RyaW5nKFwidXRmOFwiKTtcbiAgICAgICAgICAgIH0pO1xuXG4gICAgICAgICAgICByZXNwb25zZS5vbihcImVuZFwiLCAoZSkgPT5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBsZXQgZXJyID0gZTtcbiAgICAgICAgICAgICAgICBpZihlID09PSB1bmRlZmluZWQpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBlcnIgPSBudWxsO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlIC8vIGlmIHRoZXJlJ3MgYmVlbiBhbiBlcnJvciwgd2Ugd2FudCB0byBudWxsaWZ5IHhtbFxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgeG1sID0gbnVsbDtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICByZXR1cm4gY2FsbGJhY2soZXJyLCB4bWwpO1xuICAgICAgICAgICAgfSk7XG4gICAgICAgIH0pO1xuICAgIH1cbiAgICBlbHNlXG4gICAge1xuICAgICAgICBsZXQgZXJyID0gbmV3IFR5cGVFcnJvcihcIkFyZ3VtZW50ICdkb21haW5OYW1lUGF0dGVybicgbXVzdCBub3QgYmUgZW1wdHlcIik7XG4gICAgICAgIHJldHVybiBjYWxsYmFjayhlcnIsIG51bGwpO1xuICAgIH1cbn1cblxuXG4vLyBNYXliZSB0aGlzIHNob3VsZCBiZSBhbiBvcHRpb24gb2JqPyBmb3IgYXQgbGVhc3QgZS5nLiBjb25maWctdHlwZSBvcHRpb25zXG5mdW5jdGlvbiBjaGVja0NUTG9ncyhkb21haW5OYW1lUGF0dGVybnM6IEFycmF5LCBpZ25vcmVDZXJ0c1ZhbGlkRnJvbUJlZm9yZVRTOiBudW1iZXIgPSBkZWZhdWx0cy5pZ25vcmVDZXJ0c1ZhbGlkRnJvbUJlZm9yZVRTLCBpZ25vcmVDZXJ0c1ZhbGlkVG9CZWZvcmVUUzogbnVtYmVyID0gZGVmYXVsdHMuaWdub3JlQ2VydHNWYWxpZFRvQmVmb3JlVFMsIGV4cGVjdGVkQ0FzOiBBcnJheSA9IGRlZmF1bHRzLmV4cGVjdGVkQ0FzLCBjYWxsYmFjazogRnVuY3Rpb24pXG57XG4gICAgY29uc3QgdG90YWxOdW1Eb21haW5OYW1lUGF0dGVybnMgPSBkb21haW5OYW1lUGF0dGVybnMubGVuZ3RoO1xuICAgIGxldCB0b3RhbE51bURvbWFpbk5hbWVQYXR0ZXJuc0NvbXBsZXRlZCA9IDA7XG5cbiAgICBkb21haW5OYW1lUGF0dGVybnMuZm9yRWFjaCgoZG9tYWluTmFtZVBhdHRlcm4pID0+XG4gICAge1xuICAgICAgICAvLyBIVFRQMi1jYXBhYmxlIEdFVCBvZiB0aGUgc3BlY2lmaWMgWE1MIGZlZWQgZm9yIHRoZSByZWxldmFudCBkb21haW4gbmFtZSBwYXR0ZXJuIChlLmcuICUuYmJjLmNvLnVrIC0gd2hlcmUgJSBpcyBhIHdpbGRjYXJkKVxuICAgICAgICBnZXRSU1NYTUwoZG9tYWluTmFtZVBhdHRlcm4sIChSU1NFcnJvciwgUlNTWE1MKSA9PiAvLyBlc2xpbnQtZGlzYWJsZS1saW5lIGNvbnNpc3RlbnQtcmV0dXJuXG4gICAgICAgIHtcbiAgICAgICAgICAgIGlmKFJTU0Vycm9yKVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHJldHVybiBjYWxsYmFjayhSU1NFcnJvciwgbnVsbCk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIC8vIFJhdyBjb252ZXJzaW9uIGZyb20gWE1MIHRvIEpTT05cbiAgICAgICAgICAgIGNvbnZlcnRYTUxUb0pTT04oUlNTWE1MLCAoY29udmVydEVyciwgUlNTSlNPTikgPT4gLy8gZXNsaW50LWRpc2FibGUtbGluZSBjb25zaXN0ZW50LXJldHVyblxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmKGNvbnZlcnRFcnIpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gY2FsbGJhY2soY29udmVydEVyciwgbnVsbCk7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gRG93bmxvYWRpbmcgb2YgUlNTIGZlZWQgZnJvbSBjcnQuc2ggd2l0aCBmaWx0ZXJpbmcgYW5kIHBhcnNpbmdcbiAgICAgICAgICAgICAgICBnZXRDZXJ0c0RhdGEoUlNTSlNPTiwgaWdub3JlQ2VydHNWYWxpZEZyb21CZWZvcmVUUywgaWdub3JlQ2VydHNWYWxpZFRvQmVmb3JlVFMsIGV4cGVjdGVkQ0FzLCAoZ2V0Q2VydHNEYXRhRXJyLCBjZXJ0c0RhdGEpID0+IC8vIGVzbGludC1kaXNhYmxlLWxpbmUgY29uc2lzdGVudC1yZXR1cm5cbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGlmKGdldENlcnRzRGF0YUVycilcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGNhbGxiYWNrKGdldENlcnRzRGF0YUVyciwgbnVsbCk7XG4gICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICAvLyBUcmFjayBob3cgbWFueSBvZiB0aGUgY29uZmlndXJlZCBkb21haW5OYW1lUGF0dGVybnMgd2UndmUgY29tcGxldGVkIGFuZC4uLlxuICAgICAgICAgICAgICAgICAgICB0b3RhbE51bURvbWFpbk5hbWVQYXR0ZXJuc0NvbXBsZXRlZCsrO1xuXG4gICAgICAgICAgICAgICAgICAgIC8vIC4uLmV4aXQgd2hlbiBhbGwgZG9tYWluTmFtZVBhdHRlcm5zIGFyZSBjb21wbGV0ZSAoYmVjYXVzZSB0aGlzIGlzIGFzeW5jKVxuICAgICAgICAgICAgICAgICAgICBpZih0b3RhbE51bURvbWFpbk5hbWVQYXR0ZXJuc0NvbXBsZXRlZCA+PSB0b3RhbE51bURvbWFpbk5hbWVQYXR0ZXJucylcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGNhbGxiYWNrKG51bGwsIGNlcnRzRGF0YSk7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9KTtcbiAgICB9KTtcbn1cblxuLy8gV2UgKnNob3VsZCogb25seSBuZWVkIHRvIGV4cG9ydCB0aGUgdXNlci1mYWNpbmcgZnVuY3Rpb25cbm1vZHVsZS5leHBvcnRzID1cbntcbiAgICBnZXRDZXJ0RGV0YWlsczogZ2V0Q2VydERldGFpbHMsXG4gICAgZ2V0Q2VydHNEYXRhOiBnZXRDZXJ0c0RhdGEsXG4gICAgY29udmVydFhNTFRvSlNPTjogY29udmVydFhNTFRvSlNPTixcbiAgICBnZXRSU1NYTUw6IGdldFJTU1hNTCxcbiAgICBjaGVja0NUTG9nczogY2hlY2tDVExvZ3Ncbn07XG4iXX0=