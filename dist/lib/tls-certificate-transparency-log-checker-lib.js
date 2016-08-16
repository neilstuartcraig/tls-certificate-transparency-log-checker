"use strict";

// Core deps

var _typeof = typeof Symbol === "function" && typeof Symbol.iterator === "symbol" ? function (obj) { return typeof obj; } : function (obj) { return obj && typeof Symbol === "function" && obj.constructor === Symbol ? "symbol" : typeof obj; };

// 3rd party deps


var _os = require("os");

var _os2 = _interopRequireDefault(_os);

var _x7 = require("x509.js");

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

    var rawCertText = rawCertSummary["$t"].match(/.*(-----BEGIN CERTIFICATE-----.*-----END CERTIFICATE-----).*/);

    if (rawCertText !== null) {
        var certText = rawCertText[1].replace(/<br>/g, _os2.default.EOL);

        var parsedCertJSON = (0, _x7.parseCert)(certText);

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
    }

    return ret; // null if error, object otherwise
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

    var err = new Error("Malformed JSON, rejecting");
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

                if (certDetailsJSON !== null) {
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
                }
            });
        }
    }

    // Counts (totals)
    certsData.allCerts.count = certsData.allCerts.entries.length;
    certsData.unexpectedCA.count = certsData.unexpectedCA.entries.length;
    certsData.byCA.count = Object.keys(certsData.byCA.entries).length;

    return callback(err, certsData);
}

function convertXMLToJSON(toJson, XML, callback) {
    if (!(typeof toJson === 'function')) {
        throw new TypeError("Value of argument \"toJson\" violates contract.\n\nExpected:\nFunction\n\nGot:\n" + _inspect(toJson));
    }

    if (!(typeof XML === 'string')) {
        throw new TypeError("Value of argument \"XML\" violates contract.\n\nExpected:\nstring\n\nGot:\n" + _inspect(XML));
    }

    if (!(typeof callback === 'function')) {
        throw new TypeError("Value of argument \"callback\" violates contract.\n\nExpected:\nFunction\n\nGot:\n" + _inspect(callback));
    }

    var err = null;
    var parsedJSON = null;

    try {
        // NOTE: toJson is a 3rd party dep (xml2json)
        var rawJSON = toJson(XML);

        // Somewhat oddly, toJson returns a stringified JOSN object
        parsedJSON = JSON.parse(rawJSON);
    } catch (e) {
        err = e;
    }

    return callback(err, parsedJSON);
}

function getRSSXML(domainNamePattern, get, callback) {
    if (!(typeof domainNamePattern === 'string')) {
        throw new TypeError("Value of argument \"domainNamePattern\" violates contract.\n\nExpected:\nstring\n\nGot:\n" + _inspect(domainNamePattern));
    }

    if (!(get instanceof Object)) {
        throw new TypeError("Value of argument \"get\" violates contract.\n\nExpected:\nObject\n\nGot:\n" + _inspect(get));
    }

    if (!(typeof callback === 'function')) {
        throw new TypeError("Value of argument \"callback\" violates contract.\n\nExpected:\nFunction\n\nGot:\n" + _inspect(callback));
    }

    var xml = "";

    // NOTE: We're doing a plain (not if-modified-since) GET on the URL and are NOT using the built-in "ignore expired certs" as we do that programmativally via ignoreCertsValidToBeforeTS
    get("https://crt.sh/atom?identity=" + domainNamePattern, function (response) {
        response.on("data", function (d) {
            xml += d.toString("utf8");
        });

        response.on("end", function (e) {
            return callback(e, xml);
        });
    });
}

// Maybe this should be an option obj? for at least e.g. config-type options
function checkCTLogs(get, toJson, domainNamePatterns) {
    var ignoreCertsValidFromBeforeTS = arguments.length <= 3 || arguments[3] === undefined ? defaults.ignoreCertsValidFromBeforeTS : arguments[3];
    var ignoreCertsValidToBeforeTS = arguments.length <= 4 || arguments[4] === undefined ? defaults.ignoreCertsValidToBeforeTS : arguments[4];
    var expectedCAs = arguments.length <= 5 || arguments[5] === undefined ? defaults.expectedCAs : arguments[5];
    var callback = arguments[6];

    if (!(get instanceof Object)) {
        throw new TypeError("Value of argument \"get\" violates contract.\n\nExpected:\nObject\n\nGot:\n" + _inspect(get));
    }

    if (!(typeof toJson === 'function')) {
        throw new TypeError("Value of argument \"toJson\" violates contract.\n\nExpected:\nFunction\n\nGot:\n" + _inspect(toJson));
    }

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
        getRSSXML(domainNamePattern, get, function (RSSError, RSSXML) // eslint-disable-line consistent-return
        {
            if (RSSError) {
                return callback(RSSError, null);
            }

            // Raw conversion from XML to JSON
            convertXMLToJSON(toJson, RSSXML, function (convertErr, RSSJSON) // eslint-disable-line consistent-return
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
module.exports = checkCTLogs;

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
            var _ret = function () {
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

            if ((typeof _ret === "undefined" ? "undefined" : _typeof(_ret)) === "object") return _ret.v;
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
//# sourceMappingURL=/Users/craign04/Documents/BBC/GlobalTrafficMGMT/github/tls-certificate-transparency-log-checker/dist/maps/lib/tls-certificate-transparency-log-checker-lib.js.map