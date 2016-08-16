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
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIi4uLy4uL3NyYy9saWIvdGxzLWNlcnRpZmljYXRlLXRyYW5zcGFyZW5jeS1sb2ctY2hlY2tlci1saWIuanMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6IkFBQUE7O0FBRUE7Ozs7QUFHQTs7O0FBRkE7Ozs7QUFHQTs7OztBQUVBO0FBQ0EsSUFBTSxRQUFRLFNBQVMsSUFBSSxJQUFKLEdBQVcsT0FBWCxLQUF1QixJQUFoQyxFQUFzQyxFQUF0QyxDQUFkLEMsQ0FBeUQ7QUFDekQsSUFBTSxXQUNOO0FBQ0ksa0NBQThCLFFBQVEsS0FEMUMsRUFDaUQ7QUFDN0MsZ0NBQTRCLEtBRmhDO0FBR0ksaUJBQWEsRUFIakIsQ0FHb0I7QUFIcEIsQ0FEQTs7QUFRQTtBQUNBLFNBQVMsY0FBVCxDQUF3QixjQUF4QixFQUNBO0FBQUEsVUFEd0IsY0FDeEIsWUFEd0MsTUFDeEM7QUFBQSxnSUFEd0IsY0FDeEI7QUFBQTs7QUFDSSxRQUFJLE1BQU0sSUFBVjs7QUFFQSxRQUFJLGNBQWMsZUFBZSxJQUFmLEVBQXFCLEtBQXJCLENBQTJCLDhEQUEzQixDQUFsQjs7QUFFQSxRQUFHLGdCQUFnQixJQUFuQixFQUNBO0FBQ0ksWUFBSSxXQUFXLFlBQVksQ0FBWixFQUFlLE9BQWYsQ0FBdUIsT0FBdkIsRUFBZ0MsYUFBRyxHQUFuQyxDQUFmOztBQUVBLFlBQUksaUJBQWlCLG1CQUFVLFFBQVYsQ0FBckI7O0FBRUEsWUFBSSxXQUNKO0FBQ0ksb0JBQVEsZUFBZSxNQUFmLElBQXlCLElBRHJDO0FBRUkscUJBQVMsZUFBZSxPQUFmLElBQTBCLEVBRnZDLEVBRTJDO0FBQ3ZDLG9CQUFRLGVBQWUsTUFBZixJQUF5QixFQUhyQyxFQUd5QztBQUNyQyx1QkFBVyxlQUFlLFNBQWYsSUFBNEIsSUFKM0M7QUFLSSx5QkFBYSxDQUxqQixFQUtvQjtBQUNoQixxQkFBUyxlQUFlLFFBQWYsSUFBMkIsSUFOeEM7QUFPSSx1QkFBVyxDQVBmLEVBT2tCO0FBQ2QsMkJBQWUsQ0FSbkIsRUFRc0I7QUFDbEIs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O0FBRUQ7QUFDQSxPQUFPLE9BQVAsR0FBaUIsV0FBakIiLCJmaWxlIjoidGxzLWNlcnRpZmljYXRlLXRyYW5zcGFyZW5jeS1sb2ctY2hlY2tlci1saWIuanMiLCJzb3VyY2VzQ29udGVudCI6WyJcInVzZSBzdHJpY3RcIjtcblxuLy8gQ29yZSBkZXBzXG5pbXBvcnQgT1MgZnJvbSBcIm9zXCI7XG5cbi8vIDNyZCBwYXJ0eSBkZXBzXG5pbXBvcnQge3BhcnNlQ2VydH0gZnJvbSBcIng1MDkuanNcIjtcblxuLy8gRGVmYXVsdHMgKHVzZWQgaW4gZnVuY3Rpb24gZGVmaW5pdGlvbnMpXG5jb25zdCBub3dUUyA9IHBhcnNlSW50KG5ldyBEYXRlKCkuZ2V0VGltZSgpIC8gMTAwMCwgMTApOyAvLyBOT1RFOiBKUyB0aW1lc3RhbXBzIGFyZSBpbiBtc2VjXG5jb25zdCBkZWZhdWx0cyA9XG57XG4gICAgaWdub3JlQ2VydHNWYWxpZEZyb21CZWZvcmVUUzogbm93VFMgLSA4NjQwMCwgLy8gMSBkYXkgYWdvXG4gICAgaWdub3JlQ2VydHNWYWxpZFRvQmVmb3JlVFM6IG5vd1RTLFxuICAgIGV4cGVjdGVkQ0FzOiBbXSAvLyBEZWZhdWx0IGlzIGV4cGVjdCBub25lXG59O1xuXG5cbi8vIE5PVEU6IFRoaXMgaXMgc3luYyBmb3IgdGhlIG1vbWVudCB3aGljaCBpcyBwcm9iYWJseSBhIGJhZCBpZGVhIC0gbWFraW5nIGFzeW5jIHdpbGwgbmVlZCB3b3JrIG9uIGdldENlcnRzRGF0YSgpIChiZWxvdylcbmZ1bmN0aW9uIGdldENlcnREZXRhaWxzKHJhd0NlcnRTdW1tYXJ5OiBPYmplY3QpXG57XG4gICAgbGV0IHJldCA9IG51bGw7XG5cbiAgICBsZXQgcmF3Q2VydFRleHQgPSByYXdDZXJ0U3VtbWFyeVtcIiR0XCJdLm1hdGNoKC8uKigtLS0tLUJFR0lOIENFUlRJRklDQVRFLS0tLS0uKi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0pLiovKTtcblxuICAgIGlmKHJhd0NlcnRUZXh0ICE9PSBudWxsKVxuICAgIHtcbiAgICAgICAgbGV0IGNlcnRUZXh0ID0gcmF3Q2VydFRleHRbMV0ucmVwbGFjZSgvPGJyPi9nLCBPUy5FT0wpO1xuXG4gICAgICAgIGxldCBwYXJzZWRDZXJ0SlNPTiA9IHBhcnNlQ2VydChjZXJ0VGV4dCk7XG5cbiAgICAgICAgbGV0IGNlcnRKU09OID1cbiAgICAgICAge1xuICAgICAgICAgICAgc2VyaWFsOiBwYXJzZWRDZXJ0SlNPTi5zZXJpYWwgfHwgbnVsbCxcbiAgICAgICAgICAgIHN1YmplY3Q6IHBhcnNlZENlcnRKU09OLnN1YmplY3QgfHwge30sIC8vIGVzbGludC1kaXNhYmxlLWxpbmUgb2JqZWN0LWN1cmx5LW5ld2xpbmVcbiAgICAgICAgICAgIGlzc3VlcjogcGFyc2VkQ2VydEpTT04uaXNzdWVyIHx8IHt9LCAvLyBlc2xpbnQtZGlzYWJsZS1saW5lIG9iamVjdC1jdXJseS1uZXdsaW5lXG4gICAgICAgICAgICB2YWxpZEZyb206IHBhcnNlZENlcnRKU09OLm5vdEJlZm9yZSB8fCBudWxsLFxuICAgICAgICAgICAgdmFsaWRGcm9tVFM6IDAsIC8vIFdpbGwgYmUgdXBkYXRlZCBiZWxvd1xuICAgICAgICAgICAgdmFsaWRUbzogcGFyc2VkQ2VydEpTT04ubm90QWZ0ZXIgfHwgbnVsbCxcbiAgICAgICAgICAgIHZhbGlkVG9UUzogMCwgLy8gV2lsbCBiZSB1cGRhdGVkIGJlbG93XG4gICAgICAgICAgICBkYXlzUmVtYWluaW5nOiAwLCAvLyBXaWxsIGJlIHVwZGF0ZWQgYmVsb3dcbiAgICAgICAgICAgIFNBTjogcGFyc2VkQ2VydEpTT04uYWx0TmFtZXMgfHwgW11cbiAgICAgICAgfTtcblxuICAgICAgICB0cnlcbiAgICAgICAge1xuICAgICAgICAgICAgY2VydEpTT04udmFsaWRGcm9tVFMgPSBwYXJzZUludChuZXcgRGF0ZShjZXJ0SlNPTi52YWxpZEZyb20pLmdldFRpbWUoKSAvIDEwMDAsIDEwKTsgLy8gbmVlZCB0byByZW1vdmUgbGFzdCAzIGNoYXJzIGFzIEpTIHVzZSBNU2VjIFRTJ3NcbiAgICAgICAgfVxuICAgICAgICBjYXRjaChlKVxuICAgICAgICB7XG4gICAgICAgICAgICBjZXJ0SlNPTi52YWxpZEZyb21UUyA9IDA7IC8vIElzIHRoZXJlIGFueXRoaW5nIG1vcmUgc2Vuc2libGUgd2hpY2ggY291bGQgYmUgZG9uZT9cbiAgICAgICAgfVxuXG4gICAgICAgIHRyeVxuICAgICAgICB7XG4gICAgICAgICAgICBjZXJ0SlNPTi52YWxpZFRvVFMgPSBwYXJzZUludChuZXcgRGF0ZShjZXJ0SlNPTi52YWxpZFRvKS5nZXRUaW1lKCkgLyAxMDAwLCAxMCk7IC8vIG5lZWQgdG8gcmVtb3ZlIGxhc3QgMyBjaGFycyBhcyBKUyB1c2UgTVNlYyBUUydzXG4gICAgICAgIH1cbiAgICAgICAgY2F0Y2goZSlcbiAgICAgICAge1xuICAgICAgICAgICAgY2VydEpTT04udmFsaWRGcm9tVFMgPSAwOyAvLyBJcyB0aGVyZSBhbnl0aGluZyBtb3JlIHNlbnNpYmxlIHdoaWNoIGNvdWxkIGJlIGRvbmU/XG4gICAgICAgIH1cblxuICAgICAgICBjZXJ0SlNPTi5kYXlzUmVtYWluaW5nID0gTWF0aC5mbG9vcigoY2VydEpTT04udmFsaWRUb1RTIC0gbm93VFMpIC8gODY0MDApO1xuXG4gICAgICAgIHJldCA9IGNlcnRKU09OO1xuICAgIH1cblxuICAgIHJldHVybiByZXQ7IC8vIG51bGwgaWYgZXJyb3IsIG9iamVjdCBvdGhlcndpc2Vcbn1cblxuZnVuY3Rpb24gZ2V0Q2VydHNEYXRhKHBhcnNlZEpTT046IE9iamVjdCwgaWdub3JlQ2VydHNWYWxpZEZyb21CZWZvcmVUUzogbnVtYmVyID0gZGVmYXVsdHMuaWdub3JlQ2VydHNWYWxpZEZyb21CZWZvcmVUUywgaWdub3JlQ2VydHNWYWxpZFRvQmVmb3JlVFM6IG51bWJlciA9IGRlZmF1bHRzLmlnbm9yZUNlcnRzVmFsaWRUb0JlZm9yZVRTLCBleHBlY3RlZENBczogQXJyYXkgPSBkZWZhdWx0cy5leHBlY3RlZENBcywgY2FsbGJhY2s6IEZ1bmN0aW9uKVxue1xuICAgIC8qIE5PVEU6IEpTT04gc3RydWN0dXJlIG9mIHBhcnNlZEpTT04gaXM6XG4gICAge1xuICAgICAgICBmZWVkOlxuICAgICAgICB7XG4gICAgICAgICAgICB4bWxuczogJ2h0dHA6Ly93d3cudzMub3JnLzIwMDUvQXRvbScsXG4gICAgICAgICAgICAneG1sOmxhbmcnOiAnZW4nLFxuICAgICAgICAgICAgYXV0aG9yOiB7IG5hbWU6ICdjcnQuc2gnLCB1cmk6ICdodHRwczovL2NydC5zaC8nIH0sXG4gICAgICAgICAgICBpY29uOiAnaHR0cHM6Ly9jcnQuc2gvZmF2aWNvbi5pY28nLFxuICAgICAgICAgICAgaWQ6ICdodHRwczovL2NydC5zaC8/aWRlbnRpdHk9JTI1LmJiYy5jb20mZXhjbHVkZT1leHBpcmVkJyxcbiAgICAgICAgICAgIGxpbms6IFsgW09iamVjdF0sIFtPYmplY3RdIF0sXG4gICAgICAgICAgICB0aXRsZTogJ2lkZW50aXR5PSUuYmJjLmNvbTsgZXhjbHVkZT1leHBpcmVkJyxcbiAgICAgICAgICAgIHVwZGF0ZWQ6ICcyMDE2LTA4LTA0VDExOjA2OjQ3WicsXG4gICAgICAgICAgICBlbnRyeTpcbiAgICAgICAgICAgIFtcbiAgICAgICAgICAgICAgICBbT2JqZWN0XSxcbiAgICAgICAgICAgICAgICBbT2JqZWN0XSxcbiAgICAgICAgICAgICAgICAuLi5cbiAgICAgICAgICAgIF1cbiAgICAgICAgfVxuICAgIH1cbiAgICAqL1xuXG4gICAgbGV0IGVyciA9IG5ldyBFcnJvcihcIk1hbGZvcm1lZCBKU09OLCByZWplY3RpbmdcIik7XG4gICAgbGV0IGNlcnRzRGF0YSA9XG4gICAge1xuICAgICAgICBhbGxDZXJ0czpcbiAgICAgICAge1xuICAgICAgICAgICAgY291bnQ6IDAsXG4gICAgICAgICAgICBlbnRyaWVzOiBbXVxuICAgICAgICB9LFxuICAgICAgICB1bmV4cGVjdGVkQ0E6XG4gICAgICAgIHtcbiAgICAgICAgICAgIGNvdW50OiAwLFxuICAgICAgICAgICAgZW50cmllczogW11cbiAgICAgICAgfSxcbiAgICAgICAgYnlDQTpcbiAgICAgICAge1xuICAgICAgICAgICAgY291bnQ6IDAsXG4gICAgICAgICAgICBlbnRyaWVzOlxuICAgICAgICAgICAge1xuXG4gICAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICB9O1xuXG4gICAgaWYocGFyc2VkSlNPTi5mZWVkKVxuICAgIHtcbiAgICAgICAgaWYocGFyc2VkSlNPTi5mZWVkLmVudHJ5IGluc3RhbmNlb2YgQXJyYXkpXG4gICAgICAgIHtcbiAgICAgICAgICAgIHBhcnNlZEpTT04uZmVlZC5lbnRyeS5mb3JFYWNoKChjZXJ0KSA9PlxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIC8vIFVzZSB4NTA5LmpzIHRvIHBhcnNlIHRoZSByYXcgY2VydCBzdHJpbmcgaW50byBjb25zaXN0ZW50IEpTT05cbiAgICAgICAgICAgICAgICBsZXQgY2VydERldGFpbHNKU09OID0gZ2V0Q2VydERldGFpbHMoY2VydC5zdW1tYXJ5KTtcblxuICAgICAgICAgICAgICAgIGlmKGNlcnREZXRhaWxzSlNPTiAhPT0gbnVsbClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIC8vIElnbm9yZSBjZXJ0cyB3aG9zZSB2YWxpZFRvVFMgaXMgPCBpZ25vcmVDZXJ0c1ZhbGlkVG9CZWZvcmVUU1xuICAgICAgICAgICAgICAgICAgICBpZihjZXJ0RGV0YWlsc0pTT04udmFsaWRUb1RTID49IGlnbm9yZUNlcnRzVmFsaWRUb0JlZm9yZVRTKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAvLyBOT1RFOiBUaGlzIG1heSBiZSB0b28gY29hcnNlXG4gICAgICAgICAgICAgICAgICAgICAgICBlcnIgPSBudWxsO1xuXG4gICAgICAgICAgICAgICAgICAgICAgICAvLyBPbmx5IGluY2x1ZGUgY2VydHMgd2hpY2ggaGF2ZSBiZWVuIGlzc3VlZCBzaW5jZSB0aGUgbGFzdCBydW4sIHVubGVzcyB0aGUgdXNlciBoYXMgb3B0ZWQgdG8gcmV0dXJuIGFsbCBieSBzZXR0aW5nIGlnbm9yZUNlcnRzVmFsaWRGcm9tQmVmb3JlVFMgdG8gKGV4YWN0bHkpIDBcbiAgICAgICAgICAgICAgICAgICAgICAgIGlmKGNlcnREZXRhaWxzSlNPTi52YWxpZEZyb21UUyA+PSBpZ25vcmVDZXJ0c1ZhbGlkRnJvbUJlZm9yZVRTIHx8IGlnbm9yZUNlcnRzVmFsaWRGcm9tQmVmb3JlVFMgPT09IDApXG4gICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgLy8gQWxsIGNlcnRzXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgY2VydHNEYXRhLmFsbENlcnRzLmVudHJpZXMucHVzaChjZXJ0RGV0YWlsc0pTT04pO1xuXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgLy8gQ2VydHMgd2l0aCBhbiBcInVuZXhwZWN0ZWRcIiBDQVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGxldCBleHBlY3RlZENBTWF0Y2ggPSBmYWxzZTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZihPYmplY3Qua2V5cyhjZXJ0RGV0YWlsc0pTT04uaXNzdWVyKS5sZW5ndGggPiAwKVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZXhwZWN0ZWRDQXMuZm9yRWFjaCgoRUNBKSA9PlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZihjZXJ0RGV0YWlsc0pTT04uaXNzdWVyLmNvbW1vbk5hbWUubWF0Y2goRUNBKSlcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBleHBlY3RlZENBTWF0Y2ggPSB0cnVlO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZihleHBlY3RlZENBTWF0Y2ggPT09IGZhbHNlKVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY2VydHNEYXRhLnVuZXhwZWN0ZWRDQS5lbnRyaWVzLnB1c2goY2VydERldGFpbHNKU09OKTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAvLyBBbGwgY2VydHMsIGdyb3VwZWQgYnkgQ0FcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZihjZXJ0c0RhdGEuYnlDQS5lbnRyaWVzW2NlcnREZXRhaWxzSlNPTi5pc3N1ZXIuY29tbW9uTmFtZV0gPT09IHVuZGVmaW5lZClcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNlcnRzRGF0YS5ieUNBLmVudHJpZXNbY2VydERldGFpbHNKU09OLmlzc3Vlci5jb21tb25OYW1lXSA9IFtdO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNlcnRzRGF0YS5ieUNBLmVudHJpZXNbY2VydERldGFpbHNKU09OLmlzc3Vlci5jb21tb25OYW1lXS5wdXNoKGNlcnREZXRhaWxzSlNPTik7XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfVxuICAgIH1cblxuICAgIC8vIENvdW50cyAodG90YWxzKVxuICAgIGNlcnRzRGF0YS5hbGxDZXJ0cy5jb3VudCA9IGNlcnRzRGF0YS5hbGxDZXJ0cy5lbnRyaWVzLmxlbmd0aDtcbiAgICBjZXJ0c0RhdGEudW5leHBlY3RlZENBLmNvdW50ID0gY2VydHNEYXRhLnVuZXhwZWN0ZWRDQS5lbnRyaWVzLmxlbmd0aDtcbiAgICBjZXJ0c0RhdGEuYnlDQS5jb3VudCA9IE9iamVjdC5rZXlzKGNlcnRzRGF0YS5ieUNBLmVudHJpZXMpLmxlbmd0aDtcblxuICAgIHJldHVybiBjYWxsYmFjayhlcnIsIGNlcnRzRGF0YSk7XG59XG5cblxuZnVuY3Rpb24gY29udmVydFhNTFRvSlNPTih0b0pzb246IEZ1bmN0aW9uLCBYTUw6IHN0cmluZywgY2FsbGJhY2s6IEZ1bmN0aW9uKVxue1xuICAgIGxldCBlcnIgPSBudWxsO1xuICAgIGxldCBwYXJzZWRKU09OID0gbnVsbDtcblxuICAgIHRyeVxuICAgIHtcbiAgICAgICAgLy8gTk9URTogdG9Kc29uIGlzIGEgM3JkIHBhcnR5IGRlcCAoeG1sMmpzb24pXG4gICAgICAgIGxldCByYXdKU09OID0gdG9Kc29uKFhNTCk7XG5cbiAgICAgICAgLy8gU29tZXdoYXQgb2RkbHksIHRvSnNvbiByZXR1cm5zIGEgc3RyaW5naWZpZWQgSk9TTiBvYmplY3RcbiAgICAgICAgcGFyc2VkSlNPTiA9IEpTT04ucGFyc2UocmF3SlNPTik7XG4gICAgfVxuICAgIGNhdGNoIChlKVxuICAgIHtcbiAgICAgICAgZXJyID0gZTtcbiAgICB9XG5cbiAgICByZXR1cm4gY2FsbGJhY2soZXJyLCBwYXJzZWRKU09OKTtcbn1cblxuXG5mdW5jdGlvbiBnZXRSU1NYTUwoZG9tYWluTmFtZVBhdHRlcm46IHN0cmluZywgZ2V0OiBPYmplY3QsIGNhbGxiYWNrOiBGdW5jdGlvbilcbntcbiAgICBsZXQgeG1sID0gXCJcIjtcblxuICAgIC8vIE5PVEU6IFdlJ3JlIGRvaW5nIGEgcGxhaW4gKG5vdCBpZi1tb2RpZmllZC1zaW5jZSkgR0VUIG9uIHRoZSBVUkwgYW5kIGFyZSBOT1QgdXNpbmcgdGhlIGJ1aWx0LWluIFwiaWdub3JlIGV4cGlyZWQgY2VydHNcIiBhcyB3ZSBkbyB0aGF0IHByb2dyYW1tYXRpdmFsbHkgdmlhIGlnbm9yZUNlcnRzVmFsaWRUb0JlZm9yZVRTXG4gICAgZ2V0KFwiaHR0cHM6Ly9jcnQuc2gvYXRvbT9pZGVudGl0eT1cIiArIGRvbWFpbk5hbWVQYXR0ZXJuLCAocmVzcG9uc2UpID0+XG4gICAge1xuICAgICAgICByZXNwb25zZS5vbihcImRhdGFcIiwgKGQpID0+XG4gICAgICAgIHtcbiAgICAgICAgICAgIHhtbCArPSBkLnRvU3RyaW5nKFwidXRmOFwiKTtcbiAgICAgICAgfSk7XG5cbiAgICAgICAgcmVzcG9uc2Uub24oXCJlbmRcIiwgKGUpID0+XG4gICAgICAgIHtcbiAgICAgICAgICAgIHJldHVybiBjYWxsYmFjayhlLCB4bWwpO1xuICAgICAgICB9KTtcbiAgICB9KTtcbn1cblxuXG4vLyBNYXliZSB0aGlzIHNob3VsZCBiZSBhbiBvcHRpb24gb2JqPyBmb3IgYXQgbGVhc3QgZS5nLiBjb25maWctdHlwZSBvcHRpb25zXG5mdW5jdGlvbiBjaGVja0NUTG9ncyhnZXQ6IE9iamVjdCwgdG9Kc29uOiBGdW5jdGlvbiwgZG9tYWluTmFtZVBhdHRlcm5zOiBBcnJheSwgaWdub3JlQ2VydHNWYWxpZEZyb21CZWZvcmVUUzogbnVtYmVyID0gZGVmYXVsdHMuaWdub3JlQ2VydHNWYWxpZEZyb21CZWZvcmVUUywgaWdub3JlQ2VydHNWYWxpZFRvQmVmb3JlVFM6IG51bWJlciA9IGRlZmF1bHRzLmlnbm9yZUNlcnRzVmFsaWRUb0JlZm9yZVRTLCBleHBlY3RlZENBczogQXJyYXkgPSBkZWZhdWx0cy5leHBlY3RlZENBcywgY2FsbGJhY2s6IEZ1bmN0aW9uKVxue1xuICAgIGNvbnN0IHRvdGFsTnVtRG9tYWluTmFtZVBhdHRlcm5zID0gZG9tYWluTmFtZVBhdHRlcm5zLmxlbmd0aDtcbiAgICBsZXQgdG90YWxOdW1Eb21haW5OYW1lUGF0dGVybnNDb21wbGV0ZWQgPSAwO1xuXG4gICAgZG9tYWluTmFtZVBhdHRlcm5zLmZvckVhY2goKGRvbWFpbk5hbWVQYXR0ZXJuKSA9PlxuICAgIHtcbiAgICAgICAgLy8gSFRUUDItY2FwYWJsZSBHRVQgb2YgdGhlIHNwZWNpZmljIFhNTCBmZWVkIGZvciB0aGUgcmVsZXZhbnQgZG9tYWluIG5hbWUgcGF0dGVybiAoZS5nLiAlLmJiYy5jby51ayAtIHdoZXJlICUgaXMgYSB3aWxkY2FyZClcbiAgICAgICAgZ2V0UlNTWE1MKGRvbWFpbk5hbWVQYXR0ZXJuLCBnZXQsIChSU1NFcnJvciwgUlNTWE1MKSA9PiAvLyBlc2xpbnQtZGlzYWJsZS1saW5lIGNvbnNpc3RlbnQtcmV0dXJuXG4gICAgICAgIHtcbiAgICAgICAgICAgIGlmKFJTU0Vycm9yKVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHJldHVybiBjYWxsYmFjayhSU1NFcnJvciwgbnVsbCk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIC8vIFJhdyBjb252ZXJzaW9uIGZyb20gWE1MIHRvIEpTT05cbiAgICAgICAgICAgIGNvbnZlcnRYTUxUb0pTT04odG9Kc29uLCBSU1NYTUwsIChjb252ZXJ0RXJyLCBSU1NKU09OKSA9PiAvLyBlc2xpbnQtZGlzYWJsZS1saW5lIGNvbnNpc3RlbnQtcmV0dXJuXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYoY29udmVydEVycilcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBjYWxsYmFjayhjb252ZXJ0RXJyLCBudWxsKTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyBEb3dubG9hZGluZyBvZiBSU1MgZmVlZCBmcm9tIGNydC5zaCB3aXRoIGZpbHRlcmluZyBhbmQgcGFyc2luZ1xuICAgICAgICAgICAgICAgIGdldENlcnRzRGF0YShSU1NKU09OLCBpZ25vcmVDZXJ0c1ZhbGlkRnJvbUJlZm9yZVRTLCBpZ25vcmVDZXJ0c1ZhbGlkVG9CZWZvcmVUUywgZXhwZWN0ZWRDQXMsIChnZXRDZXJ0c0RhdGFFcnIsIGNlcnRzRGF0YSkgPT4gLy8gZXNsaW50LWRpc2FibGUtbGluZSBjb25zaXN0ZW50LXJldHVyblxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgaWYoZ2V0Q2VydHNEYXRhRXJyKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gY2FsbGJhY2soZ2V0Q2VydHNEYXRhRXJyLCBudWxsKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgIC8vIFRyYWNrIGhvdyBtYW55IG9mIHRoZSBjb25maWd1cmVkIGRvbWFpbk5hbWVQYXR0ZXJucyB3ZSd2ZSBjb21wbGV0ZWQgYW5kLi4uXG4gICAgICAgICAgICAgICAgICAgIHRvdGFsTnVtRG9tYWluTmFtZVBhdHRlcm5zQ29tcGxldGVkKys7XG5cbiAgICAgICAgICAgICAgICAgICAgLy8gLi4uZXhpdCB3aGVuIGFsbCBkb21haW5OYW1lUGF0dGVybnMgYXJlIGNvbXBsZXRlIChiZWNhdXNlIHRoaXMgaXMgYXN5bmMpXG4gICAgICAgICAgICAgICAgICAgIGlmKHRvdGFsTnVtRG9tYWluTmFtZVBhdHRlcm5zQ29tcGxldGVkID49IHRvdGFsTnVtRG9tYWluTmFtZVBhdHRlcm5zKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gY2FsbGJhY2sobnVsbCwgY2VydHNEYXRhKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgfSk7XG4gICAgICAgIH0pO1xuICAgIH0pO1xufVxuXG4vLyBXZSAqc2hvdWxkKiBvbmx5IG5lZWQgdG8gZXhwb3J0IHRoZSB1c2VyLWZhY2luZyBmdW5jdGlvblxubW9kdWxlLmV4cG9ydHMgPSBjaGVja0NUTG9ncztcbiJdfQ==