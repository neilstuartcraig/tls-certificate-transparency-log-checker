"use strict";

// Core deps
import OS from "os";

// 3rd party deps

// Defaults (used in function definitions)
const nowTS = new Date().getTime() / 1000; // NOTE: JS timestamps are in msec
const defaults =
{
    ignoreCertsValidFromBeforeTS: nowTS - 86400, // 1 day ago
    ignoreCertsValidToBeforeTS: nowTS,
    expectedCAs: [] // Default is expect none
};

function getCertsData(parsedJSON: Object, ignoreCertsValidFromBeforeTS: number = defaults.checkIntervalSecs, ignoreCertsValidToBeforeTS: number = defaults.ignoreCertsValidToBeforeTS, expectedCAs: Array = defaults.expectedCAs = defaults.expectedCAs, callback: Function)
{
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

    let err = new Error("Malformed JSON, rejecting");
    let certsData =
    {
        certs:
        {
            count: 0,
            entries: []
        },
        unexpectedCA:
        {
            count: 0,
            entries: []
        },
        byCA:
        {
            count: 0,
            entries:
            {

            }
        }
    };

    if(parsedJSON.feed)
    {
        if(parsedJSON.feed.entry instanceof Array)
        {
            parsedJSON.feed.entry.forEach((cert) =>
            {
                // NOTE: Might want to split this out in separate fn's:

                // Extract the info elements from the title, example title format:
                // [Certificate] Issued by GlobalSign Organization Validation CA - SHA256 - G2; Valid from 2015-01-13 to 2017-01-13; Serial number 1121d0ef260d17b3f15bd22f277c980d735c
                let titleComponents = cert.title.split(";");

                // CA should be the 0th element, see above example
                let CAPrefix = "Issued by ";
                let CAPrefixPos = titleComponents[0].indexOf(CAPrefix);
                let CA = CAPrefixPos >= 0 ? titleComponents[0].substr(CAPrefixPos + CAPrefix.length) : null;

                // The valid from/to should be the 1st element, see above example
                let dates = titleComponents[1].match(/Valid from ([0-9]{4}-[0-9]{2}-[0-9]{2}) to ([0-9]{4}-[0-9]{2}-[0-9]{2})/i);

                let validFrom = dates[1] || null;
                let validFromTS = new Date(validFrom + " 00:00:00").getTime() / 1000; // need to remove last 3 chars as JS use MSec TS's

                let validTo = dates[2] || null;
                let validToTS = new Date(validTo + " 23:59:59").getTime() / 1000; // need to remove last 3 chars as JS use MSec TS's

                // Ignore certs whose validToTS is < ignoreCertsValidToBeforeTS
                if(validToTS >= ignoreCertsValidToBeforeTS)
                {
                    let daysRemaining = Math.floor((validToTS - nowTS) / 86400);

                    // Serial number
                    let serialComponents = titleComponents[2].split(" ");
                    let serial = serialComponents[serialComponents.length - 1];


                    // Common name and SANs
                    // $t example format: emp.bbc.com &nbsp; emp.live.bbc.com &nbsp; smp.bbc.com &nbsp; smp.live.bbc.com<br><br><div style=\"font:8pt monospace\">-----BEGIN CERTIFICATE-----<br>MIIF+jCCBOKgAwIBAgISESFlByoLUbb9vwNQTSbGYO02MA0GCSqGSIb3DQEBCwUA<br>MGYxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMTwwOgYD<br>VQQDEzNHbG9iYWxTaWduIE9yZ2FuaXphdGlvbiBWYWxpZGF0aW9uIENBIC0gU0hB<br>MjU2IC0gRzIwHhcNMTUwODEzMTQyNjEyWhcNMTYwODEzMTQyNjEyWjBzMQswCQYD<br>VQQGEwJHQjEPMA0GA1UECBMGTG9uZG9uMQ8wDQYDVQQHEwZMb25kb24xKTAnBgNV<br>BAoTIEJyaXRpc2ggQnJvYWRjYXN0aW5nIENvcnBvcmF0aW9uMRcwFQYDVQQDEw5l<br>bXAuYmJjaS5jby51azCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOgE<br>EzAbdIjKqSAH3A/ZyBfGPDQ76BLWQh9oyo84uZzNtY7JvFGz+bSoEPEc9SHAzs7C<br>shyLREzyYaSnepwyYwwj47fqa2NqBp+RlMFD2ZifxsAyJHl3klIEesgMij42wK9q<br>xnBFWG0CY1rRwdDZtR7K80l8vgeLp2wvqJbU50juesYHTIfB9xuAkkNz0xOkwiid<br>ILBEmY41JnLqKYbC3srtaiXhNlIojZi7kJMemFyg7BumTy6vJsNC/bSPOXiveZrZ<br>y2eQY4N2++5OV7xoVbF8nc95EgDBiSrpKOpbFTKcz5Al3XxJ6u7UVjzuWM97hq8M<br>Ux4ezdYPcyhVeImUmYcCAwEAAaOCApMwggKPMA4GA1UdDwEB/wQEAwIFoDBJBgNV<br>HSAEQjBAMD4GBmeBDAECAjA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3dy5nbG9i<br>YWxzaWduLmNvbS9yZXBvc2l0b3J5LzCB2QYDVR0RBIHRMIHOgg5lbXAuYmJjaS5j<br>by51a4INZW1wLmJiYy5jby51a4ILZW1wLmJiYy5jb22CDnNtcC5iYmNpLmNvLnVr<br>gg1zbXAuYmJjLmNvLnVrggtzbXAuYmJjLmNvbYITZW1wLmxpdmUuYmJjaS5jby51<br>a4ISZW1wLmxpdmUuYmJjLmNvLnVrghBlbXAubGl2ZS5iYmMuY29tghNzbXAubGl2<br>ZS5iYmNpLmNvLnVrghJzbXAubGl2ZS5iYmMuY28udWuCEHNtcC5saXZlLmJiYy5j<br>b20wCQYDVR0TBAIwADAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwSQYD<br>VR0fBEIwQDA+oDygOoY4aHR0cDovL2NybC5nbG9iYWxzaWduLmNvbS9ncy9nc29y<br>Z2FuaXphdGlvbnZhbHNoYTJnMi5jcmwwgaAGCCsGAQUFBwEBBIGTMIGQME0GCCsG<br>AQUFBzAChkFodHRwOi8vc2VjdXJlLmdsb2JhbHNpZ24uY29tL2NhY2VydC9nc29y<br>Z2FuaXphdGlvbnZhbHNoYTJnMnIxLmNydDA/BggrBgEFBQcwAYYzaHR0cDovL29j<br>c3AyLmdsb2JhbHNpZ24uY29tL2dzb3JnYW5pemF0aW9udmFsc2hhMmcyMB0GA1Ud<br>DgQWBBSqjg7j2iVdEE6LFy4Bl82DctMBtTAfBgNVHSMEGDAWgBSW3mHxvRwWKVMc<br>wMx9O4MAQOYafDANBgkqhkiG9w0BAQsFAAOCAQEAE1xfeLbp9xCf8G3kJPXzVZ/l<br>g/iDjAXUDV28Woat/+ZW/UEqtFRI0jL0NViNyTfbIxRy9FO4b62DB2YOzVHOo55r<br>GABnNtkbZVIfiw3ecLo696dr2yg+sfDiubO6ubmZGSVQAmJK/t3DN0Sd8UmE8RgZ<br>RXzNZbtOCq6rZtnLTJq4f/wHp8ikW9rWhBpSvwk4CsKD7g1yliUmzYk7dh7Puwbf<br>9NiDfQ6zEKiFq7HYJBHcN/2xI5W/rdEFz3nJWnXS87y2WiFyR2Qg9uqU8+kehApb<br>-----END CERTIFICATE-----</div>
                    let summaryComponents = cert.summary["$t"].split("<br>");

                    let nameComponents = summaryComponents[0].split("&nbsp;");

                    let commonName = nameComponents.shift().trim();
                    let SAN = nameComponents.map((n) =>
                    {
                        return n.trim();
                    });

                    // Cert
                    // TODO: determine which format the cert is in - doesn't seem to be b64
                    // let certRaw = cert.summary["$t"].match(/.*(-----BEGIN CERTIFICATE-----.*-----END CERTIFICATE-----).*/);
                    // let parsedCert = certRaw[1].replace(/<br>/g, OS.EOL);
                    // let decodedCert = Buffer.from(parsedCert, "ascii").toString("utf8");

                    let data =
                    {
                        commonName: commonName,
                        SAN: SAN,
                        serial: serial,
                        validFrom: validFrom,
                        validFromTS: validFromTS,
                        validTo: validTo,
                        validToTS: validToTS,
                        daysRemaining: daysRemaining,
                        CA: CA
                    };

                    // NOTE: This may be too coarse
                    err = null;

    // TODO: Prob split filtering into dedicated Fn
                    // Only include certs which have been issued since the last run, unless the user has opted to return all by setting checkIntervalSecs to (exactly) 0
                    if(data.validFromTS >= ignoreCertsValidFromBeforeTS || ignoreCertsValidFromBeforeTS === 0)
                    {
                        certsData.certs.entries.push(data);
                    }

                    let expectedCAMatch = false;
                    if(data.CA)
                    {
                        expectedCAs.forEach((ECA) =>
                        {
                            if(data.CA.match(ECA))
                            {
                                expectedCAMatch = true;
                            }
                        });
                    }

                    if(expectedCAMatch === false)
                    {
                        certsData.unexpectedCA.entries.push(data);
                    }


                    if(certsData.byCA.entries[data.CA] === undefined)
                    {
                        certsData.byCA.entries[data.CA] = [];
                    }

                    certsData.byCA.entries[data.CA].push(data);
                }

            });
        }
    }

    // Counts (totals)
    certsData.certs.count = certsData.certs.entries.length;
    certsData.unexpectedCA.count = certsData.unexpectedCA.entries.length;
    certsData.byCA.count = Object.keys(certsData.byCA.entries).length;

    return callback(err, certsData);
}


function convertXMLToJSON(toJson: Function, XML: string, callback: Function)
{
    let err = null;
    let parsedJSON = null;

    try
    {
        // NOTE: toJson is a 3rd party dep (xml2json)
        let rawJSON = toJson(XML);

        // Somewhat oddly, toJson returns a stringified JOSN object
        parsedJSON = JSON.parse(rawJSON);
    }
    catch (e)
    {
        err = e;
    }

    return callback(err, parsedJSON);
}


function getRSSXML(domainNamePattern: string, get: Object, callback: Function)
{
    let xml = "";

    // NOTE: We're doing a plain (not if-modified-since) GET on the URL and are NOT using the built-in "ignore expired certs" as we do that programmativally via ignoreCertsValidToBeforeTS
    get("https://crt.sh/atom?identity=" + domainNamePattern, (response) =>
    {
        response.on("data", (d) =>
        {
            xml += d.toString("utf8");
        });

        response.on("end", (e) =>
        {
            return callback(e, xml);
        });
    });
}


// Maybe this should be an option obj? for at least e.g. config-type options
function checkCTLogs(get: Object, toJson: Function, domainNamePatterns: Array, checkIntervalSecs: uint32 = defaults.checkIntervalSecs, ignoreCertsValidToBeforeTS: number = defaults.ignoreCertsValidToBeforeTS, expectedCAs: Array = defaults.expectedCAs, callback: Function)
{
    const numDomainNamePatterns = domainNamePatterns.length;
    let numDomainNamePatternsCompleted = 0;

    domainNamePatterns.forEach((domainNamePattern) =>
    {
        // HTTP2-capable GET of the specific XML feed for the relevant domain name pattern (e.g. %.bbc.co.uk - where % is a wildcard)
        getRSSXML(domainNamePattern, get, (RSSError, RSSXML) =>
        {
            if(RSSError)
            {
                return callback(RSSError, null);
            }

            // Raw conversion from XML to JSON
            convertXMLToJSON(toJson, RSSXML, (convertErr, RSSJSON) =>
            {
                if(convertErr)
                {
                    return callback(convertErr, null);
                }

                let ignoreCertsValidFromBeforeTS = nowTS - checkIntervalSecs;

                getCertsData(RSSJSON, ignoreCertsValidFromBeforeTS, ignoreCertsValidToBeforeTS, expectedCAs, (getCertsDataErr, certsData) =>
                {
                    if(getCertsDataErr)
                    {
                        return callback(getCertsDataErr, null);
                    }

                    numDomainNamePatternsCompleted++;

                    if(numDomainNamePatternsCompleted >= numDomainNamePatterns)
                    {
                        return callback(null, certsData);
                    }
                });
            })
        });
    });
}

module.exports =
{
    checkCTLogs: checkCTLogs
};
