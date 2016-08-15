#!/user/env/node

"use strict";

/*
    Helper script which simply creates a copy of the template config file at the current path
    to streamline creation of configs for specific tests
*/

// Core deps

var _fs = require("fs");

var _path = require("path");

var _process = require("process");

// 3rd party deps

// local deps

// config
const src = (0, _path.join)(__dirname, "../../config/tls-certificate-transparency-log-checker-config-template.js");
const dest = (0, _path.join)((0, _process.cwd)(), "tls-certificate-transparency-log-checker-config.js");

const srcOpts = {
    flags: "r",
    autoClose: true
};

const destOpts = {
    flags: "w",
    defaultEncoding: "utf8",
    autoClose: true
};

// Stream/pipe the template config file into a local (pwd) file
(0, _fs.createReadStream)(src, srcOpts).pipe((0, _fs.createWriteStream)(dest, destOpts));