#!/usr/bin/env node
"use strict";

/*
    Helper script which simply creates a copy of the template config file at the current path
    to streamline creation of configs for specific tests
*/

// Core deps
import {createReadStream, createWriteStream} from "fs";
import {join} from "path";
import {cwd} from "process";

// 3rd party deps

// local deps

// config
const src = join(__dirname, "../../config/tls-certificate-transparency-log-checker-config-template.js");
const dest = join(cwd(), "tls-certificate-transparency-log-checker-config.js");

const srcOpts =
{
    flags: "r",
    autoClose: true
};

const destOpts =
{
    flags: "w",
    defaultEncoding: "utf8",
    autoClose: true
};

// Stream/pipe the template config file into a local (pwd) file
createReadStream(src, srcOpts).pipe(createWriteStream(dest, destOpts));
