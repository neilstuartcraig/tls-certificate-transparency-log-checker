#! /usr/bin/env node
"use strict";

const path = require("path");
const fs = require("fs");

const configDir = "config";
const configTemplateFilename = "tls-certificate-transparency-log-alerter-config-template.js";
const configDestinationFilename = "tls-certificate-transparency-log-alerter-config.js";

const src = path.join("./", configDir, "/", configTemplateFilename).replace(" ", "\ ");
const dest = path.join("./", configDir, "/", configDestinationFilename);

// Check we can read the source file
fs.access(src, fs.R_OK, (srcAccessErr) =>
{
  if(srcAccessErr)
  {
    throw srcAccessErr;
  }

  // Read the source file
  fs.readFile(src, (readSrcErr, readSrcData) =>
  {
    if(readSrcErr)
    {
      throw readSrcErr;
    }

    // Append the contents of the source file to the destination file - this is OK because we already checked that the destination file doesn't exist, so this will just create it
    fs.appendFile(dest, readSrcData, {flag: "ax"}, (appendErr) =>
    {
      if(appendErr)
      {
        if(appendErr.code === "EEXIST")
        {
          console.log("Config file " + dest + " exists, will not overwrite it");
          process.exit(0);
        }
        else
        {
          throw appendErr;
        }
      }

      console.log("Copied config file to " + dest + " - please amend it with your details before running the app");
    });
  });
});
