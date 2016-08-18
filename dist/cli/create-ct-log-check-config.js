#!/usr/bin/env node

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
var src = (0, _path.join)(__dirname, "../../config/tls-certificate-transparency-log-checker-config-template.js");
var dest = (0, _path.join)((0, _process.cwd)(), "tls-certificate-transparency-log-checker-config.js");

var srcOpts = {
    flags: "r",
    autoClose: true
};

var destOpts = {
    flags: "w",
    defaultEncoding: "utf8",
    autoClose: true
};

// Stream/pipe the template config file into a local (pwd) file
(0, _fs.createReadStream)(src, srcOpts).pipe((0, _fs.createWriteStream)(dest, destOpts));
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIi4uLy4uL3NyYy9jbGkvY3JlYXRlLWN0LWxvZy1jaGVjay1jb25maWcuanMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6IjtBQUNBOztBQUVBOzs7OztBQUtBOztBQUNBOztBQUNBOztBQUNBOztBQUVBOztBQUVBOztBQUVBO0FBQ0EsSUFBTSxNQUFNLGdCQUFLLFNBQUwsRUFBZ0IsMEVBQWhCLENBQVo7QUFDQSxJQUFNLE9BQU8sZ0JBQUssbUJBQUwsRUFBWSxvREFBWixDQUFiOztBQUVBLElBQU0sVUFDTjtBQUNJLFdBQU8sR0FEWDtBQUVJLGVBQVc7QUFGZixDQURBOztBQU1BLElBQU0sV0FDTjtBQUNJLFdBQU8sR0FEWDtBQUVJLHFCQUFpQixNQUZyQjtBQUdJLGVBQVc7QUFIZixDQURBOztBQU9BO0FBQ0EsMEJBQWlCLEdBQWpCLEVBQXNCLE9BQXRCLEVBQStCLElBQS9CLENBQW9DLDJCQUFrQixJQUFsQixFQUF3QixRQUF4QixDQUFwQyIsImZpbGUiOiJjcmVhdGUtY3QtbG9nLWNoZWNrLWNvbmZpZy5qcyIsInNvdXJjZXNDb250ZW50IjpbIlxuXCJ1c2Ugc3RyaWN0XCI7XG5cbi8qXG4gICAgSGVscGVyIHNjcmlwdCB3aGljaCBzaW1wbHkgY3JlYXRlcyBhIGNvcHkgb2YgdGhlIHRlbXBsYXRlIGNvbmZpZyBmaWxlIGF0IHRoZSBjdXJyZW50IHBhdGhcbiAgICB0byBzdHJlYW1saW5lIGNyZWF0aW9uIG9mIGNvbmZpZ3MgZm9yIHNwZWNpZmljIHRlc3RzXG4qL1xuXG4vLyBDb3JlIGRlcHNcbmltcG9ydCB7Y3JlYXRlUmVhZFN0cmVhbSwgY3JlYXRlV3JpdGVTdHJlYW19IGZyb20gXCJmc1wiO1xuaW1wb3J0IHtqb2lufSBmcm9tIFwicGF0aFwiO1xuaW1wb3J0IHtjd2R9IGZyb20gXCJwcm9jZXNzXCI7XG5cbi8vIDNyZCBwYXJ0eSBkZXBzXG5cbi8vIGxvY2FsIGRlcHNcblxuLy8gY29uZmlnXG5jb25zdCBzcmMgPSBqb2luKF9fZGlybmFtZSwgXCIuLi8uLi9jb25maWcvdGxzLWNlcnRpZmljYXRlLXRyYW5zcGFyZW5jeS1sb2ctY2hlY2tlci1jb25maWctdGVtcGxhdGUuanNcIik7XG5jb25zdCBkZXN0ID0gam9pbihjd2QoKSwgXCJ0bHMtY2VydGlmaWNhdGUtdHJhbnNwYXJlbmN5LWxvZy1jaGVja2VyLWNvbmZpZy5qc1wiKTtcblxuY29uc3Qgc3JjT3B0cyA9XG57XG4gICAgZmxhZ3M6IFwiclwiLFxuICAgIGF1dG9DbG9zZTogdHJ1ZVxufTtcblxuY29uc3QgZGVzdE9wdHMgPVxue1xuICAgIGZsYWdzOiBcIndcIixcbiAgICBkZWZhdWx0RW5jb2Rpbmc6IFwidXRmOFwiLFxuICAgIGF1dG9DbG9zZTogdHJ1ZVxufTtcblxuLy8gU3RyZWFtL3BpcGUgdGhlIHRlbXBsYXRlIGNvbmZpZyBmaWxlIGludG8gYSBsb2NhbCAocHdkKSBmaWxlXG5jcmVhdGVSZWFkU3RyZWFtKHNyYywgc3JjT3B0cykucGlwZShjcmVhdGVXcml0ZVN0cmVhbShkZXN0LCBkZXN0T3B0cykpO1xuIl19