"use strict";

// 3rd party deps
import test from "ava";

// Local deps
import lib from "../dist/lib/tls-certificate-transparency-log-alerter-lib.js";

test("lib.test() with valid inputs (1)", (t) =>
{
    let res = lib.test("a");
    t.is(res, "b", "a must equal b");
});
