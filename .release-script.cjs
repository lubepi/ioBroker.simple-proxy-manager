// @ts-check

/// <reference path="node_modules/@alcalzone/release-script/globals.d.ts" />

const iobroker = require("@alcalzone/release-script-plugin-iobroker");
const license = require("@alcalzone/release-script-plugin-license");
const manualReview = require("@alcalzone/release-script-plugin-manual-review");

module.exports = {
    plugins: [
        iobroker.default({ languages: ["en", "de", "ru", "pt", "nl", "fr", "it", "es", "pl", "uk", "zh-cn"] }),
        license.default({ license: "MIT" }),
        manualReview.default(),
    ],
};
