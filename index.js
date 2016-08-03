'use strict';

const isNode = require('itsa-utils').isNode;
let rsa;

const WEBWORKER_SUPPORT = false; // no support for webworker: "secure random number generation not supported"

if (isNode) {
    rsa = require('./lib/rsa-node');
}
else {
    if (WEBWORKER_SUPPORT && window.Worker) {
        rsa = require('./lib/rsa-browser');
    }
    else {
        rsa = require('./lib/rsa-no-thread');
    }
}

module.exports = rsa;
