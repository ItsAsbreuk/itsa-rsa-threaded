/*eslint no-empty: 0*/

'use strict';

require('itsa-jsext');

const callRSA = require('./rsa');

const executeChild = data => {
    process.send(callRSA(data.args));
};

process.once('message', executeChild);
