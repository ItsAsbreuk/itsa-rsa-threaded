/*eslint no-empty: 0*/
/*eslint no-undef: 0*/

'use strict';

require('itsa-jsext');

const callRSA = require('./rsa');

module.exports = function (self) {
    const executeChild = e => {
        // self.postMessage({error: 'err'});
        self.postMessage(callRSA(e.data));
    //     self.removeEventListener('message', executeChild);
    };
    self.addEventListener('message', executeChild);
};
