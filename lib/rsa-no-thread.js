/*eslint no-empty: 0*/
'use strict';

require('itsa-jsext');

let rsa = {};

const callRSA = require('./rsa'),
    NOOP = () => {},
    METHODS = require('./methods'),
    CRYPTED_METHODS = require('./crypted-methods'),
    BOOLEAN_METHODS = require('./boolean-methods');

const rsaFunc = function() {
    let args = Array.prototype.slice.call(arguments),
        promise = Promise.itsa_manage();
    const fn = arguments[0];
    // always call `isPublic` with argument 'true':
    (fn==='isPublic') && (args[2]=true);

    const processData = data => {
            let value;
            if (data.error) {
                if (BOOLEAN_METHODS[fn]) {
                    promise.fulfill(false);
                }
                else {
                    promise.reject(data.error);
                }
            }
            else {
                value = data.value;
                if (CRYPTED_METHODS[fn]) {
                    try {
                        value = JSON.parse(value);
                        if (Object.itsa_isObject(value) && (value.type==='Buffer')) {
                            value = new Buffer(value.data);
                        }
                    }
                    catch (err) {}
                }
                promise.fulfill(value);
            }
        };

    promise.kill = NOOP;

    // sending arguments to the child-process, into object with property `args`:
    processData(callRSA(args));

    return promise;
};

METHODS.forEach(method => {
    rsa[method] = rsaFunc.bind(null, method);
});

module.exports = rsa;


