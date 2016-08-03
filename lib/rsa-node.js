/*eslint no-empty: 0*/
'use strict';

require('itsa-jsext');

let rsa = {};

const fork = require('child_process').fork,
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
        },
        rejectPromise = err => {
            promise.reject(err);
        },

        // executing child-process, but we won't add any arguments yet:
        // passing the arguments currently needs to be `Strings`, whereas we may need to pass Objects
        // therefore, arguments will be send to the child later on
        childProcess = fork('./lib/process-node-child.js');

    childProcess.on('message', processData);
    childProcess.on('exit', rejectPromise);
    childProcess.on('error', rejectPromise);

    promise.itsa_finally(() => {
        // cleanup:
        childProcess.removeListener('message', processData);
        childProcess.removeListener('exit', rejectPromise);
        childProcess.removeListener('error', rejectPromise);
    });

    promise.kill = childProcess.kill;

    // sending arguments to the child-process, into object with property `args`:
    childProcess.send({args});

    return promise;
};

METHODS.forEach(method => {
    rsa[method] = rsaFunc.bind(null, method);
});

module.exports = rsa;
