/*eslint no-empty: 0*/

'use strict';

require('itsa-jsext');

const NodeRSA = require('node-rsa'),
    toBuffer = require('./to-buffer.js'),
    CRYPTED_METHODS = require('./crypted-methods'),
    BOOLEAN_METHODS = require('./boolean-methods');

const callRSA = args => {
    // when passing through, `Buffer`-properties will become an Object --> we need to retransfer them:
    args = toBuffer(args);
    let fn = args[0],
        key = args[1],
        rsaKey, returnValue, privateKey, publicKey, format, options;
    const methodArgs = args.slice(2); // arguments to apply to any rsaKey-method

    if (fn==='generateKeyPair') {
        if ((typeof key!=='string') && !Buffer.isBuffer(key)) {
            key = null;
            format = args[1];
            options = args[2];
        }
        format || (format={});
        rsaKey = new NodeRSA(key);
        key || rsaKey.generateKeyPair(format.b, format.e);
        options && rsaKey.setOptions(options);

        try {
            privateKey = rsaKey.exportKey();
            publicKey = rsaKey.exportKey('public');
        }
        catch (err) {
            return {error: err.message};
        }
        return {
            value: {
                private: privateKey,
                public: publicKey
            }
        };
    }

    if (fn==='privateToPublicKey') {
        if ((typeof key!=='string') && !Buffer.isBuffer(key)) {
            return {error: 'No valid private key'};
        }
        format || (format={});
        rsaKey = new NodeRSA(key);
        try {
            publicKey = rsaKey.exportKey('public');
        }
        catch (err) {
            return {error: err.message};
        }
        return {
            value: publicKey
        };
    }

    if (Object.itsa_isObject(key)) {
        try {
            rsaKey = new NodeRSA(key.key, key.format, key.options);
        }
        catch (err) {
            return {error: err.message};
        }
    }
    else {
        try {
            rsaKey = new NodeRSA(key);
        }
        catch (err) {
            return {error: err.message};
        }
    }
    try {
        returnValue = rsaKey[fn].apply(rsaKey, methodArgs);
    }
    catch (err) {
        return {error: err.message};
    }
    // for some reasson, the boolean funcs don't return boolean values:
    // make them boolean:
    BOOLEAN_METHODS[fn] && (returnValue=!!returnValue);
    if (CRYPTED_METHODS[fn]) {
        try {
            returnValue = JSON.stringify(returnValue);
        }
        catch (err) {
            return {error: err.message};
        }
    }
    return {value: returnValue};
};

module.exports = callRSA;
