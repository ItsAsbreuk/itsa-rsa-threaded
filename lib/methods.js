/**
 *
 * Pollyfils for often used functionality for Arrays
 *
 * <i>Copyright (c) 2014 ITSA - https://github.com/itsa</i>
 * New BSD License - http://choosealicense.com/licenses/bsd-3-clause/
 *
 * @module js-ext
 * @submodule lib/methods.js
 * @class ItsaRsaThreaded
 *
 */

'use strict';

const methods = [
    /**
     * Generates a private and public key. When empty, is generates a keypair with 2048 bits and exp=65537.
     *
     * @example
     *   let rsa = require('itsa-rsa-threaded');<br>
     *   rsa.generateKeyPair()<br>
     *   .then(keys => {<br>
     *     &nbsp;&nbsp;&nbsp;&nbsp;// keys.private holds the private key<br>
     *     &nbsp;&nbsp;&nbsp;&nbsp;// keys.public holds the public key<br>
     *   });
     *
     * @method generateKeyPair
     * @param [keyData] {String|Buffer|Object} parameters for generating key or the key in one of supported formats:<br>
     *                                         * Private key in PEM string<br>
     *                                         * Buffer containing private PEM string<br>
     *                                         * Buffer containing private DER encoded data<br>
     *                                         * Object contains key components
     * @param [format] {String} format for importing key. Composed of several parts: scheme-[key_type]-[output_type]<br>
     *                          * scheme: support for multiple format schemes for import/export keys:<br>
     *                          &nbsp;&nbsp;&nbsp;&nbsp;'pkcs1' — public key starts from '-----BEGIN RSA PUBLIC KEY-----' header and private key starts from '-----BEGIN RSA PRIVATE KEY-----' header<br>
     *                          &nbsp;&nbsp;&nbsp;&nbsp;'pkcs8' — public key starts from '-----BEGIN PUBLIC KEY-----' header and private key starts from '-----BEGIN PRIVATE KEY-----' header<br>
     *                          &nbsp;&nbsp;&nbsp;&nbsp;'components' — use it for import/export key from/to raw components --> see: https://github.com/rzcoder/node-rsa#importexport-keys<br>
     *                          * key_type — can be 'private' or 'public'. Default 'private'<br>
     *                          * output_type — can be:<br>
     *                          &nbsp;&nbsp;&nbsp;&nbsp;'pem' — Base64 encoded string with header and footer. Used by default.<br>
     *                          &nbsp;&nbsp;&nbsp;&nbsp;'der' — Binary encoded key data.<br>
     * @param [options] {Object}
     * @param [options.encryptionScheme="pkcs1_oaep"] {String} padding scheme for encrypt/decrypt. Either 'pkcs1_oaep' or 'pkcs1'
     * @param [options.signingScheme="pkcs1-sha256"] {String} scheme used for signing and verifying.<br>
     *                                                        Either 'pkcs1' or 'pss' or 'scheme-hash' format string (eg 'pss-sha1'). If chosen pss then 'pss-sha1' will be used<br>
     *                                                        Notice: This lib supporting next hash algorithms: 'md5', 'ripemd160', 'sha1', 'sha256', 'sha512' in browser and node environment
     *                                                        and additional 'md4', 'sha', 'sha224', 'sha384' in node only.
     * @return {Promise} resolves with an object that holds 2 : {private: String|Buffer, public: String|Buffer}
     */
    'generateKeyPair', // may pass a private key

    /**
     * Generates the public key out of a private key.
     *
     * @example
     *   let rsa = require('itsa-rsa-threaded'),<br>
     *   &nbsp;&nbsp;&nbsp;&nbsp;PRIVATE_KEY = '-----BEGIN PRIVATE KEY----- .... -----END PRIVATE KEY-----';<br>
     *   rsa.privateToPublicKey(PRIVATE_KEY)<br>
     *   .then(publicKey => {<br>
     *     &nbsp;&nbsp;&nbsp;&nbsp;// publicKey holds the public key<br>
     *   });
     *
     * @method privateToPublicKey
     * @param key {String|Buffer|Object} parameters for generating key or the key in one of supported formats:<br>
     *                                         * key in PEM string<br>
     *                                         * Buffer containing PEM string<br>
     *                                         * Buffer containing DER encoded data<br>
     *                                         * Object with the properties: {key, options, format} (see the arguments of `generateKeyPair`)
     * @return {Promise} resolves with a public Key
     */
    'privateToPublicKey',

    /**
     * Checks if a key is a private key.
     *
     * @example
     *   let rsa = require('itsa-rsa-threaded'),<br>
     *   &nbsp;&nbsp;&nbsp;&nbsp;KEY = '-----BEGIN PRIVATE KEY----- .... -----END PRIVATE KEY-----';<br>
     *   rsa.isPrivate(KEY)<br>
     *   .then(private => {<br>
     *     &nbsp;&nbsp;&nbsp;&nbsp;// private is either `true` or `false`<br>
     *   });
     *
     * @method isPrivate
     * @param key {String|Buffer|Object} parameters for generating key or the key in one of supported formats:<br>
     *                                         * key in PEM string<br>
     *                                         * Buffer containing PEM string<br>
     *                                         * Buffer containing DER encoded data<br>
     *                                         * Object with the properties: {key, options, format} (see the arguments of `generateKeyPair`)
     * @return {Promise} resolves with boolean, telling if the key is private or not.
     */
    'isPrivate',

    /**
     * Checks if a key is a public key.
     *
     * @example
     *   let rsa = require('itsa-rsa-threaded'),<br>
     *   &nbsp;&nbsp;&nbsp;&nbsp;KEY = '-----BEGIN PUBLIC KEY----- .... -----END PUBLIC KEY-----';<br>
     *   rsa.isPrivate(KEY)<br>
     *   .then(public => {<br>
     *     &nbsp;&nbsp;&nbsp;&nbsp;// public is either `true` or `false`<br>
     *   });
     *
     * @method isPublic
     * @param key {String|Buffer|Object} parameters for generating key or the key in one of supported formats:<br>
     *                                         * key in PEM string<br>
     *                                         * Buffer containing PEM string<br>
     *                                         * Buffer containing DER encoded data<br>
     *                                         * Object with the properties: {key, options, format} (see the arguments of `generateKeyPair`)
     * @return {Promise} resolves with boolean, telling if the key is public or not.
     */
    'isPublic',

    /**
     * Encrypts any data with a PUBLIC Key.
     *
     * @example
     *   let rsa = require('itsa-rsa-threaded'),<br>
     *   &nbsp;&nbsp;&nbsp;&nbsp;PUBLIC_KEY = '-----BEGIN PUBLIC KEY----- .... -----END PUBLIC KEY-----',<br>
     *   &nbsp;&nbsp;&nbsp;&nbsp;data = {a: 10};<br>
     *   rsa.encrypt(PUBLIC_KEY, data)<br>
     *   .then(encryptedData => {<br>
     *     &nbsp;&nbsp;&nbsp;&nbsp;// encryptedData holds the encrypted data<br>
     *   });
     *
     * @method encrypt
     * @param key {String|Buffer|Object} parameters for generating key or the key in one of supported formats:<br>
     *                                         * key in PEM string<br>
     *                                         * Buffer containing PEM string<br>
     *                                         * Buffer containing DER encoded data<br>
     *                                         * Object with the properties: {key, options, format} (see the arguments of `generateKeyPair`)
     * @param data {Any} data to encrypt
     * @return {Promise} resolves with a Buffer, holding the encrypted data
     */
    'encrypt',

    /**
     * Decrypts data using a PRIVATE key.
     *
     * @example
     *   let rsa = require('itsa-rsa-threaded'),<br>
     *   &nbsp;&nbsp;&nbsp;&nbsp;PRIVATE_KEY = '-----BEGIN PRIVATE KEY----- .... -----END PRIVATE KEY-----';<br>
     *   &nbsp;&nbsp;&nbsp;&nbsp;encryptedData = ...;<br>
     *   rsa.decrypt(PRIVATE_KEY, encryptedData)<br>
     *   .then(data => {<br>
     *     &nbsp;&nbsp;&nbsp;&nbsp;// data holds the decrypted data<br>
     *   });
     *
     * @method decrypt
     * @param key {String|Buffer|Object} parameters for generating key or the key in one of supported formats:<br>
     *                                         * key in PEM string<br>
     *                                         * Buffer containing PEM string<br>
     *                                         * Buffer containing DER encoded data<br>
     *                                         * Object with the properties: {key, options, format} (see the arguments of `generateKeyPair`)
     * @param data {Buffer} data to decrypt
     * @return {Promise} resolves with the decrypted data {Any}
     */
    'decrypt',

    /**
     * Encrypts any data with a PRIVATE Key.
     *
     * @example
     *   let rsa = require('itsa-rsa-threaded'),<br>
     *   &nbsp;&nbsp;&nbsp;&nbsp;PRIVATE_KEY = '-----BEGIN PRIVATE KEY----- .... -----END PRIVATE KEY-----';<br>
     *   &nbsp;&nbsp;&nbsp;&nbsp;data = {a: 10};<br>
     *   rsa.encryptPrivate(PRIVATE_KEY, data)<br>
     *   .then(encryptedData => {<br>
     *     &nbsp;&nbsp;&nbsp;&nbsp;// encryptedData holds the encrypted data<br>
     *   });
     *
     * @method encryptPrivate
     * @param key {String|Buffer|Object} parameters for generating key or the key in one of supported formats:<br>
     *                                         * key in PEM string<br>
     *                                         * Buffer containing PEM string<br>
     *                                         * Buffer containing DER encoded data<br>
     *                                         * Object with the properties: {key, options, format} (see the arguments of `generateKeyPair`)
     * @param data {Any} data to encrypt
     * @return {Promise} resolves with a Buffer, holding the encrypted data
     */
    'encryptPrivate',

    /**
     * Decrypts data using a PUBLIC key.
     *
     * @example
     *   let rsa = require('itsa-rsa-threaded'),<br>
     *   &nbsp;&nbsp;&nbsp;&nbsp;PUBLIC_KEY = '-----BEGIN PUBLIC KEY----- .... -----END PUBLIC KEY-----';<br>
     *   &nbsp;&nbsp;&nbsp;&nbsp;encryptedData = ...;<br>
     *   rsa.decryptPublic(PUBLIC_KEY, encryptedData)<br>
     *   .then(data => {<br>
     *     &nbsp;&nbsp;&nbsp;&nbsp;// data holds the decrypted data<br>
     *   });
     *
     * @method decryptPublic
     * @param key {String|Buffer|Object} parameters for generating key or the key in one of supported formats:<br>
     *                                         * key in PEM string<br>
     *                                         * Buffer containing PEM string<br>
     *                                         * Buffer containing DER encoded data<br>
     *                                         * Object with the properties: {key, options, format} (see the arguments of `generateKeyPair`)
     * @param data {Buffer} data to decrypt
     * @return {Promise} resolves with the decrypted data {Any}
     */
    'decryptPublic',

    /**
     * Signs any data with a PRIVATE key
     *
     * @example
     *   let rsa = require('itsa-rsa-threaded'),<br>
     *   &nbsp;&nbsp;&nbsp;&nbsp;PRIVATE_KEY = '-----BEGIN PRIVATE KEY----- .... -----END PRIVATE KEY-----',<br>
     *   &nbsp;&nbsp;&nbsp;&nbsp;data = {a: 10};<br>
     *   rsa.sign(PRIVATE_KEY, data)<br>
     *   .then(signedData => {<br>
     *     &nbsp;&nbsp;&nbsp;&nbsp;// signedData holds the encrypted, signed data<br>
     *   });
     *
     * @method sign
     * @param key {String|Buffer|Object} parameters for generating key or the key in one of supported formats:<br>
     *                                         * key in PEM string<br>
     *                                         * Buffer containing PEM string<br>
     *                                         * Buffer containing DER encoded data<br>
     *                                         * Object with the properties: {key, options, format} (see the arguments of `generateKeyPair`)
     * @param data {Any} data to sign
     * @return {Promise} resolves with a Buffer, holding the encrypted signed data
     */
    'sign',

    /**
     * Verifies signed values with aa PRIVATE key.
     *
     * @example
     *   let rsa = require('itsa-rsa-threaded'),<br>
     *   &nbsp;&nbsp;&nbsp;&nbsp;PRIVATE_KEY = '-----BEGIN PRIVATE KEY----- .... -----END PRIVATE KEY-----',<br>
     *   &nbsp;&nbsp;&nbsp;&nbsp;signedData = ...;<br>
     *   rsa.verify(PRIVATE_KEY, signedData)<br>
     *   .then(verified => {<br>
     *     &nbsp;&nbsp;&nbsp;&nbsp;// verified is either `true` or `false`<br>
     *   });
     *
     * @method verify
     * @param key {String|Buffer|Object} parameters for generating key or the key in one of supported formats:<br>
     *                                         * key in PEM string<br>
     *                                         * Buffer containing PEM string<br>
     *                                         * Buffer containing DER encoded data<br>
     *                                         * Object with the properties: {key, options, format} (see the arguments of `generateKeyPair`)
     * @param data {Buffer} data to verify
     * @return {Promise} resolves with `true` or `false`
     */
    'verify',

    /**
     * Retrieves the key-size.
     * Works with both private and public keys.
     *
     * @example
     *   let rsa = require('itsa-rsa-threaded'),<br>
     *   &nbsp;&nbsp;&nbsp;&nbsp;PRIVATE_KEY = '-----BEGIN PRIVATE KEY----- .... -----END PRIVATE KEY-----';<br>
     *   rsa.getKeySize(PRIVATE_KEY)<br>
     *   .then(size => {<br>
     *     &nbsp;&nbsp;&nbsp;&nbsp;// size is the key-size<br>
     *   });
     *
     * @method getKeySize
     * @param key {String|Buffer|Object} parameters for generating key or the key in one of supported formats:<br>
     *                                         * key in PEM string<br>
     *                                         * Buffer containing PEM string<br>
     *                                         * Buffer containing DER encoded data<br>
     *                                         * Object with the properties: {key, options, format} (see the arguments of `generateKeyPair`)
     * @return {Promise} resolves with the key-size {Number}
     */
    'getKeySize',

    /**
     * Retrieves the max. message-size of the key.
     * Works with both private and public keys.
     *
     * @example
     *   let rsa = require('itsa-rsa-threaded'),<br>
     *   &nbsp;&nbsp;&nbsp;&nbsp;PRIVATE_KEY = '-----BEGIN PRIVATE KEY----- .... -----END PRIVATE KEY-----';<br>
     *   rsa.getMaxMessageSize(PRIVATE_KEY)<br>
     *   .then(maxMessageSize => {<br>
     *     &nbsp;&nbsp;&nbsp;&nbsp;// maxMessageSize is the max. message-size of the key<br>
     *   });
     *
     * @method getMaxMessageSize
     * @param key {String|Buffer|Object} parameters for generating key or the key in one of supported formats:<br>
     *                                         * key in PEM string<br>
     *                                         * Buffer containing PEM string<br>
     *                                         * Buffer containing DER encoded data<br>
     *                                         * Object with the properties: {key, options, format} (see the arguments of `generateKeyPair`)
     * @return {Promise} resolves with the max. message-size of the key {Number}
     */
    'getMaxMessageSize'
];

module.exports = methods;
