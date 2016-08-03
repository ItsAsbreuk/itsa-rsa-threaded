/*global describe, it */
/*eslint no-unused-vars: 0*/

var chai = require('chai'),
    expect = chai.expect,
    should = chai.should(),
    ItsaRsaThreaded = require('../index'),
    fs = require('fs'),
    utils = require('itsa-utils'),
    NodeRSA = require('node-rsa'),
    OAEP = require('node-rsa/src/schemes/oaep'),
    publicKey1 = fs.readFileSync('./tests/keys/public_pkcs1.der'), // // browsefrify + brfs MUST have a string and no variable as argument of fs.readFileSync --> https://github.com/substack/brfs/issues/36
    publicKey2 = fs.readFileSync('./tests/keys/public_pkcs1.pem').toString(),
    publicKey3 = fs.readFileSync('./tests/keys/public_pkcs8.der'),
    publicKey4 = fs.readFileSync('./tests/keys/public_pkcs8.pem').toString(),
    privateKey1 = fs.readFileSync('./tests/keys/private_pkcs1.der'),
    privateKey2 = fs.readFileSync('./tests/keys/private_pkcs1.pem').toString(),
    privateKey3 = fs.readFileSync('./tests/keys/private_pkcs8.der'),
    privateKey4 = fs.readFileSync('./tests/keys/private_pkcs8.pem').toString(),
    environments = ['browser', 'node'],
    encryptSchemes = ['pkcs1', 'pkcs1_oaep'],
    signingSchemes = ['pkcs1', 'pss'],
    signHashAlgorithms = {
        'browser': ['MD5', 'RIPEMD160', 'SHA1', 'SHA256', 'SHA512']
    },
    dataBundle = {
        'string': {
            data: 'ascii + 12345678',
            encoding: 'utf8'
        },
        'unicode string': {
            data: 'ascii + юникод スラ ⑨',
            encoding: 'utf8'
        },
        'empty string': {
            data: '',
            encoding: ['utf8', 'ascii', 'hex', 'base64']
        },
        'long string': {
            data: 'Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.',
            encoding: ['utf8', 'ascii']
        },
        'buffer': {
            data: new Buffer('ascii + юникод スラ ⑨'),
            encoding: 'buffer'
        },
        'json object': {
            data: {str: 'string', arr: ['a', 'r', 'r', 'a', 'y', true, '⑨'], int: 42, nested: {key: {key: 1}}},
            encoding: 'json'
        },
        'json array': {
            data: [1, 2, 3, 4, 5, 6, 7, 8, 9, [10, 11, 12, [13], 14, 15, [16, 17, [18]]]],
            encoding: 'json'
        }
    },
    generatedKeys = [],
    keyObjects = [],
    keySizes = [
        {b: 512, e: 3},
        {b: 512, e: 5},
        {b: 512, e: 257},
        {b: 512, e: 65537},
        {b: 768}, // 'e' should be 65537
        {b: 1024}, // 'e' should be 65537
        {b: 2048} // 'e' should be 65537
    ];

if (utils.isNode) {
    signHashAlgorithms.node = ['MD4', 'MD5', 'RIPEMD160', 'SHA', 'SHA1', 'SHA224', 'SHA256', 'SHA384', 'SHA512'];
}
else {
    signHashAlgorithms.node = ['MD5', 'RIPEMD160', 'SHA1', 'SHA256', 'SHA512'];
}

// Generating keys:
keySizes.forEach(size => {
    generatedKeys.push(new NodeRSA({b: size.b, e: size.e}, {encryptionScheme: 'pkcs1'}));
});

chai.use(require('chai-as-promised'));

describe('Work with keys', function () {

    describe('Generating keys', function () {
        this.timeout(35000);

        it('Generate public key', function() {
            const keyPair = ItsaRsaThreaded.generateKeyPair();
            return keyPair.then(keys => ItsaRsaThreaded.isPublic(keys.public)).should.become(true);
        });

        it('Generate private key', function() {
            const keyPair = ItsaRsaThreaded.generateKeyPair();
            return keyPair.then(keys => ItsaRsaThreaded.isPrivate(keys.private)).should.become(true);
        });

        keySizes.forEach(size => {
            (function (size) {
                it('should make key pair ' + size.b + '-bit length and public exponent is ' + (size.e ? size.e : size.e + ' and should be 65537'), function (done) {
                    const keyPair = ItsaRsaThreaded.generateKeyPair({b: size.b, e: size.e}, {encryptionScheme: 'pkcs1'});
                    keyPair.then(keys => {
                        var array = [
                            ItsaRsaThreaded.getKeySize(keys.private),
                            ItsaRsaThreaded.getMaxMessageSize({key: keys.private, options: {encryptionScheme: 'pkcs1'}}),
                            ItsaRsaThreaded.getKeySize(keys.public),
                            ItsaRsaThreaded.getMaxMessageSize({key: keys.public, options: {encryptionScheme: 'pkcs1'}})
                        ];
                        return Promise.all(array).then(response => {
                            expect(response[0]).to.be.equal(size.b);
                            expect(response[1]).to.be.equal((size.b / 8) - 11);
                            expect(response[2]).to.be.equal(size.b);
                            expect(response[3]).to.be.equal((size.b / 8) - 11);
                            done();
                        });
                    }).catch(err => done(new Error(err)));
                });
            })(size);
        });
    });

    describe('Import/Export keys', function () {
        var privateKeyPKCS1 = '-----BEGIN RSA PRIVATE KEY-----\n' +
            'MIIFwgIBAAKCAUEAsE1edyfToZRv6cFOkB0tAJ5qJor4YF5CccJAL0fS/o1Yk10V\n' +
            'SXH4Xx4peSJgYQKkO0HqO1hAz6k9dFQB4U1CnWtRjtNEcIfycqrZrhu6you5syb6\n' +
            'ScV3Zu/9bm7/DyaLlx/gJhUPR1OxOzaqsEvlu7hbDhNLIYo1zKFb/aUBbD6+UcaG\n' +
            'xH2BfFNdzVAtVSVpc/s2Y3sboMN7rByUj7937iQlaMINvVjyasynYuzHNw6ZRP9J\n' +
            'P9fwxrCyaxnTPWxVl0qvVaQO2+TtFMtDXH2OVZtWWeLHAL8cildw0G+u2qVqTqIG\n' +
            'EwNyJlsAHykaPFAMW0xLueumrSlB+JUJPrRvvw4nBCd4GOrNSlPCE/xlk1Cb8JaI\n' +
            'CTLvDUcYc3ZqL3jqAueBhkpw2uCz8xVJeOA1KY4kQIIx8JEBsAYzgyP2iy0CAwEA\n' +
            'AQKCAUAjBcudShkdgRpWSmNr94/IDrAxpeu/YRo79QXBHriIftW4uIYRCAX6B0jf\n' +
            '2ndg7iBn8Skxzs9ZMVqW8FVLR4jTMs2J3Og8npUIOG5zyuhpciZas4SHASY+GbCz\n' +
            'rnMWtGaIh/mENyzI05RimfKAgSNLDk1wV17Wc9lKJEfc9Fl7Al/WaOS+xdviMcFx\n' +
            'ltrajksLkjz0uDD917eKskbE45lULfGqeI0kYDadWp88pw6ikXJln2p3Y1PNQF3e\n' +
            'y2cN+Snzd0jx/c5fD9B1zxKYv5bUo+UnTzBxV81e9xCJfkdXv+6D5qDn1gGLdZZa\n' +
            '5FxtZbRgVh/ZlqP9xYr72as/WFmIA20wRgHPgWvLyHsh0XThqZf2/O3R8KmFv8aT\n' +
            '+kmc5is6sVItIIi7ltorVapTkJai3zz/VSMBBaL+ytFN9jVl4QKBoQDfL8TMeZXu\n' +
            'gBTN7yq6zZWN8+60MUaxz0/lKdzmo35z32rpVKdsYd922pmcsNYaoj/H9L3j/NP4\n' +
            '9z+SHfYpWvTa7AvJfNlXYc3BRXIarpfnXsm65IzKzHaF9i2xdXxkfTEYIvOQDMLF\n' +
            'SiiObWJMV+QqUxb3luu3/CR3IcbgeTOpdiC/T/Zl/YYl17JqZTHmLFZPq7xewttg\n' +
            'zQorDRWIFDtlAoGhAMo4+uM9f4BpOHSmayhLhHArIGs4386BkXSeOLeQitaQJ/2c\n' +
            'zb459O87XoCAonZbq+dI7XRnBU3toQvEsZgrtGkOFXCZJMWAQxD5BQ5vEYT6c86h\n' +
            'uGpX6h3ODlJ6UGi+5CWyMQ1cFlBkfffFAarjSYTVlyj736sOeDuJWX133z5VQBQ8\n' +
            '1xSH23kNF95vxB4I1fXG8WL11YZU7VEwSLC4aCkCgaAKRj+wDhTZ4umSRWVZLiep\n' +
            'XkZp4y7W9q095nx13abvnKRmU3BVq/fGl++kZ/ujRD7dbKXlPflgJ7m0d06ivr4w\n' +
            '6dbtEqNKw4TeVd0X31u82f89bFIS7/Cw4BFgbwEn+x9sdgdyZTP+MxjE3cI9s3oc\n' +
            'fLC8+ySk1qWzGkn2gX3gWkDNrdexAEfRrClZfokaiIX8qvJEBoJk5WuHadXI6u2F\n' +
            'AoGgByidOQ4kRVd0OCzr/jEuLwpXy3Pn+Fd93rL7LwRe5dmUkNXMMr+6e/2OCt6C\n' +
            '4c28+CMMxOIgvfF7kf8Uil6BtHZbK/E/6/3uYdtu4mPsKtjy4I25CYqzLvrsZt8N\n' +
            'maeoS+1S7zYjVBU6oFrJBFOndpxZDYpdEKEigHkMQfTMYliCPDUrJ/7nNhHQln8+\n' +
            'YhHOATVZtjcdp/O5svYSnK7qgQKBoDd3lFWrPatgxpF1JXMEFFbaIRdNxHkKA4YY\n' +
            'gMTM4MPgViunYX/yJ7SaX8jWnC231A9uVn4+kb+DvKjc+ZuTQvnIUK2u6LvIinVF\n' +
            'snDEA+BbXwehAtwdHDMDtqYFdx4hvCWQwBNn4p3J0OO2tbYVMtvM5aOEfRSYagfm\n' +
            'RywhDUAjW8U0RBnzlmXhQQ6B9bjqooS2MsRrJrS5CU682fb3hBo=\n' +
            '-----END RSA PRIVATE KEY-----';

        var publicKeyPKCS8 = '-----BEGIN PUBLIC KEY-----\n' +
            'MIIBYjANBgkqhkiG9w0BAQEFAAOCAU8AMIIBSgKCAUEAsE1edyfToZRv6cFOkB0t\n' +
            'AJ5qJor4YF5CccJAL0fS/o1Yk10VSXH4Xx4peSJgYQKkO0HqO1hAz6k9dFQB4U1C\n' +
            'nWtRjtNEcIfycqrZrhu6you5syb6ScV3Zu/9bm7/DyaLlx/gJhUPR1OxOzaqsEvl\n' +
            'u7hbDhNLIYo1zKFb/aUBbD6+UcaGxH2BfFNdzVAtVSVpc/s2Y3sboMN7rByUj793\n' +
            '7iQlaMINvVjyasynYuzHNw6ZRP9JP9fwxrCyaxnTPWxVl0qvVaQO2+TtFMtDXH2O\n' +
            'VZtWWeLHAL8cildw0G+u2qVqTqIGEwNyJlsAHykaPFAMW0xLueumrSlB+JUJPrRv\n' +
            'vw4nBCd4GOrNSlPCE/xlk1Cb8JaICTLvDUcYc3ZqL3jqAueBhkpw2uCz8xVJeOA1\n' +
            'KY4kQIIx8JEBsAYzgyP2iy0CAwEAAQ==\n' +
            '-----END PUBLIC KEY-----';

        var privateKeyPEMNotTrimmed = '     \n\n    \n\n ' + privateKeyPKCS1 + '\n \n  \n\n  ';
        var publicKeyPEMNotTrimmed = '\n\n\n\n ' + publicKeyPKCS8 + '\n \n\n\n  ';

        describe('Good cases', function () {
            describe('Common cases', function () {
                it('should load private key from (not trimmed) PKCS1-PEM string', function (done) {
                    var array = [
                        ItsaRsaThreaded.isPrivate(privateKeyPEMNotTrimmed),
                        ItsaRsaThreaded.isPublic(privateKeyPEMNotTrimmed)
                    ];
                    Promise.all(array).then(response => {
                        expect(response[0]).to.be.true;
                        expect(response[1]).to.be.false;
                        done();
                    }).catch(err => done(new Error(err)));
                });

                it('should load public key from (not trimmed) PKCS8-PEM string', function (done) {
                    var array = [
                        ItsaRsaThreaded.isPrivate(publicKeyPEMNotTrimmed),
                        ItsaRsaThreaded.isPublic(publicKeyPEMNotTrimmed)
                    ];
                    Promise.all(array).then(response => {
                        expect(response[0]).to.be.false;
                        expect(response[1]).to.be.true;
                        done();
                    }).catch(err => done(new Error(err)));
                });

                it('should load private key from PKCS1-PEM string', function (done) {
                    var array = [
                        ItsaRsaThreaded.isPrivate(privateKeyPKCS1),
                        ItsaRsaThreaded.isPublic(privateKeyPKCS1)
                    ];
                    Promise.all(array).then(response => {
                        expect(response[0]).to.be.true;
                        expect(response[1]).to.be.false;
                        done();
                    }).catch(err => done(new Error(err)));
                });

                it('should load public key from PKCS8-PEM string', function (done) {
                    var array = [
                        ItsaRsaThreaded.isPrivate(publicKeyPKCS8),
                        ItsaRsaThreaded.isPublic(publicKeyPKCS8)
                    ];
                    Promise.all(array).then(response => {
                        expect(response[0]).to.be.false;
                        expect(response[1]).to.be.true;
                        done();
                    }).catch(err => done(new Error(err)));
                });

                it('privateToPublicKey should return pkcs8 public PEM string', function (done) {
                    this.timeout(35000);
                    const keyPair = ItsaRsaThreaded.privateToPublicKey(privateKeyPEMNotTrimmed);
                    keyPair.then(key => {
                        expect(key).to.be.eql(publicKeyPKCS8);
                        var array = [
                            ItsaRsaThreaded.isPrivate(key),
                            ItsaRsaThreaded.isPublic(key)
                        ];
                        return Promise.all(array).then(response => {
                            expect(response[0]).to.be.false;
                            expect(response[1]).to.be.true;
                            done();
                        });
                    }).catch(err => done(new Error(err)));
                });

            });

        });

    });
});

describe('Check keys', function() {
    this.timeout(5000);

    describe('Private', function() {
        it('private der-1 should pass', function() {
            return ItsaRsaThreaded.isPrivate({key: privateKey1, format: 'pkcs1-private-der'}).should.become(true);
        });
        it('private pem-1 should pass', function() {
            return ItsaRsaThreaded.isPrivate(privateKey2).should.become(true);
        });
        it('private der-8 should pass', function() {
            return ItsaRsaThreaded.isPrivate({key: privateKey3, format: 'pkcs8-private-der'}).should.become(true);
        });
        it('private pem-8 should pass', function() {
            return ItsaRsaThreaded.isPrivate(privateKey4).should.become(true);
        });
        it('public der-1 should fail', function() {
            return ItsaRsaThreaded.isPrivate({key: publicKey1, format: 'pkcs1-public-der'}).should.become(false);
        });
        it('public pem-1 should fail', function() {
            return ItsaRsaThreaded.isPrivate(publicKey2).should.become(false);
        });
        it('public der-8 should fail', function() {
            return ItsaRsaThreaded.isPrivate({key: publicKey3, format: 'pkcs8-public-der'}).should.become(false);
        });
        it('public pem-8 should fail', function() {
            return ItsaRsaThreaded.isPrivate(publicKey4).should.become(false);
        });
    });

    describe('Public', function() {
        it('public der-1 should pass', function() {
            return ItsaRsaThreaded.isPublic({key: publicKey1, format: 'pkcs1-public-der'}).should.become(true);
        });
        it('public pem-1 should pass', function() {
            return ItsaRsaThreaded.isPublic(publicKey2).should.become(true);
        });
        it('public der-8 should pass', function() {
            return ItsaRsaThreaded.isPublic({key: publicKey3, format: 'pkcs8-public-der'}).should.become(true);
        });
        it('public pem-8 should pass', function() {
            return ItsaRsaThreaded.isPublic(publicKey4).should.become(true);
        });
        it('private der-1 should fail', function() {
            return ItsaRsaThreaded.isPublic({key: privateKey1, format: 'pkcs1-private-der'}).should.become(false);
        });
        it('private pem-1 should fail', function() {
            return ItsaRsaThreaded.isPublic(privateKey2).should.become(false);
        });
        it('private der-8 should fail', function() {
            return ItsaRsaThreaded.isPublic({key: privateKey3, format: 'pkcs8-private-der'}).should.become(false);
        });
        it('private pem-8 should fail', function() {
            return ItsaRsaThreaded.isPublic(privateKey4).should.become(false);
        });
    });

    describe('Invalid Private keys', function() {
        it('invalid should fail', function() {
            return ItsaRsaThreaded.isPrivate('wrong content').should.become(false);
        });
        it('private der-1 unspecified', function() {
            return ItsaRsaThreaded.isPrivate(privateKey1).should.become(false);
        });
        it('private der-1 wrong unspecified', function() {
            return ItsaRsaThreaded.isPrivate({key: privateKey1, format: 'pkcs8-private-der'}).should.become(false);
        });
        it('private pem-1 wrong unspecified', function() {
            return ItsaRsaThreaded.isPrivate({key: privateKey2, format: 'pkcs8-private-der'}).should.become(false);
        });
        it('private der-8 unspecified', function() {
            return ItsaRsaThreaded.isPrivate(privateKey3).should.become(false);
        });
        it('private der-8 wrong unspecified', function() {
            return ItsaRsaThreaded.isPrivate({key: privateKey3, format: 'pkcs1-private-der'}).should.become(false);
        });
        it('private pem-8 wrong unspecified', function() {
            return ItsaRsaThreaded.isPrivate({key: privateKey4, format: 'pkcs8-private-der'}).should.become(false);
        });
    });

    describe('Invalid Public keys', function() {
        it('invalid should fail', function() {
            return ItsaRsaThreaded.isPublic('wrong content').should.become(false);
        });
        it('public der-1 unspecified', function() {
            return ItsaRsaThreaded.isPublic(publicKey1).should.become(false);
        });
        it('public der-1 wrong unspecified', function() {
            return ItsaRsaThreaded.isPublic({key: publicKey1, format: 'pkcs8-public-der'}).should.become(false);
        });
        it('public pem-1 wrong unspecified', function() {
            return ItsaRsaThreaded.isPublic({key: publicKey2, format: 'pkcs8-public-der'}).should.become(false);
        });
        it('public der-8 unspecified', function() {
            return ItsaRsaThreaded.isPublic(publicKey3).should.become(false);
        });
        it('public der-8 wrong unspecified', function() {
            return ItsaRsaThreaded.isPublic({key: publicKey3, format: 'pkcs1-public-der'}).should.become(false);
        });
        it('public pem-8 wrong unspecified', function() {
            return ItsaRsaThreaded.isPublic({key: publicKey4, format: 'pkcs8-public-der'}).should.become(false);
        });
    });

});

describe('Key-info', function() {
    this.timeout(5000);

    describe('getKeySize', function() {
        it('private der-1 should pass', function() {
            return ItsaRsaThreaded.getKeySize({key: privateKey1, format: 'pkcs1-private-der'}).should.become(1024);
        });
        it('private pem-1 should pass', function() {
            return ItsaRsaThreaded.getKeySize(privateKey2).should.become(1024);
        });
        it('private der-8 should pass', function() {
            return ItsaRsaThreaded.getKeySize({key: privateKey3, format: 'pkcs8-private-der'}).should.become(1024);
        });
        it('private pem-8 should pass', function() {
            return ItsaRsaThreaded.getKeySize(privateKey4).should.become(1024);
        });
        it('public der-1 should fail', function() {
            return ItsaRsaThreaded.getKeySize({key: publicKey1, format: 'pkcs1-public-der'}).should.become(1024);
        });
        it('public pem-1 should fail', function() {
            return ItsaRsaThreaded.getKeySize(publicKey2).should.become(1024);
        });
        it('public der-8 should fail', function() {
            return ItsaRsaThreaded.getKeySize({key: publicKey3, format: 'pkcs8-public-der'}).should.become(1024);
        });
        it('public pem-8 should fail', function() {
            return ItsaRsaThreaded.getKeySize(publicKey4).should.become(1024);
        });
        it('invalid should reject', function() {
            return ItsaRsaThreaded.getKeySize('wrong content').should.reject;
        });
    });

    describe('getMaxMessageSize', function() {
        it('private der-1 should pass', function() {
            return ItsaRsaThreaded.getMaxMessageSize({key: privateKey1, format: 'pkcs1-private-der'}).should.become(86);
        });
        it('private pem-1 should pass', function() {
            return ItsaRsaThreaded.getMaxMessageSize(privateKey2).should.become(86);
        });
        it('private der-8 should pass', function() {
            return ItsaRsaThreaded.getMaxMessageSize({key: privateKey3, format: 'pkcs8-private-der'}).should.become(86);
        });
        it('private pem-8 should pass', function() {
            return ItsaRsaThreaded.getMaxMessageSize(privateKey4).should.become(86);
        });
        it('public der-1 should fail', function() {
            return ItsaRsaThreaded.getMaxMessageSize({key: publicKey1, format: 'pkcs1-public-der'}).should.become(86);
        });
        it('public pem-1 should fail', function() {
            return ItsaRsaThreaded.getMaxMessageSize(publicKey2).should.become(86);
        });
        it('public der-8 should fail', function() {
            return ItsaRsaThreaded.getMaxMessageSize({key: publicKey3, format: 'pkcs8-public-der'}).should.become(86);
        });
        it('public pem-8 should fail', function() {
            return ItsaRsaThreaded.getMaxMessageSize(publicKey4).should.become(86);
        });
        it('invalid should reject', function() {
            return ItsaRsaThreaded.getMaxMessageSize('wrong content').should.reject;
        });
    });

});

describe('Encrypting & decrypting', function () {
    this.timeout(5000);
    environments.forEach(env => {
        (function (env) {
            encryptSchemes.forEach(scheme_i => {
                (function (scheme) {
                    describe('Environment: ' + env + '. Encryption scheme: ' + scheme, function () {
                        describe('Good cases', function () {
                            var encrypted = {};
                            var decrypted = {};
                            dataBundle.itsa_each((value, i) => {
                                (function (i) {
                                    var key = null;
                                    var suit = dataBundle[i];

                                    it('`encrypt()` should encrypt ' + i, function (done) {
                                        let keyObj;
                                        key = new NodeRSA(generatedKeys[Math.round(Math.random() * 1000) % generatedKeys.length].exportKey(), {
                                            environment: env,
                                            encryptionScheme: scheme
                                        });
                                        keyObjects[i] = {
                                            key: key.exportKey(),
                                            options: {
                                                environment: env,
                                                encryptionScheme: scheme
                                            }
                                        };
                                        ItsaRsaThreaded.encrypt(keyObjects[i], suit.data).then(
                                            data => {
                                                encrypted[i] = data;
                                                expect(Buffer.isBuffer(data)).to.be.true;
                                                expect(data.length>0).to.be.true;
                                                done();
                                            },
                                            err => {
                                                console.log('error', err);
                                                done(new Error(err));
                                            }
                                        ).catch(err => done(new Error(err)));
                                    });

                                    it('`decrypt()` should decrypt ' + i, function (done) {
                                        ItsaRsaThreaded.decrypt(keyObjects[i], encrypted[i], Array.isArray(suit.encoding) ? suit.encoding[0] : suit.encoding).then(
                                            data => {
                                                decrypted[i] = data;
                                                if (Buffer.isBuffer(decrypted[i])) {
                                                    expect(suit.data.toString('hex')).to.be.eql(decrypted[i].toString('hex'));
                                                } else {
                                                    expect(suit.data).to.be.eql(decrypted[i]);
                                                }
                                                done();
                                            },
                                            err => {
                                                done(new Error(err));
                                            }
                                        ).catch(err => done(new Error(err)));
                                    });
                                })(i);
                            });
                        });

                        describe('Bad cases', function () {
                            it('unsupported data type null', function () {
                                return ItsaRsaThreaded.encrypt(generatedKeys[0].exportKey(), null).should.be.rejected;
                            });
                            it('unsupported data type undefined', function () {
                                return ItsaRsaThreaded.encrypt(generatedKeys[0].exportKey(), undefined).should.be.rejected;
                            });
                            it('unsupported data type true', function () {
                                return ItsaRsaThreaded.encrypt(generatedKeys[0].exportKey(), true).should.be.rejected;
                            });
                            it('unsupported data type false', function () {
                                return ItsaRsaThreaded.encrypt(generatedKeys[0].exportKey(), false).should.be.rejected;
                            });
                            it('incorrect key for decrypting', function () {
                                const promise = ItsaRsaThreaded.encrypt(generatedKeys[0].exportKey(), 'data')
                                                .then(encrypted => ItsaRsaThreaded.decrypt(generatedKeys[1], encrypted));
                                return promise.should.be.rejected;
                            });
                        });
                    });
                })(scheme_i);
            });

            describe('Environment: ' + env + '. encryptPrivate & decryptPublic', function () {
                var encrypted = {};
                var decrypted = {};
                dataBundle.itsa_each((value, i) => {
                    (function (i) {
                        var key = null;
                        var suit = dataBundle[i];

                        it('`encryptPrivate()` should encrypt ' + i, function (done) {
                            key = new NodeRSA(generatedKeys[Math.round(Math.random() * 1000) % generatedKeys.length].exportKey(), {
                                environment: env
                            });
                            keyObjects[i] = {
                                key: key.exportKey(),
                                options: {
                                    environment: env
                                }
                            };
                            ItsaRsaThreaded.encryptPrivate(keyObjects[i], suit.data).then(
                                data => {
                                    encrypted[i] = data;
                                    expect(Buffer.isBuffer(data)).to.be.true;
                                    expect(data.length>0).to.be.true;
                                    done();
                                },
                                err => {
                                    done(new Error(err));
                                }
                            ).catch(err => done(new Error(err)));


                        });

                        it('`decryptPublic()` should decrypt ' + i, function (done) {
                            ItsaRsaThreaded.decryptPublic(keyObjects[i], encrypted[i], Array.isArray(suit.encoding) ? suit.encoding[0] : suit.encoding).then(
                                data => {
                                    decrypted[i] = data;
                                    if (Buffer.isBuffer(decrypted[i])) {
                                        expect(suit.data.toString('hex')).to.be.eql(decrypted[i].toString('hex'));
                                    } else {
                                        expect(suit.data).to.be.eql(decrypted[i]);
                                    }
                                    done();
                                },
                                err => {
                                    done(new Error(err));
                                }
                            ).catch(err => done(new Error(err)));
                        });
                    })(i);
                });
            });
        })(env);
    });

});

describe('Signing & verifying', function () {
    signingSchemes.forEach(scheme_i => {
        (function (scheme) {
            describe('Signing scheme: ' + scheme, function () {
                var envs = ['node'];
                if (scheme == 'pkcs1') {
                    envs = environments;
                }
                envs.forEach(env => {
                    (function (env) {

                        describe('Good cases ' + (envs.length > 1 ? ' in ' + env + ' environment' : ''), function () {
                            var signed = {};
                            var key = null;

                            dataBundle.itsa_each((value, i) => {
                                (function (i) {
                                    var suit = dataBundle[i];
                                    it('should sign ' + i, function (done) {
                                        key = new NodeRSA(generatedKeys[generatedKeys.length - 1].exportKey(), {
                                            signingScheme: scheme + '-sha256',
                                            environment: env
                                        });
                                        keyObjects[i] = {
                                            key: key.exportKey(),
                                            options: {
                                                signingScheme: scheme + '-sha256',
                                                environment: env
                                            }
                                        };
                                        ItsaRsaThreaded.sign(keyObjects[i], suit.data).then(
                                            data => {
                                                signed[i] = data;
                                                expect(Buffer.isBuffer(data)).to.be.true;
                                                expect(data.length>0).to.be.true;
                                                done();
                                            },
                                            err => {
                                                done(new Error(err));
                                            }
                                        ).catch(err => done(new Error(err)));
                                    });

                                    it('should verify ' + i, function () {
                                        return ItsaRsaThreaded.verify(keyObjects[i], suit.data, signed[i]).should.become(true);
                                    });
                                })(i);
                            });

                            signHashAlgorithms[env].forEach(alg => {
                                (function (alg) {
                                    it('signing with custom algorithm (' + alg + ')', function () {
                                        var key = new NodeRSA(generatedKeys[generatedKeys.length - 1].exportKey(), {
                                            signingScheme: scheme + '-' + alg,
                                            environment: env
                                        });
                                        var keyObject = {
                                            key: key.exportKey(),
                                            options: {
                                                signingScheme: scheme + '-' + alg,
                                                environment: env
                                            }
                                        };
                                        var promise = ItsaRsaThreaded.sign(keyObject, 'data')
                                                      .then(signed => ItsaRsaThreaded.verify(keyObject, 'data', signed));
                                        return promise.should.become(true);
                                    });

                                    if (scheme === 'pss') {
                                        it('signing with custom algorithm (' + alg + ') with max salt length', function () {
                                            var a = alg.toLowerCase();
                                            var key = new NodeRSA(generatedKeys[generatedKeys.length - 1].exportKey(), {
                                                signingScheme: { scheme: scheme, hash: a, saltLength: OAEP.digestLength[a] },
                                                environment: env
                                            });
                                            var keyObject = {
                                                key: key.exportKey(),
                                                options: {
                                                    signingScheme: { scheme: scheme, hash: a, saltLength: OAEP.digestLength[a] },
                                                    environment: env
                                                }
                                            };
                                            var promise = ItsaRsaThreaded.sign(keyObject, 'data')
                                                          .then(signed => ItsaRsaThreaded.verify(keyObject, 'data', signed));
                                            return promise.should.become(true);
                                        });
                                    }
                                })(alg);
                            });
                        });

                      describe('Bad cases' + (envs.length > 1 ? ' in ' + env + ' environment' : ''), function () {

                            it('incorrect data for verifying', function () {
                                var key = new NodeRSA(generatedKeys[0].exportKey(), {
                                    signingScheme: scheme + '-sha256',
                                    environment: env
                                });
                                var keyObject = {
                                    key: key.exportKey(),
                                    options: {
                                        signingScheme: scheme + '-sha256',
                                        environment: env
                                    }
                                };
                                var promise = ItsaRsaThreaded.sign(keyObject, 'data1')
                                              .then(signed => ItsaRsaThreaded.verify(keyObject, 'data2', signed));
                                return promise.should.become(false);
                            });

                            it('incorrect key for signing', function () {
                                var key = new NodeRSA(generatedKeys[0].exportKey('pkcs8-public'), {
                                    signingScheme: scheme + '-sha256',
                                    environment: env
                                });
                                var keyObject = {
                                    key: key.exportKey('pkcs8-public'),
                                    options: {
                                        signingScheme: scheme + '-sha256',
                                        environment: env
                                    }
                                };
                                return ItsaRsaThreaded.sign(keyObject, 'data').should.be.rejected;
                            });

                            it('incorrect key for verifying', function () {
                                var key1 = new NodeRSA(generatedKeys[0].exportKey(), {
                                    signingScheme: scheme + '-sha256',
                                    environment: env
                                });
                                var key2 = new NodeRSA(generatedKeys[1].exportKey('pkcs8-public'), {
                                    signingScheme: scheme + '-sha256',
                                    environment: env
                                });
                                var keyObject1 = {
                                    key: key1.exportKey(),
                                    options: {
                                        signingScheme: scheme + '-sha256',
                                        environment: env
                                    }
                                };
                                var keyObject2 = {
                                    key: key2.exportKey('pkcs8-public'),
                                    options: {
                                        signingScheme: scheme + '-sha256',
                                        environment: env
                                    }
                                };
                                var promise = ItsaRsaThreaded.sign(keyObject1, 'data')
                                              .then(signed => ItsaRsaThreaded.verify(keyObject2, 'data', signed));
                                return promise.should.become(false);
                            });

                            it('incorrect key for verifying (empty)', function () {
                                var keyObject = {
                                    key: null,
                                    options: {
                                        environment: env
                                    }
                                };
                                return ItsaRsaThreaded.verify(keyObject, 'data', 'somesignature').should.be.rejected;
                            });

                            it('different algorithms', function () {
                                var singKey = new NodeRSA(generatedKeys[0].exportKey(), {
                                    signingScheme: scheme + '-md5',
                                    environment: env
                                });
                                var verifyKey = new NodeRSA(generatedKeys[0].exportKey(), {
                                    signingScheme: scheme + '-sha1',
                                    environment: env
                                });
                                var keyObjectSign = {
                                    key: singKey.exportKey(),
                                    options: {
                                        signingScheme: scheme + '-md5',
                                        environment: env
                                    }
                                };
                                var keyObjectVerify = {
                                    key: verifyKey.exportKey(),
                                    options: {
                                        signingScheme: scheme + '-sha1',
                                        environment: env
                                    }
                                };
                                var promise = ItsaRsaThreaded.sign(keyObjectSign, 'data')
                                              .then(signed => ItsaRsaThreaded.verify(keyObjectVerify, 'data', signed));
                                return promise.should.become(false);
                            });

                        });

                    })(env);
                });

                if (scheme !== 'pkcs1') {
                    return;
                }

                describe('Compatibility of different environments', function () {
                    signHashAlgorithms['browser'].forEach(alg => {
                        (function (alg) {
                            it('signing with custom algorithm (' + alg + ') (equal test)', function (done) {
                                var nodeKey = new NodeRSA(generatedKeys[5].exportKey(), {
                                    signingScheme: scheme + '-' + alg,
                                    environment: 'node'
                                });
                                var browserKey = new NodeRSA(generatedKeys[5].exportKey(), {
                                    signingScheme: scheme + '-' + alg,
                                    environment: 'browser'
                                });
                                var nodeKeyObject = {
                                    key: nodeKey.exportKey(),
                                    options: {
                                        signingScheme: scheme + '-' + alg,
                                        environment: 'node'
                                    }
                                };
                                var browserKeyObject = {
                                    key: browserKey.exportKey(),
                                    options: {
                                        signingScheme: scheme + '-' + alg,
                                        environment: 'browser'
                                    }
                                };
                                var promiseNode = ItsaRsaThreaded.sign(nodeKeyObject, 'data', 'hex');
                                var promiseBrowser = ItsaRsaThreaded.sign(browserKeyObject, 'data', 'hex');
                                Promise.all([promiseNode, promiseBrowser])
                                .then(data => {
                                    expect(data[0]).to.be.eql(data[1]);
                                    done();
                                })
                                .catch(err => done(new Error(err)));
                            });

                            it('sign in node & verify in browser (' + alg + ')', function () {
                                var nodeKey = new NodeRSA(generatedKeys[5].exportKey(), {
                                    signingScheme: scheme + '-' + alg,
                                    environment: 'node'
                                });
                                var browserKey = new NodeRSA(generatedKeys[5].exportKey(), {
                                    signingScheme: scheme + '-' + alg,
                                    environment: 'browser'
                                });
                                var nodeKeyObject = {
                                    key: nodeKey.exportKey(),
                                    options: {
                                        signingScheme: scheme + '-' + alg,
                                        environment: 'node'
                                    }
                                };
                                var browserKeyObject = {
                                    key: browserKey.exportKey(),
                                    options: {
                                        signingScheme: scheme + '-' + alg,
                                        environment: 'browser'
                                    }
                                };
                                var promise = ItsaRsaThreaded.sign(nodeKeyObject, 'data')
                                              .then(signed => ItsaRsaThreaded.verify(browserKeyObject, 'data', signed));
                                return promise.should.become(true);
                            });

                            it('sign in browser & verify in node (' + alg + ')', function () {
                                var nodeKey = new NodeRSA(generatedKeys[5].exportKey(), {
                                    signingScheme: scheme + '-' + alg,
                                    environment: 'node'
                                });
                                var browserKey = new NodeRSA(generatedKeys[5].exportKey(), {
                                    signingScheme: scheme + '-' + alg,
                                    environment: 'browser'
                                });
                                var nodeKeyObject = {
                                    key: nodeKey.exportKey(),
                                    options: {
                                        signingScheme: scheme + '-' + alg,
                                        environment: 'node'
                                    }
                                };
                                var browserKeyObject = {
                                    key: browserKey.exportKey(),
                                    options: {
                                        signingScheme: scheme + '-' + alg,
                                        environment: 'browser'
                                    }
                                };
                                var promise = ItsaRsaThreaded.sign(browserKeyObject, 'data')
                                              .then(signed => ItsaRsaThreaded.verify(nodeKeyObject, 'data', signed));
                                return promise.should.become(true);
                            });
                        })(alg);
                    });
                });
            });
        })(scheme_i);
    });
});
