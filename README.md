[![Build Status](https://travis-ci.org/ItsAsbreuk/itsa-rsa-threaded.svg?branch=master)](https://travis-ci.org/ItsAsbreuk/itsa-rsa-threaded)

Promise-based RSA library which runs in separate threads to avoid blocking the event-loop

Based on:
node-rsa from rzcoder's https://github.com/rzcoder/node-rsa
and jsbn library from Tom Wu http://www-cs-students.stanford.edu/~tjw/jsbn/

* Pure JavaScript
* Non-blocking on nodejs
* Promise based
* No needed OpenSSL
* Generating keys
* Supports long messages for encrypt/decrypt
* Signing and verifying

The code also runs in a browser, but there it **will block the eventloop**!
(generating keys might take several seconds)

**[View the full API](http://projects.itsasbreuk.nl/modules/itsa-rsa-threaded/api/classes/ItsaRsaThreaded.html)**

### Example generating keys:

```js
let rsa = require('itsa-rsa-threaded');

rsa.generateKeyPair()
   .then(keys => {
       // keys.private holds the private key
       // keys.public holds the public key
   });
```

### Example encrypting data:

```js
let rsa = require('itsa-rsa-threaded'),
    PUBLIC_KEY = '-----BEGIN PUBLIC KEY----- .... -----END PUBLIC KEY-----',
    data = {a: 10};

rsa.encrypt(PUBLIC_KEY, data)
   .then(encryptedData => {
       // encryptedData holds the encrypted data
   });
```

### Example signing data:

```js
let rsa = require('itsa-rsa-threaded'),
    PRIVATE_KEY = '-----BEGIN PRIVATE KEY----- .... -----END PRIVATE KEY-----';
    data = {a: 10};
rsa.sign(PRIVATE_KEY, data)
   .then(signedData => {
       // signedData holds the encrypted, signed data
   });
```

### Example verifying data:

```js
let rsa = require('itsa-rsa-threaded'),
    PRIVATE_KEY = '-----BEGIN PRIVATE KEY----- .... -----END PRIVATE KEY-----',
    signedData = ...;
rsa.verify(PRIVATE_KEY, signedData)
   .then(verified => {
       // verified is either `true` or `false`
   });
```

## License

#### Copyright (c) 2016, ItsAsbreuk for code used in `itsa-rsa-threaded`
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.

* Neither the name of the copyright holder nor the names of its
  contributors may be used to endorse or promote products derived from
  this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#### Licensing for code `node-rsa` from rzcoder
Copyright (c) 2014  rzcoder<br/>

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

#### Licensing for code used in `rsa.js` and `jsbn.js`

Copyright (c) 2003-2005  Tom Wu<br/>
All Rights Reserved.

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS-IS" AND WITHOUT WARRANTY OF ANY KIND,
EXPRESS, IMPLIED OR OTHERWISE, INCLUDING WITHOUT LIMITATION, ANY
WARRANTY OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.

IN NO EVENT SHALL TOM WU BE LIABLE FOR ANY SPECIAL, INCIDENTAL,
INDIRECT OR CONSEQUENTIAL DAMAGES OF ANY KIND, OR ANY DAMAGES WHATSOEVER
RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER OR NOT ADVISED OF
THE POSSIBILITY OF DAMAGE, AND ON ANY THEORY OF LIABILITY, ARISING OUT
OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

In addition, the following condition applies:

All redistributions must retain an intact copy of this copyright notice
and disclaimer.