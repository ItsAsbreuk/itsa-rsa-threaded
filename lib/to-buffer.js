/*eslint no-empty: 0*/

'use strict';

require('itsa-jsext');

const toBuffer = data => {
    data.forEach((field, i) => {
        let nested;
        if (Object.itsa_isObject(field) &&
            ((field.type==='Buffer') ||
             (Object.itsa_isObject(field.key) && (nested=(field.key.type==='Buffer')))
            )) {
            try {
                if (nested) {
                    data[i].key = new Buffer(field.key.data);
                }
                else {
                    data[i] = new Buffer(field.data);
                }
            }
            catch (err) {}
        }
    });
    return data;
};

module.exports = toBuffer;
