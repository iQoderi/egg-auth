'use strict';

/**
 * egg-bcrypt default config
 * @member Config#bcrypt
 * @property {String} SOME_KEY - some description
 */
exports.auth = {
    password: {
        saltTime: 10
    },
    app: true,
    agent: false,
};
