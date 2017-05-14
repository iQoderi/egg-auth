"use strict";

const bcrypt = require('bcrypt');
const jwt = require('koa-jwt');
const Promise = require('bluebird');

Promise.promisifyAll(bcrypt);

class  Passport {
    constructor(app, config) {
        this.app = app;
        this.config = config;
    }

    async encrypt(password) {
        const salt = await bcrypt.genSaltAsync(this.config.password.saltTime);
        const hash = await bcrypt.hashAsync(password, salt);
        return hash;
    }

    async validate(password, hash) {
        const res = await bcrypt.compareAsync(password, hash);
        return res;
    }


    static init(app, config) {
        this.app.addSingleton('auth', new Passport);
    }
}

