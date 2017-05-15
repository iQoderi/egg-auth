"use strict";

const bcrypt = require('bcrypt');
const jwt = require('koa-jwt');
const compose = require('koa-compose');
const Promise = require('bluebird');

Promise.promisifyAll(bcrypt);

class  Auth {
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

    signToken(id, time = '1y') {
        const { secrets } = this.config.auth.session;
        return jwt.sign({ _id: id }, secrets, { expiresIn: time });
    }

    async authToken() {

    }

}


const authFactory = (app, config) => {
    return new Auth(app, config);
};

const mount = (app) => {
    return app.addSingleton('auth', authFactory);
};


module.exports = mount;