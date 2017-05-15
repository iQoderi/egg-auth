"use strict";

const bcrypt = require('bcrypt');
const jwt = require('koa-jwt');
const compose = require('koa-compose');
const assert = require('assert');
const Promise = require('bluebird');

Promise.promisifyAll(bcrypt);

class Auth {
    constructor(app) {
        this.config = app.config;
    }

    /**
     * 加密密码
     * @param password
     * @returns {Promise.<*>}
     */
    async encrypt(password) {
        const salt = await bcrypt.genSaltAsync(this.config.auth.password.saltTime);
        const hash = await bcrypt.hashAsync(password, salt);
        let newPass = "";
        hash.then(data => newPass = data );
        return newPass;
    }

    /**
     * 验证密码
     * @param password
     * @param hash
     * @returns {Promise.<*>}
     */
    async validate(password, hash) {
        const res = await bcrypt.compareAsync(password, hash);
        let ret = '';
        res.then(data => ret = data);
        return ret;
    }

    /**
     * 生成token
     * @param id
     * @param time
     * @returns {*}
     */
    signToken(id, time = '1y') {
        const { secrets } = this.config.auth.session;
        return jwt.sign({ _id: id }, secrets, { expiresIn: time });
    }

    /**
     * 验证token
     * @returns {Promise.<void>}
     */
    async authToken() {
        const { secrets } = this.config.auth.session;
        return compose([
            async (ctx, next) => {
                const { query, headers } = ctx.request;
                const token = query.access_token || headers.access_token;
                headers.authorization = `Bearer ${token}`;
                await next();
            },
            jwt({ secrets, passthrough: true }),
        ]);
    }

    /**
     * 验证用户是否登录
     * @returns {Promise.<*>}
     */
    async isAuthenticated(nextMiddleware) {
        return compose([
            this.authToken(),
            async (ctx, next) => {
                if (!ctx.state.user) ctx.throw('UnauthorizedError',401);
                await next();
            },
            nextMiddleware
        ]);
    }

    /**
     * 检查用户权限
     * @param role
     * @returns {Promise.<function(*, *)>}
     */
    async hasRole(role) {
        if (!role && role !== 0) ctx.throw('required role need to be set');
        return async (ctx, next) => {
            const { userRoles } = this.config.auth;
            if (userRoles.indexOf(ctx.request.user.role) >= userRoles.indexOf(role)) {
                await next();
            } else {
                ctx.throw(403);
            }
        }
    }
}

const mount = (app) => {
    const { auth:config } = app.config;
    assert(config.password && config.session, `[egg-auth] password: ${config.password}, session: ${config.password}`)
    app.auth = new Auth(app);
};

module.exports = mount;
