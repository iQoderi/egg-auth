"use strict";

const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const compose = require('koa-compose');
const assert = require('assert');
const Promise = require('bluebird');

Promise.promisifyAll(bcrypt);

class Auth {
    constructor(app) {
        this.config = app.config;
        this.signToken = this.signToken.bind(this);
    }

    /**
     * 加密密码
     * @param password
     * @returns {Promise.<*>}
     */
    async encrypt(password) {
        const salt = await bcrypt.genSaltAsync(this.config.auth.password.saltTime);
        const hash = await bcrypt.hashAsync(password, salt);
        return hash;
    }

    /**
     * 验证密码
     * @param password
     * @param hash
     * @returns {Promise.<*>}
     */
    async validate(password, hash) {
        const res = await bcrypt.compareAsync(password, hash);
        return res;
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
     * 验证token中间件
     * @returns {Promise.<void>}
     */
    async decodedToken(ctx, next) {
        const { query, headers } = ctx.request;
        const { secrets } = ctx.app.config.auth.session;
        const token = query.access_token || headers.access_token;
        if (token) {
            const decoded = jwt.verify(token, secrets);
            ctx.state.user = decoded;
        } else {
            ctx.state.user = {};
        }
        await next();
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
    hasRole(role) {
        return async (ctx, next) => {
            if (!role && role !== 0) ctx.throw('required role need to be set');
            const { userRoles } = ctx.app.config.auth;
            if (userRoles.indexOf(ctx.state.user.role) >= userRoles.indexOf(role)) {
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
