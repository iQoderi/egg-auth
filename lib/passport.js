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

    /**
     * 加密密码
     * @param password
     * @returns {Promise.<*>}
     */
    async encrypt(password) {
        const salt = await bcrypt.genSaltAsync(this.config.password.saltTime);
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
            const { userRoles } = this.config;
            if (userRoles.indexOf(ctx.request.user.role) >= userRoles.indexOf(role)) {
                await next();
            } else {
                ctx.throw(403);
            }
        }
    }



}


const authFactory = (app, config) => {
    return new Auth(app, config);
};

const mount = (app) => {
    return app.addSingleton('auth', authFactory);
};


module.exports = mount;