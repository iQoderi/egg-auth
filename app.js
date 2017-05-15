'use strict';

const Auth = require('./lib/passport');

module.exports = app => {
  if (app.config.auth.app) Auth.init(app);
};
