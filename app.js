'use strict';

const mount = require('./lib/passport');

module.exports = app => {
  if (app.config.auth.app) mount(app);
};
