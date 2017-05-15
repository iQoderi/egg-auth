'use strict';

const mount = require('./lib/passport');

module.exports = agent => {
  if (agent.config.auth.agent) mount(agent);
};
