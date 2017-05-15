'use strict';

const Auth = require('./lib/passport');

module.exports = agent => {
  if (agent.config.auth.agent) Auth.init(agent);
};
