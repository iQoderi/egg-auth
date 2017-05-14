'use strict';

const request = require('supertest');
const mm = require('egg-mock');

describe('test/bcrypt.test.js', () => {
  let app;
  before(() => {
    app = mm.app({
      baseDir: 'apps/bcrypt-test',
    });
    return app.ready();
  });

  after(() => app.close());
  afterEach(mm.restore);

  it('should GET /', () => {
    return request(app.callback())
      .get('/')
      .expect('hi, bcrypt')
      .expect(200);
  });
});
