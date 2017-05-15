# egg-auth

[![NPM version][npm-image]][npm-url]
[![build status][travis-image]][travis-url]
[![Test coverage][codecov-image]][codecov-url]
[![David deps][david-image]][david-url]
[![Known Vulnerabilities][snyk-image]][snyk-url]
[![npm download][download-image]][download-url]

[npm-image]: https://img.shields.io/npm/v/egg-bcrypt.svg?style=flat-square
[npm-url]: https://npmjs.org/package/egg-bcrypt
[travis-image]: https://img.shields.io/travis/eggjs/egg-bcrypt.svg?style=flat-square
[travis-url]: https://travis-ci.org/eggjs/egg-bcrypt
[codecov-image]: https://img.shields.io/codecov/c/github/eggjs/egg-bcrypt.svg?style=flat-square
[codecov-url]: https://codecov.io/github/eggjs/egg-bcrypt?branch=master
[david-image]: https://img.shields.io/david/eggjs/egg-bcrypt.svg?style=flat-square
[david-url]: https://david-dm.org/eggjs/egg-bcrypt
[snyk-image]: https://snyk.io/test/npm/egg-bcrypt/badge.svg?style=flat-square
[snyk-url]: https://snyk.io/test/npm/egg-bcrypt
[download-image]: https://img.shields.io/npm/dm/egg-bcrypt.svg?style=flat-square
[download-url]: https://npmjs.org/package/egg-bcrypt

<!--
Description here.
-->

## Install

```bash
$ npm i egg-auth --save
```

## Usage

```js
// {app_root}/config/plugin.js
exports.auth = {
  enable: true,
  package: 'egg-auth',
};
```

## Configuration

```js
// {app_root}/config/config.default.js
exports.auth = {
    
};
```

see [config/config.default.js](config/config.default.js) for more detail.

## Example

<!-- example here -->

## Questions & Suggestions

Please open an issue [here](https://github.com/eggjs/egg/issues).

## License

[MIT](LICENSE)
