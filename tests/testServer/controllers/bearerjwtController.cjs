/** @oastools {Controller} /api/v1/bearerjwt */

var service = require('./bearerjwtService.cjs');

/**
 * @oastools {method} GET
 */
 module.exports.getRequest = function getRequest(req, res, next) {
  service.getRequest(req.params, res, next);
};

/**
 * @oastools {method} GET
 * @oastools {path} /{param}
 */
 module.exports.getRequest = function getRequest(req, res, next) {
  service.getRequest(req.params, res, next);
};