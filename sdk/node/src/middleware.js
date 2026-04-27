/**
 * TrustFlow Express middleware
 * Automatically captures HTTP request/response details and ships them
 * to TrustFlow via the SDK client.
 */

const { TrustFlow } = require('./index');

/**
 * Returns an Express middleware that tracks every request.
 *
 * @param {Object} options
 * @param {string} [options.apiKey]    - TrustFlow API key
 * @param {string} [options.endpoint]  - TrustFlow API base URL
 * @returns {Function} Express middleware
 */
function trustFlowMiddleware({ apiKey, endpoint } = {}) {
  const tp = new TrustFlow({ apiKey, endpoint });

  // Flush remaining events when the process exits
  process.on('beforeExit', () => tp.shutdown());

  return function _trustFlowMiddleware(req, res, next) {
    const requestTime = new Date().toISOString();

    res.on('finish', () => {
      const statusCode = res.statusCode;
      const status = statusCode >= 200 && statusCode < 400 ? 'success' : 'failure';

      const user =
        req.user?.email ||
        req.user?.id ||
        'anonymous';

      const ip =
        req.headers['x-forwarded-for']?.split(',')[0].trim() ||
        req.ip ||
        req.connection?.remoteAddress ||
        'unknown';

      tp.track({
        timestamp: requestTime,
        user: String(user),
        ip,
        action: req.method,
        status,
        resource: req.originalUrl || req.url,
      });
    });

    next();
  };
}

module.exports = { trustFlowMiddleware };
