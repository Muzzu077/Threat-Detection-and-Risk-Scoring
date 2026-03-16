/**
 * ThreatPulse Express middleware
 * Automatically captures HTTP request/response details and ships them
 * to ThreatPulse via the SDK client.
 */

const { ThreatPulse } = require('./index');

/**
 * Returns an Express middleware that tracks every request.
 *
 * @param {Object} options
 * @param {string} [options.apiKey]    - ThreatPulse API key
 * @param {string} [options.endpoint]  - ThreatPulse API base URL
 * @returns {Function} Express middleware
 */
function threatPulseMiddleware({ apiKey, endpoint } = {}) {
  const tp = new ThreatPulse({ apiKey, endpoint });

  // Flush remaining events when the process exits
  process.on('beforeExit', () => tp.shutdown());

  return function _threatPulseMiddleware(req, res, next) {
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

module.exports = { threatPulseMiddleware };
