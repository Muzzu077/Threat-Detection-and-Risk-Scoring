/**
 * TrustFlow SDK for Node.js
 * Zero-dependency client for shipping HTTP logs to your TrustFlow dashboard.
 */

class TrustFlow {
  /**
   * @param {Object} options
   * @param {string}  [options.apiKey]         - API key (or set TRUSTFLOW_API_KEY env var)
   * @param {string}  [options.endpoint]       - TrustFlow API base URL
   * @param {number}  [options.batchSize=25]   - Flush automatically after this many queued events
   * @param {number}  [options.flushInterval=5000] - Auto-flush interval in ms
   */
  constructor({ apiKey, endpoint, batchSize = 25, flushInterval = 5000, maxQueueSize = 10000 } = {}) {
    this.apiKey =
      apiKey || process.env.TRUSTFLOW_API_KEY || '';
    const explicitEndpoint =
      endpoint ||
      process.env.TRUSTFLOW_ENDPOINT ||
      '';
    this.endpoint = explicitEndpoint || 'http://localhost:8000';
    this.batchSize = batchSize;
    this.flushInterval = flushInterval;
    this.maxQueueSize = maxQueueSize;

    /** @type {Array<Object>} */
    this._queue = [];
    this._dropped = 0;

    // Loud-fail: empty API key — every request will 401 silently otherwise.
    if (!this.apiKey) {
      console.error(
        '[TrustFlow] No API key configured. Set apiKey option or TRUSTFLOW_API_KEY env var. ' +
        'Events will be rejected by the server (401).'
      );
    }
    // Loud-fail: endpoint defaulted to localhost in a production-looking env.
    // This is the single most common integration mistake — events POST into
    // the void on the customer's own server and never reach the dashboard.
    const usingDefault = !explicitEndpoint;
    const looksProd = (process.env.NODE_ENV || '').toLowerCase() === 'production';
    if (usingDefault && looksProd) {
      console.error(
        '[TrustFlow] endpoint not configured — defaulting to http://localhost:8000 ' +
        'while NODE_ENV=production. Set the `endpoint` option (or TRUSTFLOW_ENDPOINT env var) ' +
        'to your TrustFlow dashboard URL or events will not be delivered.'
      );
    } else if (usingDefault) {
      console.warn(
        '[TrustFlow] endpoint not configured — defaulting to http://localhost:8000. ' +
        'Set `endpoint` (or TRUSTFLOW_ENDPOINT) for production deployments.'
      );
    }

    // Periodic flush timer
    this._timer = setInterval(() => {
      if (this._queue.length > 0) {
        this.flush().catch(() => {});
      }
    }, this.flushInterval);

    // Allow the process to exit even if the timer is still active
    if (this._timer && typeof this._timer.unref === 'function') {
      this._timer.unref();
    }
  }

  /**
   * Add an event to the internal queue.
   * Auto-flushes when the queue reaches batchSize.
   * @param {Object} event - Arbitrary event payload
   */
  track(event) {
    if (this._queue.length >= this.maxQueueSize) {
      // Drop oldest first so the queue can't grow unbounded if the
      // server is unreachable for a long time.
      this._queue.shift();
      this._dropped += 1;
      if (this._dropped === 1 || this._dropped % 1000 === 0) {
        console.error(
          `[TrustFlow] Queue full (${this.maxQueueSize}) — dropping events. ` +
          `Total dropped so far: ${this._dropped}. Check that endpoint and apiKey are correct.`
        );
      }
    }
    this._queue.push(event);
    if (this._queue.length >= this.batchSize) {
      this.flush().catch(() => {});
    }
  }

  /**
   * POST all queued events to the TrustFlow ingest endpoint.
   * On failure the events are re-queued so they can be retried.
   * @returns {Promise<void>}
   */
  async flush() {
    if (this._queue.length === 0) return;

    // Drain the queue into a local batch
    const batch = this._queue.splice(0);

    try {
      const res = await fetch(`${this.endpoint}/api/v1/ingest`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-API-Key': this.apiKey,
        },
        body: JSON.stringify({ events: batch }),
      });

      if (!res.ok) {
        // 401 = bad/missing key, 403 = revoked, 429 = rate limited, 4xx other = bad payload.
        // For 4xx (except 429) the events are bad and re-queueing forever just spams.
        const isBadRequest = res.status >= 400 && res.status < 500 && res.status !== 429;
        let body = '';
        try { body = (await res.text()).slice(0, 200); } catch { /* ignore */ }
        const msg = `ingest responded with ${res.status}${body ? ` — ${body}` : ''}`;
        if (isBadRequest) {
          console.error(`[TrustFlow] ${msg} — discarding ${batch.length} event(s) (will not retry).`);
          return;
        }
        throw new Error(msg);
      }
    } catch (err) {
      // Re-queue events so they can be retried on the next flush.
      // Honor maxQueueSize so we don't grow unbounded on prolonged outages.
      const merged = batch.concat(this._queue);
      if (merged.length > this.maxQueueSize) {
        this._dropped += merged.length - this.maxQueueSize;
      }
      this._queue = merged.slice(-this.maxQueueSize);
      console.error('[TrustFlow]', err.message || err);
    }
  }

  /**
   * Stop the auto-flush timer and flush any remaining events.
   * Call this before your process exits.
   * @returns {Promise<void>}
   */
  async shutdown() {
    if (this._timer) {
      clearInterval(this._timer);
      this._timer = null;
    }
    await this.flush();
  }
}

module.exports = { TrustFlow };
