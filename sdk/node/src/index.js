/**
 * ThreatPulse SDK for Node.js
 * Zero-dependency client for shipping HTTP logs to your ThreatPulse dashboard.
 */

class ThreatPulse {
  /**
   * @param {Object} options
   * @param {string}  [options.apiKey]         - API key (or set THREATPULSE_API_KEY env var)
   * @param {string}  [options.endpoint]       - ThreatPulse API base URL
   * @param {number}  [options.batchSize=25]   - Flush automatically after this many queued events
   * @param {number}  [options.flushInterval=5000] - Auto-flush interval in ms
   */
  constructor({ apiKey, endpoint, batchSize = 25, flushInterval = 5000 } = {}) {
    this.apiKey =
      apiKey || process.env.THREATPULSE_API_KEY || '';
    this.endpoint =
      endpoint ||
      process.env.THREATPULSE_ENDPOINT ||
      'http://localhost:8000';
    this.batchSize = batchSize;
    this.flushInterval = flushInterval;

    /** @type {Array<Object>} */
    this._queue = [];

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
    this._queue.push(event);
    if (this._queue.length >= this.batchSize) {
      this.flush().catch(() => {});
    }
  }

  /**
   * POST all queued events to the ThreatPulse ingest endpoint.
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
        throw new Error(`ThreatPulse ingest responded with ${res.status}`);
      }
    } catch (err) {
      // Re-queue events so they can be retried on the next flush
      this._queue.unshift(...batch);
      // Surface the error but don't crash
      console.error('[ThreatPulse]', err.message || err);
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

module.exports = { ThreatPulse };
