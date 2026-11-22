/**
 * Grading half of the red-team kit: same transport as gateway.js, different model.
 *
 * Self-grading (target == grader) hides exactly the failures you care about, and
 * promptfoo does not forward a file provider's `config` block, so the grader model is
 * selected with NEX_GRADER_MODEL (default particle-1, fallback codestral-latest) rather
 * than in tests.yaml. Confirm your pick answers 200 on the gateway first: dead upstream keys
 * surface as HTTP 402 subscription_expired.
 */
const GatewayProvider = require('./gateway.js');

class GraderProvider extends GatewayProvider {
  id() {
    return 'gateway-grader';
  }

  modelFor() {
    return process.env.NEX_GRADER_MODEL || 'particle-1';
  }
}

module.exports = GraderProvider;
