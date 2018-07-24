const crypto = require('./index')

/**
 * Sample uniformly at random from integers {min, min+1, ..., max-1}.
 * API compatible with npm random-lib 2.1.0.
 *
 * @param {object} opts - options
 * @param {number} opts.min - inclusive lower bound on result
 * @param {number} opts.max - exclusive upper bound on result
 * @returns {number}
 */
module.exports.randomInt = function (opts) {
  const min = opts.min || 0 // inclusive
  const max = opts.max // exclusive
  const uniform = opts.uniform || crypto.random.uniform // for testing only
  if (typeof min !== 'number' || min % 1 !== 0 || min < -Math.pow(2, 53) ||
      typeof max !== 'number' || max % 1 !== 0 || max > Math.pow(2, 53) ||
      min >= max) {
    throw new Error('Bounds must be ascending integers from -2^53 to 2^53.')
  }
  if (max - (min + 1) >= Math.pow(2, 53)) {
    throw new Error('Bounds must not differ by more than 2^53.')
  }
  return min + uniform(max - min)
}
