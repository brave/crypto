'use strict'

const assert = require('assert')
const crypto = require('../index')
const nacl = require('tweetnacl')
const test = require('tape')

/*
 * We apply a psi test to various distributions related to our uniform
 * sampler.
 *
 * The psi test, also known as the G-test, is similar to the chi^2
 * test, and is preferred by everyone's favourite Bayesian polemicist
 * Jaynes, who discusses it in Secs. 9.11.1--9.12 of his book on
 * pp. 296--301.
 *
 * Scaled appropriately, the psi test statistic converges to a chi^2
 * distribution as the number of samples grows without bound, so we
 * can use standard tables of chi^2 critical values.  I picked 100
 * degrees of freedom because that's the highest number in the NIST's
 * table:
 *
 *      NIST/SEMATECH e-Handbook of Statistical Methods,
 *      Sec. 1.3.6.7.4: Critical Values of the Chi-Square Distribution,
 *      <https://www.itl.nist.gov/div898/handbook/eda/section3/eda3674.htm>,
 *      April 2012, retrieved 2018-07-23.
 *
 * We choose a significance level alpha = 0.01, meaning there is a 1%
 * probability of spuriously reporting failure for any individual
 * trial of a psi test.  Since there are many tests in this suite, the
 * probability of a spurious test _suite_ failure in n cases is
 *
 *      1 - Binom(0; n, alpha) = 1 - (1 - alpha)^n,
 *
 * which grows rapidly as n grows.  To keep it smaller, at some cost
 * in statistical power to detect errors, we further try each psi test
 * for t trials and allow the test to pass as long as at least k
 * trials pass, so that it is as if each test's spurious failure
 * probability were
 *
 *      1 - \sum_{i=k}^t Binom(i; t, alpha).
 *
 * In the case of t = 2 trials of which k = 1 must pass, this is
 * alpha^2, and the spurious probability failure n tests is
 *
 *      1 - (1 - alpha^2)^n.
 *
 * With fifty tests, this is 1 - (1 - 0.0001)^50 < .499%.
 *
 * NOTE: Some of these tests have the reverse sense: rather than being
 * hypothesis tests trying to reject the null hypothesis of working
 * code, they are hypothesis tests trying to reject the null
 * hypothesis of _specific bugs_ which serve as alternative hypotheses
 * for the ordinary tests, and as such their significance level is the
 * complement of the _statistical power_ of the ordinary tests.  We do
 * this to test the tests for whether they actually test anything.
 *
 * I don't know what that statistical power is -- it may be easy to
 * compute in some cases, but often it isn't known analytically even
 * by Serious Statisticians with strings of letters after their names.
 * Empirically, with dozens of runs, it seems to be high enough, and
 * likely exceeds 99%.
 */

const NSAMPLES = 100000
const DF = 100
const CHI2_CRITICAL = 135.807
const NPASSES_MIN = 1
const NTRIALS = 2

function trials (t, name, f) {
  let npass = 0
  let trial
  for (trial = 0; npass < NPASSES_MIN && trial < NTRIALS; trial++) {
    if (f()) {
      npass++
    }
  }
  t.ok(npass >= NPASSES_MIN, `${npass} of ${trial} ${name} trials`)
}

function psi (C, P, n) {
  assert.strictEqual(DF, C.length)
  assert.strictEqual(DF, P.length)
  let psi = 0
  for (let i = 0; i < DF; i++) {
    if (C[i] === 0) {
      continue
    }
    assert(C[i] > 0)
    psi += C[i] * Math.log(C[i] / (n * P[i]))
  }
  psi *= 2
  return psi
}

function psiTest (t, probability, sample) {
  t.plan(1)
  const P = new Float64Array(DF) // probability
  for (let i = 0; i < DF; i++) {
    P[i] = probability(i)
  }
  trials(t, 'psi', () => {
    const C = new Uint32Array(DF) // count
    for (let s = 0; s < NSAMPLES; s++) {
      C[sample()]++
    }
    return psi(C, P, NSAMPLES) <= CHI2_CRITICAL
  })
}

function psiTestReject (t, probability, sample) {
  t.plan(1)
  const P = new Float64Array(DF) // probability
  for (let i = 0; i < DF; i++) {
    P[i] = probability(i)
  }
  trials(t, 'psi reject', () => {
    const C = new Uint32Array(DF) // count
    for (let s = 0; s < NSAMPLES; s++) {
      C[sample()]++
    }
    return psi(C, P, NSAMPLES) > CHI2_CRITICAL
  })
}

// Like uniform, but with a bug: wrong shift.
function baduniform (n) {
  if (typeof n !== 'number' || n % 1 !== 0 || n <= 0 || n > (2 ** 53)) {
    throw new Error('Bound must be positive integer at most 2^53.')
  }
  const min = (2 ** 53) % n
  let x
  do {
    const b = nacl.randomBytes(7)
    const l32 = b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 26)
    const h21 = b[4] | (b[5] << 8) | ((b[6] & 0x1f) << 16)
    x = (2 ** 32) * h21 + l32
  } while (x < min)
  return x % n
}

const ERRPAT = /Bound must be positive integer at most 2\^53\./

test('uniform() throws', (t) => {
  t.plan(1)
  t.throws(() => crypto.uniform(), ERRPAT)
})

test("uniform('foo') throws", (t) => {
  t.plan(1)
  t.throws(() => crypto.uniform('foo'), ERRPAT)
})

test('uniform(0) throws', (t) => {
  t.plan(1)
  t.throws(() => crypto.uniform(0), ERRPAT)
})

test('uniform(0.5) throws', (t) => {
  t.plan(1)
  t.throws(() => crypto.uniform(0.5), ERRPAT)
})

// round(2**53 + 1) = 2**53, but round(2**53 + 2) > 2**53
test('uniform(2**53 + 2) throws', (t) => {
  t.plan(1)
  t.throws(() => crypto.uniform((2 ** 53) + 2), ERRPAT)
})

test('uniform(1) yields 0', (t) => {
  t.plan(1)
  t.equal(0, crypto.uniform(1))
})

test('uniform(2**53) does not throw', (t) => {
  t.plan(1)
  t.doesNotThrow(() => crypto.uniform(2 ** 53))
})

test('uniform(DF) passes psi test for uniform distribution', (t) => {
  psiTest(t, i => 1 / DF, () => crypto.uniform(DF))
})

// Empirically confirm that the psi test has enough statistical power
// to detect modulo bias in the above test.
test('uniform(2*DF + 1) % DF fails psi test for uniform distribution', (t) => {
  psiTestReject(t, i => 1 / DF, () => crypto.uniform((2 * DF) + 1) % DF)
})

test('uniform(256) % DF passes psi test for modulo bias', (t) => {
  psiTest(t, i => (Math.floor(256 / DF) + (i < 256 % DF)) / 256, () => {
    return crypto.uniform(256) % DF
  })
})

// Why do we test the bits?  Because I made this error:
//
//      const l32 = b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 26)
//
// And it was _not_ caught by the above uniform tests.

test('bits [24..32) of bad uniform fail psi test for uniform distribution', (t) => {
  psiTestReject(t, i => (Math.floor(256 / DF) + (i < 256 % DF)) / 256, () => {
    return (0xff & Math.floor(baduniform(2 ** 53) / (2 ** 24))) % DF
  })
})

for (let b = 0; b < 53 - 8; b += 8) {
  test(`bits [${b}..${b + 8}) of uniform(2**53) pass psi test for uniform distribution`, (t) => {
    psiTest(t, i => (Math.floor(256 / DF) + (i < 256 % DF)) / 256, () => {
      return (0xff & Math.floor(crypto.uniform(2 ** 53) / (2 ** b))) % DF
    })
  })
}

test(`bits [45..53) of uniform(2**53) pass psi test for uniform distribution`, (t) => {
  psiTest(t, i => (Math.floor(256 / DF) + (i < 256 % DF)) / 256, () => {
    return (0xff & Math.floor(crypto.uniform(2 ** 53) / (2 ** 45))) % DF
  })
})
