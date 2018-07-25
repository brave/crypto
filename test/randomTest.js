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

function trials (t, name, ntrials, npassesMin, f) {
  let npass = 0
  let trial
  for (trial = 0; npass < npassesMin && trial < ntrials; trial++) {
    if (f()) {
      npass++
    }
  }
  t.ok(npass >= npassesMin, `${npass} of ${trial} ${name} trials`)
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
  trials(t, 'psi', NTRIALS, NPASSES_MIN, () => {
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
  trials(t, 'psi reject', NTRIALS, NTRIALS - NPASSES_MIN + 1, () => {
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
  t.throws(() => crypto.random.uniform(), ERRPAT)
})

test("uniform('foo') throws", (t) => {
  t.plan(1)
  t.throws(() => crypto.random.uniform('foo'), ERRPAT)
})

test('uniform(0) throws', (t) => {
  t.plan(1)
  t.throws(() => crypto.random.uniform(0), ERRPAT)
})

test('uniform(0.5) throws', (t) => {
  t.plan(1)
  t.throws(() => crypto.random.uniform(0.5), ERRPAT)
})

// round(2**53 + 1) = 2**53, but round(2**53 + 2) > 2**53
test('uniform(2**53 + 2) throws', (t) => {
  t.plan(1)
  t.throws(() => crypto.random.uniform((2 ** 53) + 2), ERRPAT)
})

test('uniform(1) yields 0', (t) => {
  t.plan(1)
  t.equal(0, crypto.random.uniform(1))
})

test('uniform(2**53) does not throw', (t) => {
  t.plan(1)
  t.doesNotThrow(() => crypto.random.uniform(2 ** 53))
})

test('uniform(DF) passes psi test for uniform distribution', (t) => {
  psiTest(t, i => 1 / DF, () => crypto.random.uniform(DF))
})

// Empirically confirm that the psi test has enough statistical power
// to detect modulo bias in the above test.
test('uniform(2*DF + 1) % DF fails psi test for uniform distribution', (t) => {
  psiTestReject(t, i => 1 / DF, () => crypto.random.uniform((2 * DF) + 1) % DF)
})

test('uniform(256) % DF passes psi test for modulo bias', (t) => {
  psiTest(t, i => (Math.floor(256 / DF) + (i < 256 % DF)) / 256, () => {
    return crypto.random.uniform(256) % DF
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
      const x = crypto.random.uniform(2 ** 53)
      return (0xff & Math.floor(x / (2 ** b))) % DF
    })
  })
}

test(`bits [45..53) of uniform(2**53) pass psi test for uniform distribution`, (t) => {
  psiTest(t, i => (Math.floor(256 / DF) + (i < 256 % DF)) / 256, () => {
    return (0xff & Math.floor(crypto.random.uniform(2 ** 53) / (2 ** 45))) % DF
  })
})

// Like uniform_01, but limited to binary16 numbers with 11 bits of
// precision.
function uniform_01_lowprec () { // eslint-disable-line camelcase
  function uniform16 () {
    const b = nacl.randomBytes(2)
    return (b[0] | (b[1] << 8)) >>> 0
  }

  // Draw an exponent with geometric distribution.  Here emin = -14,
  // so 16 bits is plenty.
  const e = Math.clz32(uniform16()) - 16

  // Draw normal odd 16-bit significand with uniform distribution.
  const s0 = (uniform16() | 0x8001) >>> 0

  // Round to an 11-bit significand in [2^15, 2^16], yielding a
  // significand that is a multiple of 2^(16 - 11) = 2^5.
  const hack = 3 * (2 ** (16 - 11 + 53 - 2))
  const s = (s0 + hack) - hack

  // Scale into [1/2, 1] and apply the exponent.
  return s * (2 ** (-16 - e))
}

// Like uniform_01_lowprec, but with a bug: numbers <2^-11 excluded,
// as if you used the naive approach for sampling IEEE 754-2008
// binary16 numbers in [0,1] that many people use for binary64
// numbers.
function baduniform_01_lowprec () { // eslint-disable-line camelcase
  return crypto.random.uniform(2 ** 11) / (2 ** 11)
}

// Like uniform_01, but with a bug: wrong shift amount.
function baduniform_01_badshift () { // eslint-disable-line camelcase
  function uniform32 () {
    const b = nacl.randomBytes(4)
    return (b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 25)) >>> 0
  }

  // Draw an exponent with geometric distribution.
  let e = 0
  let x
  while (e < 1088) {
    if ((x = uniform32()) !== 0) {
      break
    }
    e += 32
  }
  e += Math.clz32(x)

  // Draw normal odd 64-bit significand with uniform distribution.
  const hi = (uniform32() | 0x80000000) >>> 0
  const lo = (uniform32() | 0x00000001) >>> 0

  // Assemble parts into [2^63, 2^64) with uniform distribution.
  // Using an odd low part breaks ties in the rounding, which should
  // occur only in a set of measure zero.
  const s = hi * (2 ** 32) + lo

  // Scale into [1/2, 1) and apply the exponent.
  return s * (2 ** (-64 - e))
}

function reject (x0, f) {
  let x
  do {
    x = f()
  } while (x === x0)
  return x
}

// It had better appear uniformly distributed to psi.  The
// distribution is not exact, but the error of each bucket's
// probability from 1/DF is so small it is insignificant here.
test('uniform_01() passes psi test for uniformly spaced buckets', (t) => {
  psiTest(t, i => 1 / DF, () => {
    return Math.floor(reject(1, crypto.random.uniform_01) * DF)
  })
})

// dist16[i] = Pr[i/100 <= min(fp16(U), 99) < (i + 1)/100], where
// fp16(U) is the standard rounding to a binary16 floating-point
// number of a uniform random real in [0,1].
const dist16 = [
  9.993438720703124e-3, 9.993438720703124e-3,
  0.0100048828125, 0.00998199462890625,
  0.0100048828125, 0.0100048828125,
  0.0099591064453125, 0.0100048828125,
  0.0100048828125, 0.0100048828125,
  0.0100048828125, 0.0100048828125,
  0.009913330078125, 0.0100048828125,
  0.0100048828125, 0.0100048828125,
  0.0100048828125, 0.0100048828125,
  0.0100048828125, 0.0100048828125,
  0.0100048828125, 0.0100048828125,
  0.0100048828125, 0.0100048828125,
  0.00994384765625, 0.0098828125,
  0.0100048828125, 0.0100048828125,
  0.0100048828125, 0.0100048828125,
  0.0100048828125, 0.0100048828125,
  0.0100048828125, 0.0100048828125,
  0.0100048828125, 0.0100048828125,
  0.0100048828125, 0.0100048828125,
  0.0100048828125, 0.0100048828125,
  0.0100048828125, 0.0100048828125,
  0.0100048828125, 0.0100048828125,
  0.0100048828125, 0.0100048828125,
  0.0100048828125, 0.0100048828125,
  0.0100048828125, 0.0098828125,
  0.0098828125, 0.0098828125,
  0.010126953125, 0.0098828125,
  0.010126953125, 0.0098828125,
  0.010126953125, 0.0098828125,
  0.010126953125, 0.0098828125,
  0.010126953125, 0.0098828125,
  0.010126953125, 0.0098828125,
  0.010126953125, 0.0098828125,
  0.010126953125, 0.0098828125,
  0.010126953125, 0.0098828125,
  0.010126953125, 0.0098828125,
  0.010126953125, 0.0098828125,
  0.010126953125, 0.0098828125,
  0.0098828125, 0.010126953125,
  0.0098828125, 0.010126953125,
  0.0098828125, 0.010126953125,
  0.0098828125, 0.010126953125,
  0.0098828125, 0.010126953125,
  0.0098828125, 0.010126953125,
  0.0098828125, 0.010126953125,
  0.0098828125, 0.010126953125,
  0.0098828125, 0.010126953125,
  0.0098828125, 0.010126953125,
  0.0098828125, 0.010126953125,
  0.0098828125, 0.01037109375
]

// The low-precision variant had better appear uniformly distributed
// to psi, at least as uniform as binary16 floating-point arithmetic
// can be, which is nonuniform enough we need to compute it more
// precisely in the dist16 table.
test('uniform_01_lowprec() passes psi test for uniformly spaced buckets', (t) => {
  psiTest(t, i => dist16[i], () => {
    const x = uniform_01_lowprec()
    for (let i = 0; i < DF; i++) {
      if (x < (i + 1) / DF) {
        return i
      }
    }
    assert(x === 1)
    return DF - 1
  })
})

// Test that in 100000 samples we get at least one nonzero sample
// below 2^-11 is somewhere between 2^-11 and 2^-12, say 2^-12 to be
// conservative; the probability of a sample failing this criterion is
// then at most 1 - 2^-12; the probability of _all_ samples failing
// this criterion, i.e. a spurious failure of the test, is at most
//
//      (1 - 2^-12)^100000 ~= 2 * 10^-11 < 10^-10.
//
// This is not zero, but it's close enough for a test suite like this,
// and far below the spurious failure probability of 0.0001 for other
// tests here!
test('uniform_01_lowprec() passes small number test', (t) => {
  t.plan(1)
  trials(t, 'small number', NTRIALS, NPASSES_MIN, () => {
    for (let i = 0; i < NSAMPLES; i++) {
      const x = uniform_01_lowprec()
      if (x > 0 && x < 2 ** -11) {
        return true
      }
    }
    return false
  })
})

// baduniform_01_lowprec() may return 0, but it will never return
// anything 0 < x < 2^-11.
test('baduniform_01_lowprec() fails small number test', (t) => {
  t.plan(1)
  trials(t, 'small number', NTRIALS, NTRIALS - NPASSES_MIN + 1, () => {
    for (let i = 0; i < NSAMPLES; i++) {
      const x = baduniform_01_lowprec()
      if (x > 0 && x < 2 ** -11) {
        return false
      }
    }
    return true
  })
})

// If we discard some bits of the full-precision uniform_01(), it
// should continue to pass psi.
test('(uniform_01()*64)%1 passes psi test for uniformly spaced buckets', (t) => {
  psiTest(t, i => 1 / DF, () => {
    return Math.floor(((reject(1, crypto.random.uniform_01) * 64) % 1) * DF)
  })
})

// Another pathology.
test('baduniform_01_badshift() fails psi test for uniformly spaced buckets', (t) => {
  psiTestReject(t, i => 1 / DF, () => {
    return Math.floor(reject(1, baduniform_01_badshift) * DF)
  })
})
