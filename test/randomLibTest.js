const random = require('../random-lib')
const test = require('tape')

const ERRPAT0 = /integers from -2\^53 to 2\^53/
const ERRPAT1 = /Bounds must be ascending/
const ERRPAT2 = /Bounds must not differ by more than 2\^53/

test('randomInt with missing max throws', t => {
  t.plan(1)
  t.throws(() => random.randomInt({min: 123}), ERRPAT0)
})

test('randomInt with fractional min throws', t => {
  t.plan(1)
  t.throws(() => random.randomInt({min: 1.5, max: 123}), ERRPAT0)
})

test('randomInt with fractional max throws', t => {
  t.plan(1)
  t.throws(() => random.randomInt({min: 1, max: 123.5}), ERRPAT0)
})

test('randomInt with excessive min throws', t => {
  t.plan(1)
  t.throws(() => random.randomInt({min: -(2 ** 53) - 2, max: 123}), ERRPAT0)
})

test('randomInt with excessive max throws', t => {
  t.plan(1)
  t.throws(() => random.randomInt({min: 1, max: 2 ** 53 + 2}), ERRPAT0)
})

test('randomInt with disordered min/max throws', t => {
  t.plan(1)
  t.throws(() => random.randomInt({min: 2, max: 1}), ERRPAT1)
})

test('randomInt with equal min/max throws', t => {
  t.plan(1)
  t.throws(() => random.randomInt({min: 2, max: 2}), ERRPAT1)
})

// We could do this, but it would require extra work, and nobody cares.
test('randomInt with excessively distant min/max throws #1', t => {
  t.plan(1)
  t.throws(() => random.randomInt({min: -1, max: 2 ** 53}), ERRPAT2)
})

test('randomInt with excessively distant min/max throws #2', t => {
  t.plan(1)
  t.throws(() => random.randomInt({min: -(2 ** 53), max: 2 ** 53}), ERRPAT2)
})

test('randomInt with excessively distant min/max throws', t => {
  t.plan(1)
  t.throws(() => random.randomInt({min: -(2 ** 53), max: 2 ** 53}), ERRPAT2)
})

test(`randomInt defaults to min=0`, t => {
  t.plan(1)
  t.equal(27, random.randomInt({max: 32, uniform: n => 27}))
})

for (let i = 0; i < 3; i++) {
  const min = 42
  const max = 45
  test(`randomInt({min: ${min}, max: ${max}}) [${i}] gives ${i + min}`, t => {
    t.plan(1)
    t.equal(i + min, random.randomInt({min: min, max: max, uniform: n => i}))
  })
}
