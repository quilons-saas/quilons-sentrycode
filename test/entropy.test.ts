import assert from 'node:assert/strict';
import test from 'node:test';
import { looksLikeHighEntropySecret, shannonEntropy } from '../src/scanners/secrets/entropy.js';

test('entropy distinguishes repetitive and random-looking values', () => {
  assert.ok(shannonEntropy('aaaaaaaaaaaaaaaaaaaaaaaa') < 1);
  assert.ok(shannonEntropy('aZ93kLm2Pq7Tx4Vn8Rs1Yu5W') > 4);
});

test('high entropy detector requires minimum length and mixed character classes', () => {
  assert.equal(looksLikeHighEntropySecret('short123', 24), false);
  assert.equal(looksLikeHighEntropySecret('aZ93kLm2Pq7Tx4Vn8Rs1Yu5W', 24), true);
});
