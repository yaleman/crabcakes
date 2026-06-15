import assert from 'node:assert/strict';
import test from 'node:test';

import { methodForPolicyAction } from '../../target/js/js/policy-action.js';

test('create policy forms use POST', () => {
    assert.equal(methodForPolicyAction('create'), 'POST');
});

test('edit policy forms use PUT', () => {
    assert.equal(methodForPolicyAction('edit'), 'PUT');
});

test('unknown policy form actions fail instead of falling back to POST', () => {
    assert.throws(
        () => methodForPolicyAction('update'),
        /Unknown policy action: update/,
    );
});
