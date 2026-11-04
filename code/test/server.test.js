const test = require('node:test');
const assert = require('node:assert/strict');
const { csv, deletionIntent } = require('../server');

test('CSV parser handles quoted commas and escaped quotes', () => {
  const rows = csv('case_id,request_text\ncase_1,"Please delete, erase, and say ""done""."\n');
  assert.deepEqual(rows, [{ case_id:'case_1', request_text:'Please delete, erase, and say "done".' }]);
});

test('deletion intent accepts clear delete language', () => {
  assert.equal(deletionIntent('Please erase my account and delete associated personal data.'), true);
  assert.equal(deletionIntent('Quiero eliminar mi cuenta.'), true);
});

test('non-deletion requests are not treated as deletion', () => {
  assert.equal(deletionIntent('Please export my account data.'), false);
  assert.equal(deletionIntent('Update my account email; do not delete it.'), false);
  assert.equal(deletionIntent('Please unsubscribe me from marketing.'), false);
});

