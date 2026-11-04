const test = require('node:test');
const assert = require('node:assert/strict');
const { csv, deletionIntent, explainFinding } = require('../server');

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

test('remaining-record explanation names the affected system and policy treatment', () => {
  const result = explainFinding({op:'REPORT_REMAINING_RECORD',system:'search_service',resource:'search_001',category:'SEARCH_INDEX_ENTRY'},'DELETE');
  assert.match(result.reason,/search_service/);
  assert.match(result.reason,/delete/);
  assert.match(result.recommended_action,/absent/);
});

test('restore-risk explanation identifies the resource and verification action', () => {
  const result = explainFinding({op:'REPORT_RESTORE_RISK',system:'backup_service',resource:'backup_4978',category:'BACKUP_ARCHIVE'},'RETAIN');
  assert.match(result.reason,/backup_4978/);
  assert.match(result.recommended_action,/restore path/);
});

