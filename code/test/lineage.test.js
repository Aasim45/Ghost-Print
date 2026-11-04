const test = require('node:test');
const assert = require('node:assert/strict');
const { buildLineageGraph, isResourceId } = require('../server');

const evidenceFiles = [
  { file_id:'evidence_1', file_path:'evidence/records/source.json', origin:'inventory', captured_at:'2026-09-01T10:00:00Z' },
  { file_id:'evidence_2', file_path:'evidence/records/target.json', origin:'replica scan', captured_at:'2026-09-02T10:00:00Z' }
];

test('lineage filters system labels and aggregates repeat observations by system and resource', () => {
  assert.equal(isResourceId('support_platform'), false);
  const obs = [
    { resource:'support_9538', system_id:'support_platform', evidence:evidenceFiles[0], object:{resource_id:'support_9538',record_type:'SUPPORT_MESSAGE',state:'PRESENT'} },
    { resource:'support_9538', system_id:'support_platform', evidence:evidenceFiles[1], object:{resource_id:'support_9538',record_type:'SUPPORT_MESSAGE',state:'PRESENT'} }
  ];
  const graph = buildLineageGraph({case_id:'case_34',deletion_status:'INCOMPLETE',findings:[],steps:[]},{audit_at:'2026-09-03T00:00:00Z'},obs,evidenceFiles);
  assert.equal(graph.nodes.length,1);
  assert.equal(graph.nodes[0].id,'support_platform::support_9538');
  assert.deepEqual(graph.nodes[0].evidence_ids,['evidence_1','evidence_2']);
  assert.equal(graph.nodes[0].resource_id,'support_9538');
  assert.equal(graph.edges.length,0);
});

test('lineage adds a directed edge only for explicit, resolvable evidence endpoints', () => {
  const obs = [
    {resource:'account_1',system_id:'account_service',evidence:evidenceFiles[0],object:{resource_id:'account_1',system:'account_service',state:'PRESENT',source_resource_id:'account_1',source_system:'account_service',target_resource_id:'search_2',target_system:'search_service',relationship_type:'INDEXED_TO'}},
    {resource:'search_2',system_id:'search_service',evidence:evidenceFiles[1],object:{resource_id:'search_2',system:'search_service',state:'PRESENT'}}
  ];
  const graph = buildLineageGraph({case_id:'case_1',deletion_status:'INCOMPLETE',findings:[],steps:[]},{audit_at:'2026-09-03T00:00:00Z'},obs,evidenceFiles);
  assert.equal(graph.nodes.length,2);
  assert.equal(graph.edges.length,1);
  assert.equal(graph.edges[0].source,'account_service::account_1');
  assert.equal(graph.edges[0].target,'search_service::search_2');
  assert.equal(graph.edges[0].type,'INDEXED_TO');
});

test('lineage drops self-edges and references to resources outside the case graph', () => {
  const obs = [{resource:'account_1',system_id:'account_service',evidence:evidenceFiles[0],object:{resource_id:'account_1',source_resource_id:'account_1',target_resource_id:'account_1',relationship_type:'SELF'}}];
  const graph = buildLineageGraph({case_id:'case_1',deletion_status:'INCOMPLETE',findings:[],steps:[]},{audit_at:'2026-09-03T00:00:00Z'},obs,evidenceFiles);
  assert.equal(graph.edges.length,0);
});
