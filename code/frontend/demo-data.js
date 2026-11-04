/* Clearly illustrative UI context; case findings come only from the API. */
window.GhostguardDemo = {
  systems: [
    'account_service', 'customer_database', 'orders_database',
    'search_service', 'analytics_platform', 'support_platform', 'backup_service'
  ],
  timeline: [
    ['Deletion request received', 'Request records loaded for audit review'],
    ['Identity resolution', 'Current and historical identifiers matched where available'],
    ['Evidence review', 'Artifacts filtered against each audit cutoff'],
    ['Remediation plan', 'Proposed actions remain pending external execution']
  ]
};
