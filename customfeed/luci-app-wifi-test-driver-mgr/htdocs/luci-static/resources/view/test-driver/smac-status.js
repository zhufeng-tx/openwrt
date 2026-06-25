'use strict';
'require view';
'require dom';
'require poll';
'require rpc';

var callSmacStatus = rpc.declare({
	object: 'luci.test_driver',
	method: 'smac_status',
	expect: { status: '' }
});

return view.extend({
	load: function() {
		return L.resolveDefault(callSmacStatus(), '');
	},

	render: function(status) {
		var statusNode = E('pre', {
			'style': 'font-family:monospace; white-space:pre; overflow-x:auto; ' +
			         'background:#f9f9f9; border:1px solid #ccc; padding:10px; min-height:200px'
		}, [ status || _('Driver not loaded') ]);

		poll.add(function() {
			return L.resolveDefault(callSmacStatus(), '').then(function(result) {
				dom.content(statusNode, result || _('Driver not loaded'));
			});
		}, 3);

		return E('div', {}, [
			E('h2', {}, _('SMAC Driver Status')),
			statusNode
		]);
	},

	handleSaveApply: null,
	handleSave: null,
	handleReset: null
});
