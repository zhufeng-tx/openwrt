'use strict';
'require view';
'require rpc';
'require ui';

var callGetConfig = rpc.declare({
	object: 'luci.fmac_config',
	method: 'get_config',
	params: [ 'ifname' ]
});

var callGetStatus = rpc.declare({
	object: 'luci.fmac_config',
	method: 'get_status',
	params: [ 'ifname' ]
});

var callApplyConfig = rpc.declare({
	object: 'luci.fmac_config',
	method: 'apply_config',
	params: [ 'config' ]
});

function value(id) {
	var node = document.getElementById(id);
	return node ? node.value.trim() : '';
}

function addValue(config, key, id) {
	var v = value(id);

	if (v !== '')
		config[key] = v;
}

function optionList(options) {
	var nodes = [ E('option', { value: '' }, [ _('Skip') ]) ];

	for (var i = 0; i < options.length; i++)
		nodes.push(E('option', { value: options[i][0] }, [ options[i][1] ]));

	return nodes;
}

function textInput(id, title, description, defaultValue, type, attrs) {
	attrs = attrs || {};
	attrs.id = id;
	attrs['class'] = attrs['class'] || 'cbi-input-text';
	attrs.type = type || 'text';
	attrs.value = defaultValue || '';

	return E('div', { 'class': 'cbi-value' }, [
		E('label', { 'class': 'cbi-value-title', 'for': id }, [ title ]),
		E('div', { 'class': 'cbi-value-field' }, [
			E('input', attrs),
			description ? E('div', { 'class': 'cbi-value-description' }, [ description ]) : ''
		])
	]);
}

function selectInput(id, title, description, options) {
	return E('div', { 'class': 'cbi-value' }, [
		E('label', { 'class': 'cbi-value-title', 'for': id }, [ title ]),
		E('div', { 'class': 'cbi-value-field' }, [
			E('select', { id: id, 'class': 'cbi-input-select' }, optionList(options)),
			description ? E('div', { 'class': 'cbi-value-description' }, [ description ]) : ''
		])
	]);
}

function handleResult(result) {
	if (!result || result.code !== 0)
		throw new Error((result && result.error) || _('FMAC multicast configuration failed.'));

	ui.addNotification(null, E('p', [ _('FMAC multicast configuration applied.') ]), 'info');
}

return view.extend({
	load: function() {
		return Promise.all([
			callGetConfig('hg0').catch(function() { return {}; }),
			callGetStatus('hg0').catch(function() { return {}; })
		]);
	},

	handleApply: function() {
		var config = {
			ifname: value('fmac-mcast-ifname') || 'hg0'
		};

		addValue(config, 'mcast_key', 'fmac-mcast-key');
		addValue(config, 'join_group_mac', 'fmac-mcast-join-mac');
		addValue(config, 'join_group_aid', 'fmac-mcast-join-aid');
		addValue(config, 'mcast_dupcnt', 'fmac-mcast-dupcnt');
		addValue(config, 'mcast_tx_bw', 'fmac-mcast-tx-bw');
		addValue(config, 'mcast_tx_mcs', 'fmac-mcast-tx-mcs');
		addValue(config, 'mcast_clearch', 'fmac-mcast-clearch');

		return callApplyConfig(config).then(handleResult).catch(function(err) {
			ui.addNotification(null, E('p', [ err.message || err ]), 'danger');
		});
	},

	render: function(data) {
		var cfg = (data && data[0] && data[0].config) || {};
		var status = (data && data[1] && data[1].status) || '';
		var mcsOptions = [ [ '1', '1' ], [ '2', '2' ], [ '3', '3' ], [ '4', '4' ], [ '5', '5' ], [ '6', '6' ], [ '7', '7' ], [ '255', _('255 (auto)') ] ];
		var bwOptions = [ [ '1', '1' ], [ '2', '2' ], [ '4', '4' ], [ '8', '8' ] ];

		return E('div', { 'class': 'cbi-map' }, [
			E('h2', [ _('FMAC Multicast Configuration') ]),
			E('div', { 'class': 'cbi-map-descr' }, [ _('Apply runtime FMAC multicast settings. Empty fields are not sent to the device.') ]),
			E('div', { 'class': 'cbi-section' }, [
				textInput('fmac-mcast-ifname', _('Interface'), _('Default: hg0'), cfg.ifname || 'hg0'),
				textInput('fmac-mcast-key', _('Multicast key'), _('Send mcast_key.'), ''),
				textInput('fmac-mcast-join-mac', _('Join group MAC'), _('Sent with AID as join_group=<mac>,<aid>.'), ''),
				textInput('fmac-mcast-join-aid', _('Join group AID'), _('Required when join group MAC is set.'), '', 'number', { min: '0', step: '1' }),
				textInput('fmac-mcast-dupcnt', _('Multicast duplicate count'), _('Sent with TX bandwidth, TX MCS, and clear channel as mcast_txparam.'), '', 'number', { min: '0', step: '1' }),
				selectInput('fmac-mcast-tx-bw', _('Multicast TX bandwidth'), _('Send mcast_tx_bw.'), bwOptions),
				selectInput('fmac-mcast-tx-mcs', _('Multicast TX MCS'), _('Send mcast_tx_mcs.'), mcsOptions),
				selectInput('fmac-mcast-clearch', _('Multicast clear channel'), _('Send mcast_clearch=0 or mcast_clearch=1.'), [ [ '0', '0' ], [ '1', '1' ] ])
			]),
			E('div', { 'class': 'cbi-page-actions' }, [
				E('button', { 'class': 'btn cbi-button cbi-button-apply', click: this.handleApply.bind(this) }, [ _('Apply') ])
			]),
			E('h3', [ _('Status') ]),
			E('pre', { 'class': 'cbi-section', style: 'white-space: pre-wrap;' }, [ status || _('No status available.') ])
		]);
	}
});
