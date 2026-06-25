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

function textInput(id, title, description, defaultValue, attrs) {
	attrs = attrs || {};
	attrs.id = id;
	attrs['class'] = attrs['class'] || 'cbi-input-text';
	attrs.type = attrs.type || 'number';
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
		throw new Error((result && result.error) || _('FMAC advanced configuration failed.'));

	ui.addNotification(null, E('p', [ _('FMAC advanced configuration applied.') ]), 'info');
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
			ifname: value('fmac-advanced-ifname') || 'hg0'
		};

		addValue(config, 'txpower', 'fmac-advanced-txpower');
		addValue(config, 'super_pwr', 'fmac-advanced-super-pwr');
		addValue(config, 'bss_bw', 'fmac-advanced-bss-bw');
		addValue(config, 'agg_tx', 'fmac-advanced-agg-tx');
		addValue(config, 'agg_rx', 'fmac-advanced-agg-rx');
		addValue(config, 'max_txcnt', 'fmac-advanced-max-txcnt');

		return callApplyConfig(config).then(handleResult).catch(function(err) {
			ui.addNotification(null, E('p', [ err.message || err ]), 'danger');
		});
	},

	render: function(data) {
		var cfg = (data && data[0] && data[0].config) || {};
		var status = (data && data[1] && data[1].status) || '';

		return E('div', { 'class': 'cbi-map' }, [
			E('h2', [ _('FMAC Advanced Configuration') ]),
			E('div', { 'class': 'cbi-map-descr' }, [ _('Apply runtime FMAC advanced settings. Empty fields are not sent to the device.') ]),
			E('div', { 'class': 'cbi-section' }, [
				textInput('fmac-advanced-ifname', _('Interface'), _('Default: hg0'), cfg.ifname || 'hg0', { type: 'text' }),
				textInput('fmac-advanced-txpower', _('TX power'), _('Valid backend range: 0 to 20.'), '', { min: '0', max: '20', step: '1' }),
				selectInput('fmac-advanced-super-pwr', _('Super power'), _('Send super_pwr=0 or super_pwr=1.'), [ [ '0', '0' ], [ '1', '1' ] ]),
				selectInput('fmac-advanced-bss-bw', _('BSS bandwidth'), _('Send bss_bw.'), [ [ '1', '1' ], [ '2', '2' ], [ '4', '4' ], [ '8', '8' ] ]),
				textInput('fmac-advanced-agg-tx', _('Aggregate TX count'), _('Sent with aggregate RX count as agg_cnt=<tx>,<rx>.'), '', { min: '0', step: '1' }),
				textInput('fmac-advanced-agg-rx', _('Aggregate RX count'), _('Required when aggregate TX count is set.'), '', { min: '0', step: '1' }),
				textInput('fmac-advanced-max-txcnt', _('Max TX count'), _('Send max_txcnt.'), '', { min: '0', step: '1' })
			]),
			E('div', { 'class': 'cbi-page-actions' }, [
				E('button', { 'class': 'btn cbi-button cbi-button-apply', click: this.handleApply.bind(this) }, [ _('Apply') ])
			]),
			E('h3', [ _('Status') ]),
			E('pre', { 'class': 'cbi-section', style: 'white-space: pre-wrap;' }, [ status || _('No status available.') ])
		]);
	}
});
