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
		throw new Error((result && result.error) || _('FMAC channel configuration failed.'));

	ui.addNotification(null, E('p', [ _('FMAC channel configuration applied.') ]), 'info');
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
			ifname: value('fmac-channel-ifname') || 'hg0'
		};

		addValue(config, 'acs_enable', 'fmac-channel-acs-enable');
		addValue(config, 'acs_timeout', 'fmac-channel-acs-timeout');
		addValue(config, 'chan_list_mhz', 'fmac-channel-list');
		addValue(config, 'freq_start_mhz', 'fmac-channel-start');
		addValue(config, 'freq_end_mhz', 'fmac-channel-end');
		addValue(config, 'freq_bw_mhz', 'fmac-channel-bw');

		return callApplyConfig(config).then(handleResult).catch(function(err) {
			ui.addNotification(null, E('p', [ err.message || err ]), 'danger');
		});
	},

	render: function(data) {
		var cfg = (data && data[0] && data[0].config) || {};
		var status = (data && data[1] && data[1].status) || '';
		var freqHelp = _('Enter MHz with optional 0.1 MHz precision. Examples: 908 MHz → 9080, 908.5 MHz → 9085.');

		return E('div', { 'class': 'cbi-map' }, [
			E('h2', [ _('FMAC Channel Configuration') ]),
			E('div', { 'class': 'cbi-map-descr' }, [ _('Apply runtime FMAC channel settings. Empty fields are not sent to the device.') ]),
			E('div', { 'class': 'cbi-section' }, [
				textInput('fmac-channel-ifname', _('Interface'), _('Default: hg0'), cfg.ifname || 'hg0'),
				selectInput('fmac-channel-acs-enable', _('ACS enable'), _('Send acs=<enable>,<timeout> together with ACS timeout.'), [ [ '0', '0' ], [ '1', '1' ] ]),
				textInput('fmac-channel-acs-timeout', _('ACS timeout'), _('Required when ACS enable is set.'), '', 'number', { min: '0', step: '1' }),
				textInput('fmac-channel-list', _('Channel list'), freqHelp + ' ' + _('Comma separated, for example: 908,908.5.'), ''),
				textInput('fmac-channel-start', _('Frequency start'), freqHelp, '', 'number', { min: '0', step: '0.1' }),
				textInput('fmac-channel-end', _('Frequency end'), freqHelp, '', 'number', { min: '0', step: '0.1' }),
				textInput('fmac-channel-bw', _('Frequency bandwidth'), _('MHz value for the freq_range bw argument; this value is not multiplied by 10.'), '', 'number', { min: '0', step: '0.1' })
			]),
			E('div', { 'class': 'cbi-page-actions' }, [
				E('button', { 'class': 'btn cbi-button cbi-button-apply', click: this.handleApply.bind(this) }, [ _('Apply') ])
			]),
			E('h3', [ _('Status') ]),
			E('pre', { 'class': 'cbi-section', style: 'white-space: pre-wrap;' }, [ status || _('No status available.') ])
		]);
	}
});
