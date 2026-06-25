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

function rawValue(id) {
	var node = document.getElementById(id);
	return node ? node.value : '';
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

function textInput(id, title, description, defaultValue, type) {
	return E('div', { 'class': 'cbi-value' }, [
		E('label', { 'class': 'cbi-value-title', 'for': id }, [ title ]),
		E('div', { 'class': 'cbi-value-field' }, [
			E('input', {
				id: id,
				'class': 'cbi-input-text',
				type: type || 'text',
				value: defaultValue || ''
			}),
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

function pskHex(buffer) {
	return Array.prototype.map.call(new Uint8Array(buffer), function(byte) {
		return ('00' + byte.toString(16)).slice(-2);
	}).join('');
}

function deriveWpaPsk(passphrase, ssid) {
	if (!passphrase)
		return Promise.resolve('');

	if (!window.crypto || !window.crypto.subtle || typeof TextEncoder === 'undefined')
		return Promise.reject(new Error(_('WebCrypto PBKDF2-HMAC-SHA1 support is unavailable in this browser.')));

	if (!ssid)
		return Promise.reject(new Error(_('SSID is required when generating a WPA PSK.')));

	var encoder = new TextEncoder();
	var passphraseBytes = encoder.encode(passphrase);

	if (passphraseBytes.length < 8 || passphraseBytes.length > 63)
		return Promise.reject(new Error(_('WPA passphrase must be 8 to 63 bytes.')));

	return window.crypto.subtle.importKey('raw', passphraseBytes, 'PBKDF2', false, [ 'deriveBits' ]).then(function(key) {
		return window.crypto.subtle.deriveBits({
			name: 'PBKDF2',
			hash: 'SHA-1',
			salt: encoder.encode(ssid),
			iterations: 4096
		}, key, 256);
	}).then(pskHex);
}

function handleResult(result) {
	if (!result || result.code !== 0)
		throw new Error((result && result.error) || _('FMAC configuration failed.'));

	ui.addNotification(null, E('p', [ _('FMAC configuration applied.') ]), 'info');
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
			ifname: value('fmac-basic-ifname') || 'hg0'
		};
		var ssid = value('fmac-basic-ssid');

		addValue(config, 'mode', 'fmac-basic-mode');
		addValue(config, 'ssid', 'fmac-basic-ssid');
		addValue(config, 'ap_hide', 'fmac-basic-ap-hide');
		addValue(config, 'key_mgmt', 'fmac-basic-key-mgmt');
		addValue(config, 'tx_bw', 'fmac-basic-tx-bw');
		addValue(config, 'tx_mcs', 'fmac-basic-tx-mcs');

		return deriveWpaPsk(rawValue('fmac-basic-passphrase'), ssid).then(function(wpaPsk) {
			if (wpaPsk)
				config.wpa_psk = wpaPsk;

			return callApplyConfig(config);
		}).then(handleResult).catch(function(err) {
			ui.addNotification(null, E('p', [ err.message || err ]), 'danger');
		});
	},

	render: function(data) {
		var cfg = (data && data[0] && data[0].config) || {};
		var status = (data && data[1] && data[1].status) || '';

		return E('div', { 'class': 'cbi-map' }, [
			E('h2', [ _('FMAC Basic Configuration') ]),
			E('div', { 'class': 'cbi-map-descr' }, [ _('Apply runtime FMAC settings. Empty fields are not sent to the device.') ]),
			E('div', { 'class': 'cbi-section' }, [
				textInput('fmac-basic-ifname', _('Interface'), _('Default: hg0'), cfg.ifname || 'hg0'),
				selectInput('fmac-basic-mode', _('Mode'), _('Send mode=ap or mode=sta.'), [ [ 'ap', 'ap' ], [ 'sta', 'sta' ] ]),
				textInput('fmac-basic-ssid', _('SSID'), _('Required only when generating a WPA PSK.'), ''),
				selectInput('fmac-basic-ap-hide', _('Hide AP'), _('Send ap_hide=0 or ap_hide=1.'), [ [ '0', '0' ], [ '1', '1' ] ]),
				textInput('fmac-basic-key-mgmt', _('Key management'), _('Example: WPA-PSK. Leave empty to skip.'), ''),
				textInput('fmac-basic-passphrase', _('WPA passphrase'), _('Converted in the browser to a 64-hex WPA PSK; only wpa_psk is sent.'), '', 'password'),
				selectInput('fmac-basic-tx-bw', _('TX bandwidth'), _('Send tx_bw.'), [ [ '1', '1' ], [ '2', '2' ], [ '4', '4' ], [ '8', '8' ] ]),
				selectInput('fmac-basic-tx-mcs', _('TX MCS'), _('Send tx_mcs.'), [ [ '1', '1' ], [ '2', '2' ], [ '3', '3' ], [ '4', '4' ], [ '5', '5' ], [ '6', '6' ], [ '7', '7' ], [ '255', _('255 (auto)') ] ])
			]),
			E('div', { 'class': 'cbi-page-actions' }, [
				E('button', { 'class': 'btn cbi-button cbi-button-apply', click: this.handleApply.bind(this) }, [ _('Apply') ])
			]),
			E('h3', [ _('Status') ]),
			E('pre', { 'class': 'cbi-section', style: 'white-space: pre-wrap;' }, [ status || _('No status available.') ])
		]);
	}
});
