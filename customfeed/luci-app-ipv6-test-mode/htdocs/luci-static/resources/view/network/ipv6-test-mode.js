'use strict';
'require view';
'require poll';
'require rpc';
'require ui';

var callStatus = rpc.declare({
	object: 'luci.ipv6_test',
	method: 'get_status'
});

var callApply = rpc.declare({
	object: 'luci.ipv6_test',
	method: 'apply',
	params: [ 'mode', 'prefix' ]
});

var DEFAULT_PREFIX = 'fd42:6970:7636:1::/64';
var DEFAULT_PD_PREFIX = 'fd42:6970:7636::/48';

var callDisable = rpc.declare({
	object: 'luci.ipv6_test',
	method: 'disable'
});

var DEFAULT_STATUS = {
	ok: false,
	enabled: false,
	mode: 'stateless',
	active_mode: 'degraded',
	prefix: DEFAULT_PREFIX,
	lan_prefix: DEFAULT_PREFIX,
	router_address: 'fd42:6970:7636:1::1',
	dns_address: 'fd42:6970:7636:1::1',
	dns_name: 'router.ipv6.test',
	ra_flags: 'A=1 O=0 M=0',
	address_active: false,
	odhcpd_running: false,
	dnsmasq_running: false,
	forwarding_blocked: false,
	dhcpv6_server_enabled: false,
	dhcpv6_na_enabled: false,
	pd_server_enabled: false,
	mode_configuration_ok: false,
	pd_lease_count: 0,
	delegated_prefix: '',
	delegated_route_active: false,
	client_state: 'disabled',
	client_observed: false,
	client_address: '',
	client_method: '',
	client_neighbor_state: '',
	dhcpv6_bound: false,
	client_error: '',
	error: ''
};

return view.extend({
	selectedMode: 'stateless',
	status: null,
	modeButtons: null,
	statusNode: null,
	prefixInput: null,
	prefixLabel: null,
	prefixHelp: null,
	flowNode: null,
	reconnectNode: null,
	pollFn: null,
	refreshFailed: false,

	load: function() {
		return L.resolveDefault(callStatus(), DEFAULT_STATUS);
	},

	normalizeStatus: function(status) {
		var data = Object.assign({}, DEFAULT_STATUS, status || {});
		var clientStates = [ 'disabled', 'waiting', 'assigned', 'observed', 'error' ];
		data.mode = [ 'stateless', 'stateful', 'stateless_pd' ].indexOf(data.mode) !== -1 ? data.mode : 'stateless';
		data.lan_prefix = String(data.lan_prefix || data.prefix || DEFAULT_PREFIX);
		data.delegated_prefix = String(data.delegated_prefix || '');
		data.client_state = clientStates.indexOf(data.client_state) !== -1 ? data.client_state : 'error';
		data.client_address = String(data.client_address || '');
		data.client_method = data.client_method === 'dhcpv6' ? 'dhcpv6' : data.client_method === 'slaac' ? 'slaac' : '';
		data.client_neighbor_state = String(data.client_neighbor_state || '');
		data.client_error = String(data.client_error || '');
		return data;
	},

	validatePrefix: function(value) {
		var normalized = String(value || '').trim().toLowerCase();
		return /^fd[0-9a-f]{2}(:[0-9a-f]{1,4}){3}::\/64$/.test(normalized) ? normalized : null;
	},

	validatePdPrefix: function(value) {
		var normalized = String(value || '').trim().toLowerCase();
		var patterns = {
			48: /^fd[0-9a-f]{2}(:[0-9a-f]{1,4}){2}::\/48$/,
			52: /^fd[0-9a-f]{2}(:[0-9a-f]{1,4}){2}:[0-9a-f]000::\/52$/,
			56: /^fd[0-9a-f]{2}(:[0-9a-f]{1,4}){2}:[0-9a-f]{2}00::\/56$/,
			60: /^fd[0-9a-f]{2}(:[0-9a-f]{1,4}){2}:[0-9a-f]{3}0::\/60$/
		};
		var length = normalized.split('/')[1];
		return patterns[length] && patterns[length].test(normalized) ? normalized : null;
	},

	statusChip: function(label, active, neutral) {
		return E('div', { 'class': 'v6lab-check ' + (neutral ? 'is-off' : active ? 'is-ok' : 'is-bad') }, [
			E('span', { 'class': 'v6lab-dot', 'aria-hidden': 'true' }),
			E('span', {}, [ label ])
		]);
	},

	clientStateLabel: function(state) {
		switch (state) {
		case 'observed': return _('IPv6 observed');
		case 'assigned': return _('Address assigned');
		case 'waiting': return _('Waiting for client');
		case 'error': return _('Observation unavailable');
		default: return _('Observation inactive');
		}
	},

	clientEvidence: function(status) {
		if (status.client_state === 'error')
			return status.client_error || _('OpenWrt could not read passive client evidence.');
		if (status.client_state === 'disabled')
			return _('Enable IPv6 test mode to observe a client on the isolated LAN.');
		if (status.client_state === 'waiting')
			return status.client_method === 'dhcpv6'
				? _('Waiting for a bound DHCPv6 address from the client.')
				: _('Waiting for the client to use an SLAAC address from this prefix.');
		if (status.client_state === 'assigned')
			return _('DHCPv6 assigned this address, but no matching LAN neighbor is visible yet.');

		var assignment = status.client_method === 'dhcpv6' ? _('DHCPv6 bound') : _('SLAAC');
		var neighbor = status.client_neighbor_state
			? _('NDP %s').format(status.client_neighbor_state)
			: _('NDP observed');
		return _('%s · %s · passive evidence').format(assignment, neighbor);
	},

	renderClientObservation: function(status) {
		var address = status.client_address || _('No client address observed');
		var methodClass = status.client_method ? ' is-' + status.client_method : '';
		return E('div', { 'class': 'v6lab-client' + methodClass }, [
			E('div', { 'class': 'v6lab-client-head' }, [
				E('div', {}, [
					E('div', { 'class': 'v6lab-eyebrow' }, [ _('Client observation') ]),
					E('code', { 'class': status.client_address ? '' : 'is-empty' }, [ address ])
				]),
				E('span', { 'class': 'v6lab-client-state is-' + status.client_state }, [
					this.clientStateLabel(status.client_state)
				])
			]),
			E('div', { 'class': 'v6lab-client-evidence' }, [ this.clientEvidence(status) ])
		]);
	},

	renderDelegationObservation: function(status) {
		if (status.mode !== 'stateless_pd')
			return '';
		var bound = Boolean(status.delegated_prefix);
		var evidence = bound
			? (status.delegated_route_active
				? _('Bound IA_PD lease and downstream route are active.')
				: _('The IA_PD lease is bound, but its downstream route is not visible.'))
			: _('Waiting for a downstream router to request IA_PD.');
		return E('div', { 'class': 'v6lab-client is-pd' }, [
			E('div', { 'class': 'v6lab-client-head' }, [
				E('div', {}, [
					E('div', { 'class': 'v6lab-eyebrow' }, [ _('Delegation observation') ]),
					E('code', { 'class': bound ? '' : 'is-empty' }, [
						status.delegated_prefix || _('No delegated prefix observed')
					])
				]),
				E('span', { 'class': 'v6lab-client-state is-' + (bound && status.delegated_route_active ? 'observed' : 'waiting') }, [
					bound ? _('IA_PD bound') : _('Waiting for router')
				])
			]),
			E('div', { 'class': 'v6lab-client-evidence' }, [ evidence ])
		]);
	},

	renderStatus: function() {
		var status = this.status;
		var pdMode = status.mode === 'stateless_pd';
		var slaacOnly = status.mode === 'stateless';
		var activeLabel = status.enabled
			? (status.active_mode === 'degraded' ? _('Degraded') : pdMode ? _('Stateless + PD') : status.mode === 'stateful' ? _('Stateful') : _('Stateless'))
			: _('Disabled');
		var tone = !status.enabled ? 'is-disabled' : status.ok ? 'is-active' : 'is-degraded';
		var error = status.error
			? E('div', { 'class': 'v6lab-alert is-error' }, [
				E('strong', {}, [ _('Configuration error') ]),
				E('span', {}, [ status.error ])
			])
			: '';
		var refreshWarning = this.refreshFailed
			? E('div', { 'class': 'v6lab-refresh-warning' }, [
				_('Status refresh unavailable; showing the last result.')
			])
			: '';

		return E('div', { 'class': 'v6lab-status' }, [
			E('div', { 'class': 'v6lab-status-head' }, [
				E('div', {}, [
					E('div', { 'class': 'v6lab-eyebrow' }, [ _('IPv6 test environment') ]),
					E('h2', {}, [ _('Offline LAN, observable by design') ])
				]),
				E('span', { 'class': 'v6lab-state ' + tone }, [ activeLabel ])
			]),
			E('div', { 'class': 'v6lab-facts' }, [
				E('div', {}, [ E('span', {}, [ pdMode ? _('Delegation pool') : _('Prefix') ]), E('code', {}, [ status.prefix ]) ]),
				pdMode ? E('div', {}, [ E('span', {}, [ _('LAN /64') ]), E('code', {}, [ status.lan_prefix ]) ]) : '',
				E('div', {}, [ E('span', {}, [ _('Router and DNS') ]), E('code', {}, [ status.router_address ]) ]),
				pdMode ? '' : E('div', {}, [ E('span', {}, [ _('Local DNS name') ]), E('code', {}, [ status.dns_name ]) ])
			]),
			E('div', { 'class': 'v6lab-checks' }, [
				this.statusChip(_('LAN address'), status.address_active, !status.enabled),
				this.statusChip(_('odhcpd'), status.odhcpd_running, !status.enabled),
				slaacOnly ? this.statusChip(
					_('DHCPv6 disabled'),
					!status.dhcpv6_server_enabled && !status.dhcpv6_na_enabled,
					!status.enabled
				) : '',
				pdMode ? this.statusChip(_('PD server'), status.pd_server_enabled, !status.enabled) : '',
				this.statusChip(_('Local DNS'), status.dnsmasq_running, !status.enabled),
				this.statusChip(_('Forwarding blocked'), status.forwarding_blocked, !status.enabled)
			]),
			this.renderDelegationObservation(status),
			this.renderClientObservation(status),
			refreshWarning,
			error
		]);
	},

	refreshStatusNode: function() {
		var replacement = this.renderStatus();
		if (this.statusNode && this.statusNode.parentNode)
			this.statusNode.parentNode.replaceChild(replacement, this.statusNode);
		this.statusNode = replacement;
	},

	refreshStatus: function() {
		return callStatus().then(L.bind(function(result) {
			this.status = this.normalizeStatus(result);
			this.refreshFailed = false;
			this.refreshStatusNode();
		}, this)).catch(L.bind(function() {
			this.refreshFailed = true;
			this.refreshStatusNode();
		}, this));
	},

	setMode: function(mode) {
		this.selectedMode = [ 'stateless', 'stateful', 'stateless_pd' ].indexOf(mode) !== -1 ? mode : 'stateless';
		Object.keys(this.modeButtons || {}).forEach(L.bind(function(key) {
			var selected = key === this.selectedMode;
			this.modeButtons[key].classList.toggle('is-selected', selected);
			this.modeButtons[key].setAttribute('aria-pressed', selected ? 'true' : 'false');
		}, this));
		if (this.prefixInput) {
			if (this.selectedMode === 'stateless_pd' && !this.validatePdPrefix(this.prefixInput.value))
				this.prefixInput.value = DEFAULT_PD_PREFIX;
			else if (this.selectedMode !== 'stateless_pd' && !this.validatePrefix(this.prefixInput.value))
				this.prefixInput.value = DEFAULT_PREFIX;
			this.prefixInput.placeholder = this.selectedMode === 'stateless_pd' ? DEFAULT_PD_PREFIX : DEFAULT_PREFIX;
			this.prefixInput.setCustomValidity('');
		}
		if (this.prefixLabel)
			this.prefixLabel.textContent = this.selectedMode === 'stateless_pd' ? _('Delegation ULA prefix') : _('Test ULA prefix');
		if (this.prefixHelp)
			this.prefixHelp.textContent = this.selectedMode === 'stateless_pd'
				? _('Use a network-aligned ULA /48, /52, /56, or /60. The first /64 stays on this LAN; downstream routers request the remaining space with DHCPv6-PD.')
				: _('Use a locally assigned ULA with a /64 prefix. The router and DNS server use host address ::1.');
		if (this.flowNode && this.flowNode.parentNode) {
			var replacement = this.renderFlow(this.selectedMode);
			this.flowNode.parentNode.replaceChild(replacement, this.flowNode);
			this.flowNode = replacement;
		}
	},

	renderFlow: function(mode) {
		if (mode !== 'stateless_pd')
			return E('div', { 'class': 'v6lab-flow', 'aria-label': _('Router Advertisement flow') }, [
				E('span', {}, [ _('Router') ]),
				E('span', { 'class': 'v6lab-arrow', 'aria-hidden': 'true' }, [
					mode === 'stateless' ? '── RA only ──▶' : '── RA + DHCPv6 ──▶'
				]),
				E('span', {}, [ _('Test client') ])
			]);
		return E('div', { 'class': 'v6lab-flow is-pd', 'aria-label': _('Prefix delegation flow') }, [
			E('span', { 'class': 'v6lab-router-node' }, [ _('Devboard') ]),
			E('div', { 'class': 'v6lab-branches' }, [
				E('span', {}, [ _('RA /64 + DHCPv6 information'), ' ', E('b', {}, [ '→' ]), ' ', _('LAN clients (SLAAC)') ]),
				E('span', {}, [ _('DHCPv6 IA_PD'), ' ', E('b', {}, [ '→' ]), ' ', _('Downstream router'), ' ', E('b', {}, [ '→' ]), ' ', _('Own /64') ])
			])
		]);
	},

	modeCard: function(mode, title, flags, addressText, dnsText) {
		var button = E('button', {
			'type': 'button',
			'class': 'v6lab-mode is-' + mode,
			'aria-pressed': 'false',
			'click': L.bind(function() { this.setMode(mode); }, this)
		}, [
			E('span', { 'class': 'v6lab-mode-title' }, [ title ]),
			E('code', { 'class': 'v6lab-flags' }, [ flags ]),
			E('span', {}, [ addressText ]),
			E('small', {}, [ dnsText ])
		]);
		this.modeButtons[mode] = button;
		return button;
	},

	showReconnect: function() {
		if (!this.reconnectNode)
			return;
		this.reconnectNode.style.display = '';
		this.reconnectNode.focus();
	},

	handleApply: function() {
		var pdMode = this.selectedMode === 'stateless_pd';
		var prefix = pdMode ? this.validatePdPrefix(this.prefixInput.value) : this.validatePrefix(this.prefixInput.value);
		if (!prefix) {
			this.prefixInput.setCustomValidity(pdMode
				? _('Use a network-aligned ULA /48, /52, /56, or /60.')
				: _('Use normalized ULA /64 form: fdxx:xxxx:xxxx:xxxx::/64'));
			this.prefixInput.reportValidity();
			return;
		}
		this.prefixInput.setCustomValidity('');
		this.prefixInput.value = prefix;

		ui.showModal(_('Applying IPv6 test mode'), [
			E('p', { 'class': 'spinning' }, [ _('Reloading the LAN and IPv6 services…') ])
		]);

		return callApply(this.selectedMode, prefix).then(L.bind(function(result) {
			ui.hideModal();
			this.status = this.normalizeStatus(result);
			this.refreshFailed = false;
			this.refreshStatusNode();
			this.setMode(this.status.mode);
			if (!this.status.ok) {
				ui.addNotification(null, E('p', {}, [ this.status.error || _('The previous configuration was restored.') ]), 'danger');
				return;
			}
			ui.addNotification(null, E('p', {}, [ _('IPv6 test mode applied.') ]), 'info');
			this.showReconnect();
		}, this)).catch(function(error) {
			ui.hideModal();
			ui.addNotification(null, E('p', {}, [ error.message || error ]), 'danger');
		});
	},

	confirmDisable: function() {
		ui.showModal(_('Disable IPv6 test mode?'), [
			E('p', {}, [ _('This removes the test ULA and stops LAN Router Advertisements and DHCPv6. IPv4 management remains available.') ]),
			E('div', { 'class': 'right' }, [
				E('button', {
					'class': 'btn',
					'click': ui.hideModal
				}, [ _('Cancel') ]),
				' ',
				E('button', {
					'class': 'btn cbi-button-negative',
					'click': L.bind(this.handleDisable, this)
				}, [ _('Disable test mode') ])
			])
		]);
	},

	handleDisable: function() {
		ui.showModal(_('Disabling IPv6 test mode'), [
			E('p', { 'class': 'spinning' }, [ _('Removing the test network configuration…') ])
		]);
		return callDisable().then(L.bind(function(result) {
			ui.hideModal();
			this.status = this.normalizeStatus(result);
			this.refreshFailed = false;
			this.refreshStatusNode();
			if (!this.status.ok) {
				ui.addNotification(null, E('p', {}, [ this.status.error || _('The previous configuration was restored.') ]), 'danger');
				return;
			}
			ui.addNotification(null, E('p', {}, [ _('IPv6 test mode disabled.') ]), 'info');
		}, this)).catch(function(error) {
			ui.hideModal();
			ui.addNotification(null, E('p', {}, [ error.message || error ]), 'danger');
		});
	},

	render: function(status) {
		this.status = this.normalizeStatus(status);
		this.selectedMode = this.status.mode;
		this.modeButtons = {};
		this.prefixInput = E('input', {
			'id': 'v6lab-prefix',
			'type': 'text',
			'class': 'cbi-input-text v6lab-prefix',
			'value': this.status.prefix,
			'placeholder': this.status.mode === 'stateless_pd' ? DEFAULT_PD_PREFIX : DEFAULT_PREFIX,
			'spellcheck': 'false',
			'input': function() { this.setCustomValidity(''); }
		});

		this.reconnectNode = E('div', {
			'class': 'v6lab-alert is-action',
			'role': 'status',
			'tabindex': '-1',
			'style': 'display:none'
		}, [
			E('strong', {}, [ _('Reconnect the test client') ]),
			E('span', {}, [ _('Old SLAAC addresses and DHCPv6 leases can remain valid after a mode change. Disconnect and reconnect the client, or renew its network configuration, before evaluating the result.') ])
		]);

		var style = E('style', { 'type': 'text/css' }, [
			':root{--v6-ink:#1d2a33;--v6-panel:#f4f7f9;--v6-stateless:#007f86;--v6-stateful:#9a5b00;--v6-pd:#4557a6;--v6-offline:#b42318;--v6-focus:#1261a0}' +
			'.v6lab{color:var(--v6-ink);max-width:1080px}.v6lab-status,.v6lab-panel{background:var(--v6-panel);border:1px solid #d8e1e7;border-radius:10px;padding:1.25rem;margin-bottom:1rem}' +
			'.v6lab-status{border-top:4px solid var(--v6-offline)}.v6lab-status-head,.v6lab-actions,.v6lab-flow{display:flex;align-items:center;justify-content:space-between;gap:1rem}' +
			'.v6lab-eyebrow{text-transform:uppercase;letter-spacing:.12em;font-size:.72rem;font-weight:700;color:#52636f}.v6lab h2{margin:.2rem 0 0}.v6lab-state{border-radius:999px;padding:.35rem .75rem;font-weight:700}' +
			'.v6lab-state.is-active{background:#d9f2ef;color:#006268}.v6lab-state.is-degraded{background:#fff0d1;color:#794600}.v6lab-state.is-disabled{background:#e6eaed;color:#596871}' +
			'.v6lab-facts{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:.75rem;margin:1.15rem 0}.v6lab-facts div{display:flex;flex-direction:column;gap:.25rem}.v6lab-facts span{font-size:.78rem;color:#62727d}.v6lab code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;overflow-wrap:anywhere}' +
			'.v6lab-checks{display:flex;flex-wrap:wrap;gap:.55rem}.v6lab-check{display:flex;align-items:center;gap:.4rem;background:#fff;border:1px solid #d8e1e7;border-radius:7px;padding:.35rem .55rem}.v6lab-dot{width:.55rem;height:.55rem;border-radius:50%;background:#9aa7af}.v6lab-check.is-ok .v6lab-dot{background:#16825d}.v6lab-check.is-bad .v6lab-dot{background:var(--v6-offline)}.v6lab-check.is-off{color:#6c7a83;background:#edf1f3}' +
			'.v6lab-client{background:#fff;border:1px solid #d8e1e7;border-left:4px solid var(--v6-stateless);border-radius:8px;padding:.85rem 1rem;margin-top:1rem}.v6lab-client.is-dhcpv6{border-left-color:var(--v6-stateful)}.v6lab-client.is-pd{border-left-color:var(--v6-pd)}.v6lab-client-head{display:flex;align-items:center;justify-content:space-between;gap:1rem}.v6lab-client-head>div{display:flex;flex-direction:column;gap:.2rem}.v6lab-client code.is-empty{color:#73818a}.v6lab-client-state{border-radius:999px;padding:.3rem .65rem;font-size:.8rem;font-weight:700;white-space:nowrap}.v6lab-client-state.is-observed{background:#d9f2ef;color:#006268}.v6lab-client-state.is-assigned,.v6lab-client-state.is-waiting{background:#fff0d1;color:#794600}.v6lab-client-state.is-error{background:#fde8e7;color:#8f1c15}.v6lab-client-state.is-disabled{background:#e6eaed;color:#596871}.v6lab-client-evidence{color:#52636f;font-size:.82rem;margin-top:.5rem}.v6lab-refresh-warning{color:#794600;font-size:.8rem;margin-top:.65rem}' +
			'.v6lab-modes{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:.85rem;margin:1rem 0}.v6lab-mode{display:grid;grid-template-columns:1fr auto;gap:.45rem .75rem;text-align:left;border:2px solid #cbd6dc;border-radius:9px;background:#fff;padding:1rem;cursor:pointer;color:inherit}.v6lab-mode:hover{border-color:#8698a3}.v6lab-mode:focus-visible{outline:3px solid var(--v6-focus);outline-offset:2px}.v6lab-mode.is-stateless.is-selected{border-color:var(--v6-stateless);box-shadow:0 0 0 1px var(--v6-stateless)}.v6lab-mode.is-stateful.is-selected{border-color:var(--v6-stateful);box-shadow:0 0 0 1px var(--v6-stateful)}.v6lab-mode.is-stateless_pd.is-selected{border-color:var(--v6-pd);box-shadow:0 0 0 1px var(--v6-pd)}' +
			'.v6lab-mode-title{font-size:1.08rem;font-weight:750}.v6lab-flags{justify-self:end}.v6lab-mode small{grid-column:1/-1;color:#5d6c75}.v6lab-flow{justify-content:center;background:#fff;border:1px dashed #9fb0ba;border-radius:8px;padding:.75rem;margin:1rem 0;font-weight:700}.v6lab-flow.is-pd{display:grid;grid-template-columns:auto minmax(0,1fr);border-color:#aeb7df;background:#f3f5ff;color:#273579}.v6lab-router-node{align-self:center;padding:.45rem .7rem;border:1px solid #aeb7df;border-radius:6px;background:#fff}.v6lab-branches{display:grid;gap:.45rem}.v6lab-branches span{display:block}.v6lab-branches b{color:var(--v6-pd)}.v6lab-arrow{color:var(--v6-focus);letter-spacing:.15em}' +
			'.v6lab-field{display:grid;grid-template-columns:minmax(8rem,12rem) minmax(16rem,1fr);align-items:center;gap:1rem;margin:1rem 0}.v6lab-field label{font-weight:700}.v6lab-prefix{width:100%;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}.v6lab-help{grid-column:2;color:#5d6c75;font-size:.82rem}' +
			'.v6lab-actions{margin-top:1rem}.v6lab-alert{display:flex;gap:.6rem;align-items:flex-start;border-radius:7px;padding:.8rem 1rem;margin-top:1rem}.v6lab-alert strong{white-space:nowrap}.v6lab-alert.is-error{background:#fde8e7;color:#8f1c15}.v6lab-alert.is-action{background:#e4f0fa;color:#164f75}' +
			'@media(max-width:700px){.v6lab-facts,.v6lab-modes,.v6lab-flow.is-pd{grid-template-columns:1fr}.v6lab-status-head,.v6lab-actions,.v6lab-client-head{align-items:flex-start;flex-direction:column}.v6lab-field{grid-template-columns:1fr}.v6lab-help{grid-column:1}.v6lab-flow{font-size:.84rem;gap:.45rem}}' +
			'@media(prefers-reduced-motion:reduce){.v6lab *{scroll-behavior:auto!important;transition:none!important}}'
		]);

		this.statusNode = this.renderStatus();
		if (!this.pollFn) {
			this.pollFn = L.bind(this.refreshStatus, this);
			poll.add(this.pollFn, 5);
		}
		var statelessCard = this.modeCard(
			'stateless', _('Stateless'), 'A=1  O=0  M=0',
			_('The client creates its address with SLAAC.'),
			_('Local DNS arrives through Router Advertisement RDNSS; DHCPv6 is disabled.')
		);
		var statefulCard = this.modeCard(
			'stateful', _('Stateful'), 'A=0  O=0  M=1',
			_('The DHCPv6 server assigns the client address.'),
			_('The same DHCPv6 exchange supplies local DNS.')
		);
		var pdCard = this.modeCard(
			'stateless_pd', _('Stateless + PD'), 'A=1  O=1  M=0',
			_('LAN clients still create addresses with SLAAC.'),
			_('Downstream routers can request an additional prefix.')
		);
		this.prefixLabel = E('label', { 'for': 'v6lab-prefix' });
		this.prefixHelp = E('div', { 'class': 'v6lab-help' });
		this.flowNode = this.renderFlow(this.selectedMode);

		var page = E('div', { 'class': 'v6lab' }, [
			style,
			this.statusNode,
			E('section', { 'class': 'v6lab-panel' }, [
				E('h3', {}, [ _('Address assignment mode') ]),
				E('p', {}, [ _('Router Advertisements provide the LAN /64 and default gateway. Internet forwarding remains blocked in every mode.') ]),
				E('div', { 'class': 'v6lab-modes' }, [ statelessCard, statefulCard, pdCard ]),
				this.flowNode,
				E('div', { 'class': 'v6lab-field' }, [
					this.prefixLabel,
					this.prefixInput,
					this.prefixHelp
				]),
				E('div', { 'class': 'v6lab-actions' }, [
					E('button', {
						'class': 'btn cbi-button-negative',
						'type': 'button',
						'click': L.bind(this.confirmDisable, this)
					}, [ _('Disable test mode') ]),
					E('button', {
						'class': 'btn cbi-button-action important',
						'type': 'button',
						'click': L.bind(this.handleApply, this)
					}, [ _('Save and apply') ])
				]),
				this.reconnectNode
			])
		]);

		this.setMode(this.selectedMode);
		return page;
	},

	handleSaveApply: null,
	handleSave: null,
	handleReset: null
});
