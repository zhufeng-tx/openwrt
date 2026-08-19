'use strict';
'require view';
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

var callDisable = rpc.declare({
	object: 'luci.ipv6_test',
	method: 'disable'
});

var DEFAULT_STATUS = {
	ok: false,
	enabled: false,
	mode: 'stateless',
	active_mode: 'degraded',
	prefix: 'fd42:6970:7636:1::/64',
	router_address: 'fd42:6970:7636:1::1',
	dns_address: 'fd42:6970:7636:1::1',
	dns_name: 'router.ipv6.test',
	ra_flags: 'A=1 O=1 M=0',
	address_active: false,
	odhcpd_running: false,
	dnsmasq_running: false,
	forwarding_blocked: false,
	error: ''
};

return view.extend({
	selectedMode: 'stateless',
	status: null,
	modeButtons: null,
	statusNode: null,
	prefixInput: null,
	reconnectNode: null,

	load: function() {
		return L.resolveDefault(callStatus(), DEFAULT_STATUS);
	},

	normalizeStatus: function(status) {
		var data = Object.assign({}, DEFAULT_STATUS, status || {});
		data.mode = data.mode === 'stateful' ? 'stateful' : 'stateless';
		return data;
	},

	validatePrefix: function(value) {
		var normalized = String(value || '').trim().toLowerCase();
		return /^fd[0-9a-f]{2}(:[0-9a-f]{1,4}){3}::\/64$/.test(normalized) ? normalized : null;
	},

	statusChip: function(label, active, neutral) {
		return E('div', { 'class': 'v6lab-check ' + (neutral ? 'is-off' : active ? 'is-ok' : 'is-bad') }, [
			E('span', { 'class': 'v6lab-dot', 'aria-hidden': 'true' }),
			E('span', {}, [ label ])
		]);
	},

	renderStatus: function() {
		var status = this.status;
		var activeLabel = status.enabled
			? (status.active_mode === 'degraded' ? _('Degraded') : status.mode === 'stateful' ? _('Stateful') : _('Stateless'))
			: _('Disabled');
		var tone = !status.enabled ? 'is-disabled' : status.ok ? 'is-active' : 'is-degraded';
		var error = status.error
			? E('div', { 'class': 'v6lab-alert is-error' }, [
				E('strong', {}, [ _('Configuration error') ]),
				E('span', {}, [ status.error ])
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
				E('div', {}, [ E('span', {}, [ _('Prefix') ]), E('code', {}, [ status.prefix ]) ]),
				E('div', {}, [ E('span', {}, [ _('Router and DNS') ]), E('code', {}, [ status.router_address ]) ]),
				E('div', {}, [ E('span', {}, [ _('Local DNS name') ]), E('code', {}, [ status.dns_name ]) ])
			]),
			E('div', { 'class': 'v6lab-checks' }, [
				this.statusChip(_('LAN address'), status.address_active, !status.enabled),
				this.statusChip(_('odhcpd'), status.odhcpd_running, !status.enabled),
				this.statusChip(_('Local DNS'), status.dnsmasq_running, !status.enabled),
				this.statusChip(_('Forwarding blocked'), status.forwarding_blocked, !status.enabled)
			]),
			error
		]);
	},

	refreshStatusNode: function() {
		var replacement = this.renderStatus();
		if (this.statusNode && this.statusNode.parentNode)
			this.statusNode.parentNode.replaceChild(replacement, this.statusNode);
		this.statusNode = replacement;
	},

	setMode: function(mode) {
		this.selectedMode = mode === 'stateful' ? 'stateful' : 'stateless';
		Object.keys(this.modeButtons || {}).forEach(L.bind(function(key) {
			var selected = key === this.selectedMode;
			this.modeButtons[key].classList.toggle('is-selected', selected);
			this.modeButtons[key].setAttribute('aria-pressed', selected ? 'true' : 'false');
		}, this));
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
		var prefix = this.validatePrefix(this.prefixInput.value);
		if (!prefix) {
			this.prefixInput.setCustomValidity(_('Use normalized ULA /64 form: fdxx:xxxx:xxxx:xxxx::/64'));
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
			'placeholder': 'fd42:6970:7636:1::/64',
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
			':root{--v6-ink:#1d2a33;--v6-panel:#f4f7f9;--v6-stateless:#007f86;--v6-stateful:#9a5b00;--v6-offline:#b42318;--v6-focus:#1261a0}' +
			'.v6lab{color:var(--v6-ink);max-width:1080px}.v6lab-status,.v6lab-panel{background:var(--v6-panel);border:1px solid #d8e1e7;border-radius:10px;padding:1.25rem;margin-bottom:1rem}' +
			'.v6lab-status{border-top:4px solid var(--v6-offline)}.v6lab-status-head,.v6lab-actions,.v6lab-flow{display:flex;align-items:center;justify-content:space-between;gap:1rem}' +
			'.v6lab-eyebrow{text-transform:uppercase;letter-spacing:.12em;font-size:.72rem;font-weight:700;color:#52636f}.v6lab h2{margin:.2rem 0 0}.v6lab-state{border-radius:999px;padding:.35rem .75rem;font-weight:700}' +
			'.v6lab-state.is-active{background:#d9f2ef;color:#006268}.v6lab-state.is-degraded{background:#fff0d1;color:#794600}.v6lab-state.is-disabled{background:#e6eaed;color:#596871}' +
			'.v6lab-facts{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:.75rem;margin:1.15rem 0}.v6lab-facts div{display:flex;flex-direction:column;gap:.25rem}.v6lab-facts span{font-size:.78rem;color:#62727d}.v6lab code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;overflow-wrap:anywhere}' +
			'.v6lab-checks{display:flex;flex-wrap:wrap;gap:.55rem}.v6lab-check{display:flex;align-items:center;gap:.4rem;background:#fff;border:1px solid #d8e1e7;border-radius:7px;padding:.35rem .55rem}.v6lab-dot{width:.55rem;height:.55rem;border-radius:50%;background:#9aa7af}.v6lab-check.is-ok .v6lab-dot{background:#16825d}.v6lab-check.is-bad .v6lab-dot{background:var(--v6-offline)}.v6lab-check.is-off{color:#6c7a83;background:#edf1f3}' +
			'.v6lab-modes{display:grid;grid-template-columns:1fr 1fr;gap:.85rem;margin:1rem 0}.v6lab-mode{display:grid;grid-template-columns:1fr auto;gap:.45rem .75rem;text-align:left;border:2px solid #cbd6dc;border-radius:9px;background:#fff;padding:1rem;cursor:pointer;color:inherit}.v6lab-mode:hover{border-color:#8698a3}.v6lab-mode:focus-visible{outline:3px solid var(--v6-focus);outline-offset:2px}.v6lab-mode.is-stateless.is-selected{border-color:var(--v6-stateless);box-shadow:0 0 0 1px var(--v6-stateless)}.v6lab-mode.is-stateful.is-selected{border-color:var(--v6-stateful);box-shadow:0 0 0 1px var(--v6-stateful)}' +
			'.v6lab-mode-title{font-size:1.08rem;font-weight:750}.v6lab-flags{justify-self:end}.v6lab-mode small{grid-column:1/-1;color:#5d6c75}.v6lab-flow{justify-content:center;background:#fff;border:1px dashed #9fb0ba;border-radius:8px;padding:.75rem;margin:1rem 0;font-weight:700}.v6lab-arrow{color:var(--v6-focus);letter-spacing:.15em}' +
			'.v6lab-field{display:grid;grid-template-columns:minmax(8rem,12rem) minmax(16rem,1fr);align-items:center;gap:1rem;margin:1rem 0}.v6lab-field label{font-weight:700}.v6lab-prefix{width:100%;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}.v6lab-help{grid-column:2;color:#5d6c75;font-size:.82rem}' +
			'.v6lab-actions{margin-top:1rem}.v6lab-alert{display:flex;gap:.6rem;align-items:flex-start;border-radius:7px;padding:.8rem 1rem;margin-top:1rem}.v6lab-alert strong{white-space:nowrap}.v6lab-alert.is-error{background:#fde8e7;color:#8f1c15}.v6lab-alert.is-action{background:#e4f0fa;color:#164f75}' +
			'@media(max-width:700px){.v6lab-facts,.v6lab-modes{grid-template-columns:1fr}.v6lab-status-head,.v6lab-actions{align-items:flex-start;flex-direction:column}.v6lab-field{grid-template-columns:1fr}.v6lab-help{grid-column:1}.v6lab-flow{font-size:.84rem;gap:.45rem}}' +
			'@media(prefers-reduced-motion:reduce){.v6lab *{scroll-behavior:auto!important;transition:none!important}}'
		]);

		this.statusNode = this.renderStatus();
		var statelessCard = this.modeCard(
			'stateless', _('Stateless'), 'A=1  O=1  M=0',
			_('The client creates its address with SLAAC.'),
			_('Local DNS arrives through stateless DHCPv6.')
		);
		var statefulCard = this.modeCard(
			'stateful', _('Stateful'), 'A=0  O=0  M=1',
			_('The DHCPv6 server assigns the client address.'),
			_('The same DHCPv6 exchange supplies local DNS.')
		);

		var page = E('div', { 'class': 'v6lab' }, [
			style,
			this.statusNode,
			E('section', { 'class': 'v6lab-panel' }, [
				E('h3', {}, [ _('Address assignment mode') ]),
				E('p', {}, [ _('Router Advertisements always provide the test prefix and default gateway. Internet forwarding remains blocked in both modes.') ]),
				E('div', { 'class': 'v6lab-modes' }, [ statelessCard, statefulCard ]),
				E('div', { 'class': 'v6lab-flow', 'aria-label': _('Router Advertisement flow') }, [
					E('span', {}, [ _('Router') ]),
					E('span', { 'class': 'v6lab-arrow', 'aria-hidden': 'true' }, [ '── RA + DHCPv6 ──▶' ]),
					E('span', {}, [ _('Test client') ])
				]),
				E('div', { 'class': 'v6lab-field' }, [
					E('label', { 'for': 'v6lab-prefix' }, [ _('Test ULA prefix') ]),
					this.prefixInput,
					E('div', { 'class': 'v6lab-help' }, [ _('Use a locally assigned ULA with a /64 prefix. The router and DNS server use host address ::1.') ])
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
