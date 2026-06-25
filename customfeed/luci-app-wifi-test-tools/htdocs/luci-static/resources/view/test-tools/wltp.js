'use strict';
'require view';
'require rpc';
'require ui';

function valueOf(node) {
	return node ? node.value : '';
}

function setText(node, text) {
	if (node)
		node.textContent = text == null ? '' : String(text);
}

function clearNode(node) {
	if (!node)
		return;

	while (node.firstChild)
		node.removeChild(node.firstChild);
}

function payloadOf(res) {
	if (res && typeof res === 'object' && res.result && typeof res.result === 'object')
		return res.result;

	return res || {};
}

function field(obj, names) {
	var i, name, cur;

	for (i = 0; i < names.length; i++) {
		name = names[i];

		if (name.indexOf('.') < 0) {
			if (obj && obj[name] != null)
				return obj[name];
			continue;
		}

		cur = obj;
		name.split('.').forEach(function(part) {
			cur = cur && cur[part] != null ? cur[part] : null;
		});

		if (cur != null)
			return cur;
	}

	return '';
}

function fmt(value) {
	if (value == null || value === '')
		return '-';

	return String(value);
}

function collectLines(res) {
	var data = payloadOf(res);
	var lines = [];

	function add(v) {
		if (v == null)
			return;

		if (Array.isArray(v)) {
			v.forEach(add);
		} else if (typeof v === 'string') {
			lines = lines.concat(v.split(/\r?\n/).filter(function(line) { return line.length; }));
		} else if (typeof v === 'object') {
			lines.push(JSON.stringify(v));
		} else {
			lines.push(String(v));
		}
	}

	add(data.lines);
	add(data.log);
	add(data.stdout);
	add(data.output);
	add(data.data);

	if (!lines.length && (typeof data === 'string' || Array.isArray(data)))
		add(data);

	return lines;
}

function parseStats(lines) {
	var latest = {};

	lines.forEach(function(line) {
		var obj, stats, proto;

		try {
			obj = JSON.parse(line);
		} catch (e) {
			return;
		}

		stats = obj.final || obj.latest || obj.stats || obj;
		proto = field(stats, [ 'protocol', 'proto', 'name' ]);

		if (!proto)
			return;

		latest[proto] = stats;
	});

	return Object.keys(latest).sort().map(function(proto) {
		return latest[proto];
	});
}

return view.extend({
	callWltpStart: rpc.declare({
		object: 'luci.bw_test',
		method: 'wltp_start',
		params: [ 'mode', 'iface', 'dest_ip', 'protocols', 'rate', 'duration', 'interval', 'universe', 'pkt_size', 'burst' ]
	}),

	callWltpStop: rpc.declare({
		object: 'luci.bw_test',
		method: 'wltp_stop'
	}),

	callWltpStatus: rpc.declare({
		object: 'luci.bw_test',
		method: 'wltp_status'
	}),

	callWltpRead: rpc.declare({
		object: 'luci.bw_test',
		method: 'wltp_read'
	}),

	load: function() {
		return Promise.all([
			this.callWltpStatus().catch(function() { return {}; }),
			this.callWltpRead().catch(function() { return {}; })
		]);
	},

	setBusy: function(busy) {
		if (this.startButton)
			this.startButton.disabled = busy;
		if (this.stopButton)
			this.stopButton.disabled = busy;
		if (this.refreshButton)
			this.refreshButton.disabled = busy;
	},

	formValues: function() {
		return {
			mode: valueOf(this.modeInput),
			iface: valueOf(this.ifaceInput),
			dest_ip: valueOf(this.destinationInput),
			protocols: valueOf(this.protocolsInput),
			rate: valueOf(this.rateInput),
			duration: valueOf(this.durationInput),
			interval: valueOf(this.intervalInput),
			universe: valueOf(this.universeInput),
			pkt_size: valueOf(this.packetSizeInput),
			burst: valueOf(this.burstInput)
		};
	},

	handleStart: function(ev) {
		var v = this.formValues();

		if (ev)
			ev.preventDefault();

		this.setBusy(true);

		return this.callWltpStart(
			v.mode,
			v.iface,
			v.dest_ip,
			v.protocols,
			v.rate,
			v.duration,
			v.interval,
			v.universe,
			v.pkt_size,
			v.burst
		).then(function(res) {
			var data = payloadOf(res);

			if (data && data.error)
				ui.addNotification(null, E('p', {}, data.error), 'danger');
			else
				ui.addNotification(null, E('p', {}, _('WLTP test started.')), 'info');
		}.bind(this)).catch(function(err) {
			ui.addNotification(null, E('p', {}, err.message || err), 'danger');
		}).then(function() {
			return this.refresh();
		}.bind(this)).finally(function() {
			this.setBusy(false);
		}.bind(this));
	},

	handleStop: function(ev) {
		if (ev)
			ev.preventDefault();

		this.setBusy(true);

		return this.callWltpStop().then(function(res) {
			var data = payloadOf(res);

			if (data && data.error)
				ui.addNotification(null, E('p', {}, data.error), 'danger');
			else
				ui.addNotification(null, E('p', {}, _('WLTP test stopped.')), 'info');
		}.bind(this)).catch(function(err) {
			ui.addNotification(null, E('p', {}, err.message || err), 'danger');
		}).then(function() {
			return this.refresh();
		}.bind(this)).finally(function() {
			this.setBusy(false);
		}.bind(this));
	},

	refresh: function(ev) {
		if (ev)
			ev.preventDefault();

		this.setBusy(true);

		return Promise.all([
			this.callWltpStatus().catch(function(err) { return { error: err.message || err }; }),
			this.callWltpRead().catch(function(err) { return { error: err.message || err }; })
		]).then(function(data) {
			this.renderStatus(data[0]);
			this.renderLog(data[1]);
		}.bind(this)).finally(function() {
			this.setBusy(false);
		}.bind(this));
	},

	renderStatus: function(res) {
		var data = payloadOf(res);
		var running = data.running === true || data.running === 1 || data.status === 'running' || data.state === 'running';

		setText(this.statusRunning, running ? _('running') : _('stopped'));
		setText(this.statusMode, field(data, [ 'mode' ]) || '-');
		setText(this.statusIface, field(data, [ 'iface', 'interface', 'ifname' ]) || '-');
		setText(this.statusDestination, field(data, [ 'destination', 'dst', 'dst_ip', 'host' ]) || '-');
		setText(this.statusProtocols, field(data, [ 'protocols', 'protocol', 'proto' ]) || '-');
		setText(this.statusPid, field(data, [ 'pid' ]) || '-');
	},

	renderLog: function(res) {
		var lines = collectLines(res);
		var stats = parseStats(lines);
		var tbody, raw;

		clearNode(this.resultsNode);

		if (stats.length) {
			tbody = E('tbody', {});

			stats.forEach(function(row) {
				tbody.appendChild(E('tr', {}, [
					E('td', {}, fmt(field(row, [ 'protocol', 'proto', 'name' ]))),
					E('td', {}, fmt(field(row, [ 'tx_packets', 'tx_pkts', 'tx.packets', 'tx.packets_total' ]))),
					E('td', {}, fmt(field(row, [ 'rx_packets', 'rx_pkts', 'rx.packets', 'rx.packets_total' ]))),
					E('td', {}, fmt(field(row, [ 'tx_bytes', 'tx.bytes', 'tx.bytes_total' ]))),
					E('td', {}, fmt(field(row, [ 'rx_bytes', 'rx.bytes', 'rx.bytes_total' ]))),
					E('td', {}, fmt(field(row, [ 'loss', 'loss_pct', 'loss_percent', 'lost_packets' ]))),
					E('td', {}, fmt(field(row, [ 'pps', 'tx_pps', 'rx_pps' ]))),
					E('td', {}, fmt(field(row, [ 'Bps', 'bytes_per_sec', 'bps', 'rx_Bps', 'tx_Bps' ]))),
					E('td', {}, fmt(field(row, [ 'avg_latency', 'latency_avg', 'latency_avg_us', 'latency.avg', 'avg' ]))),
					E('td', {}, fmt(field(row, [ 'min_latency', 'latency_min', 'latency_min_us', 'latency.min', 'min' ]))),
					E('td', {}, fmt(field(row, [ 'max_latency', 'latency_max', 'latency_max_us', 'latency.max', 'max' ]))),
					E('td', {}, fmt(field(row, [ 'jitter', 'latency_jitter', 'jitter_us', 'latency.jitter' ])))
				]));
			});

			this.resultsNode.appendChild(E('table', { 'class': 'table' }, [
				E('thead', {}, E('tr', {}, [
					E('th', {}, _('Protocol')),
					E('th', {}, _('TX packets')),
					E('th', {}, _('RX packets')),
					E('th', {}, _('TX bytes')),
					E('th', {}, _('RX bytes')),
					E('th', {}, _('Loss')),
					E('th', {}, _('pps')),
					E('th', {}, _('Bps')),
					E('th', {}, _('Avg latency')),
					E('th', {}, _('Min latency')),
					E('th', {}, _('Max latency')),
					E('th', {}, _('Jitter'))
				])),
				tbody
			]));
		} else {
			this.resultsNode.appendChild(E('em', {}, _('No JSON result records found yet. Raw log is shown below.')));
		}

		raw = lines.join('\n');
		if (!raw && res && res.error)
			raw = res.error;

		setText(this.rawLogNode, raw || _('No WLTP output yet.'));
	},

	render: function(data) {
		var viewNode;

		this.modeInput = E('select', { 'class': 'cbi-input-select' }, [
			E('option', { value: 'sender' }, _('Sender')),
			E('option', { value: 'receiver' }, _('Receiver')),
			E('option', { value: 'reflector' }, _('Reflector'))
		]);
		this.ifaceInput = E('input', { 'class': 'cbi-input-text', value: 'wlan0' });
		this.destinationInput = E('input', { 'class': 'cbi-input-text', value: '239.255.0.1' });
		this.protocolsInput = E('input', { 'class': 'cbi-input-text', value: 'artnet,sacn' });
		this.rateInput = E('input', { 'class': 'cbi-input-text', value: '40' });
		this.durationInput = E('input', { 'class': 'cbi-input-text', value: '30' });
		this.intervalInput = E('input', { 'class': 'cbi-input-text', value: '1' });
		this.universeInput = E('input', { 'class': 'cbi-input-text', value: '1' });
		this.packetSizeInput = E('input', { 'class': 'cbi-input-text', value: '512' });
		this.burstInput = E('input', { 'class': 'cbi-input-text', value: '1' });

		this.statusRunning = E('span', {}, '-');
		this.statusMode = E('span', {}, '-');
		this.statusIface = E('span', {}, '-');
		this.statusDestination = E('span', {}, '-');
		this.statusProtocols = E('span', {}, '-');
		this.statusPid = E('span', {}, '-');
		this.resultsNode = E('div', {});
		this.rawLogNode = E('pre', {
			style: 'max-height: 24em; overflow: auto; white-space: pre-wrap; background: #f7f7f7; border: 1px solid #ddd; padding: 1em;'
		}, '');

		this.startButton = E('button', { 'class': 'btn cbi-button cbi-button-apply', click: this.handleStart.bind(this) }, _('Start'));
		this.stopButton = E('button', { 'class': 'btn cbi-button cbi-button-reset', click: this.handleStop.bind(this) }, _('Stop'));
		this.refreshButton = E('button', { 'class': 'btn cbi-button', click: this.refresh.bind(this) }, _('Refresh'));

		viewNode = E('div', { 'class': 'cbi-map' }, [
			E('h2', {}, _('Stage Lighting Protocol Test')),
			E('div', { 'class': 'cbi-map-descr' }, _('Run WLTP stage-lighting protocol traffic tests and inspect live output.')),

			E('div', { 'class': 'cbi-section' }, [
				E('h3', {}, _('Parameters')),
				E('div', { 'class': 'table' }, [
					E('div', { 'class': 'tr' }, [ E('div', { 'class': 'td left' }, _('Mode')), E('div', { 'class': 'td left' }, this.modeInput) ]),
					E('div', { 'class': 'tr' }, [ E('div', { 'class': 'td left' }, _('Interface')), E('div', { 'class': 'td left' }, this.ifaceInput) ]),
					E('div', { 'class': 'tr' }, [ E('div', { 'class': 'td left' }, _('Destination IP')), E('div', { 'class': 'td left' }, this.destinationInput) ]),
					E('div', { 'class': 'tr' }, [ E('div', { 'class': 'td left' }, _('Protocols')), E('div', { 'class': 'td left' }, this.protocolsInput) ]),
					E('div', { 'class': 'tr' }, [ E('div', { 'class': 'td left' }, _('Rate')), E('div', { 'class': 'td left' }, this.rateInput) ]),
					E('div', { 'class': 'tr' }, [ E('div', { 'class': 'td left' }, _('Duration')), E('div', { 'class': 'td left' }, this.durationInput) ]),
					E('div', { 'class': 'tr' }, [ E('div', { 'class': 'td left' }, _('Interval')), E('div', { 'class': 'td left' }, this.intervalInput) ]),
					E('div', { 'class': 'tr' }, [ E('div', { 'class': 'td left' }, _('Universe')), E('div', { 'class': 'td left' }, this.universeInput) ]),
					E('div', { 'class': 'tr' }, [ E('div', { 'class': 'td left' }, _('Packet size')), E('div', { 'class': 'td left' }, this.packetSizeInput) ]),
					E('div', { 'class': 'tr' }, [ E('div', { 'class': 'td left' }, _('Burst')), E('div', { 'class': 'td left' }, this.burstInput) ])
				]),
				E('div', { 'class': 'cbi-page-actions' }, [ this.startButton, ' ', this.stopButton, ' ', this.refreshButton ])
			]),

			E('div', { 'class': 'cbi-section' }, [
				E('h3', {}, _('Live status')),
				E('table', { 'class': 'table' }, [
					E('tr', {}, [ E('td', {}, _('State')), E('td', {}, this.statusRunning) ]),
					E('tr', {}, [ E('td', {}, _('Mode')), E('td', {}, this.statusMode) ]),
					E('tr', {}, [ E('td', {}, _('Interface')), E('td', {}, this.statusIface) ]),
					E('tr', {}, [ E('td', {}, _('Destination')), E('td', {}, this.statusDestination) ]),
					E('tr', {}, [ E('td', {}, _('Protocols')), E('td', {}, this.statusProtocols) ]),
					E('tr', {}, [ E('td', {}, _('PID')), E('td', {}, this.statusPid) ])
				])
			]),

			E('div', { 'class': 'cbi-section' }, [
				E('h3', {}, _('Parsed results')),
				this.resultsNode
			]),

			E('div', { 'class': 'cbi-section' }, [
				E('h3', {}, _('Raw log')),
				this.rawLogNode
			])
		]);

		this.renderStatus(data ? data[0] : {});
		this.renderLog(data ? data[1] : {});

		return viewNode;
	},

	handleSaveApply: null,
	handleSave: null,
	handleReset: null
});
