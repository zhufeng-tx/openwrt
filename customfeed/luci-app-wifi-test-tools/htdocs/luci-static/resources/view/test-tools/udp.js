'use strict';
'require view';
'require poll';
'require request';
'require rpc';
'require ui';

var callUdpStart = rpc.declare({
	object: 'luci.bw_test',
	method: 'udp_start',
	params: [ 'local_ip', 'dest_ip', 'tx_mode', 'port', 'pkt_len', 'bandwidth' ],
	expect: { code: 0 }
});

var callUdpStop = rpc.declare({
	object: 'luci.bw_test',
	method: 'udp_stop'
});

var callUdpStatus = rpc.declare({
	object: 'luci.bw_test',
	method: 'udp_status',
	expect: { running: false }
});

var callUdpRead = rpc.declare({
	object: 'luci.bw_test',
	method: 'udp_read',
	expect: { result: [] }
});

/* module-level graph state */
var graphCtx     = null;
var pollFn       = null;
var pollInterval  = 3;
var isRxMode     = false;

Math.log2 = Math.log2 || function(x) { return Math.log(x) * Math.LOG2E; };

return view.extend({
	load: function() {
		return Promise.all([
			this.loadSVG(L.resource('svg/bw-test.svg')),
			L.resolveDefault(callUdpStatus(), { running: false })
		]);
	},

	loadSVG: function(src) {
		return request.get(src).then(function(response) {
			if (!response.ok)
				throw new Error(response.statusText);
			return E('div', {
				'style': 'width:100%;height:300px;border:1px solid #000;background:#fff'
			}, E(response.text()));
		});
	},

	initGraph: function(svg) {
		var G        = svg.firstElementChild;
		var viewEl   = document.querySelector('#view');
		var width    = viewEl ? viewEl.offsetWidth - 2 : 800;
		var height   = 300 - 2;
		var step     = 5;
		var data_wanted = Math.floor(width / step);
		var values   = [];
		var i;

		for (i = 0; i < data_wanted; i++)
			values.push(0);

		/* vertical minute-marker lines */
		for (i = width % (step * 60); i < width; i += step * 60) {
			var line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
			line.setAttribute('x1', i);
			line.setAttribute('y1', 0);
			line.setAttribute('x2', i);
			line.setAttribute('y2', '100%');
			line.setAttribute('style', 'stroke:black;stroke-width:0.1');

			var text = document.createElementNS('http://www.w3.org/2000/svg', 'text');
			text.setAttribute('x', i + 5);
			text.setAttribute('y', 15);
			text.setAttribute('style', 'fill:#eee;font-size:9pt;font-family:sans-serif;text-shadow:1px 1px 1px #000');
			text.appendChild(document.createTextNode(
				Math.round((width - i) / step / 60) + 'm'
			));

			G.appendChild(line);
			G.appendChild(text);
		}

		graphCtx = {
			svg:    svg,
			width:  width,
			height: height,
			step:   step,
			values: values,
			timestamp: 0,
			peak:   0,
			sum:    0,
			count:  0
		};
	},

	redrawGraph: function(tab, lastEntry) {
		var ctx = graphCtx;
		if (!ctx) return;

		var values    = ctx.values;
		var info_peak = ctx.peak || 1;
		var size, div, mult;

		/* Y-axis auto-scaling from load.js */
		size = Math.floor(Math.log2(info_peak));
		div  = Math.pow(2, size - (size % 10));
		mult = info_peak / div;
		mult = (mult < 5) ? 2 : ((mult < 50) ? 10 : ((mult < 500) ? 100 : 1000));
		info_peak = info_peak + (mult * div) - (info_peak % (mult * div));

		var data_scale = ctx.height / info_peak;
		var G  = ctx.svg.firstElementChild;
		var el = G.getElementById('speed');

		if (el) {
			var pt = '0,' + ctx.height;
			var y  = ctx.height;
			var j;
			for (j = 0; j < values.length; j++) {
				var x = j * ctx.step;
				y = ctx.height - Math.floor(values[j] * data_scale);
				y = isNaN(y) ? ctx.height : y;
				pt += ' ' + x + ',' + y;
			}
			pt += ' ' + ctx.width + ',' + y + ' ' + ctx.width + ',' + ctx.height;
			el.setAttribute('points', pt);
		}

		var l75 = G.getElementById('label_75');
		var l50 = G.getElementById('label_50');
		var l25 = G.getElementById('label_25');
		if (l75) l75.firstChild.data = Math.round(info_peak * 0.75) + ' KB/s';
		if (l50) l50.firstChild.data = Math.round(info_peak * 0.50) + ' KB/s';
		if (l25) l25.firstChild.data = Math.round(info_peak * 0.25) + ' KB/s';

		var avg = ctx.count > 0 ? Math.round(ctx.sum / ctx.count) : 0;
		var cur = values[values.length - 1] || 0;

		var scaleEl = tab.querySelector('#udp_scale');
		if (scaleEl) scaleEl.firstChild.data =
			'(%d minute window, %d second interval)'.format(
				Math.floor(values.length * pollInterval / 60), pollInterval);

		var curEl  = tab.querySelector('#udp_cur');
		var avgEl  = tab.querySelector('#udp_avg');
		var peakEl = tab.querySelector('#udp_peak');
		if (curEl)  curEl.firstChild.data  = cur + ' KB/s';
		if (avgEl)  avgEl.firstChild.data  = avg + ' KB/s';
		if (peakEl) peakEl.firstChild.data = ctx.peak + ' KB/s';

		/* packet loss stats — auto-detect RX mode from data */
		if (lastEntry && lastEntry[2] > 0)
			isRxMode = true;

		if (isRxMode && lastEntry) {
			var lossRow = tab.querySelector('#udp_loss_row');
			var rateRow = tab.querySelector('#udp_lossrate_row');
			if (lossRow) lossRow.style.display = '';
			if (rateRow) rateRow.style.display = '';

			var totalEl = tab.querySelector('#udp_total');
			var rxEl    = tab.querySelector('#udp_rx');
			var lostEl  = tab.querySelector('#udp_lost');
			var lossEl  = tab.querySelector('#udp_loss_pct');

			var total = lastEntry[2] || 0;
			var rx    = lastEntry[3] || 0;
			var lost  = lastEntry[4] || 0;
			var pct   = total > 0 ? Math.round(lost * 100 / total) : 0;

			if (totalEl) totalEl.firstChild.data = total + ' pkts';
			if (rxEl)    rxEl.firstChild.data    = rx + ' pkts';
			if (lostEl)  lostEl.firstChild.data  = lost + ' pkts';
			if (lossEl)  lossEl.firstChild.data  = pct + '%';
		}
	},

	startPolling: function(tab) {
		var self = this;
		var ctx  = graphCtx;
		if (!ctx) return;

		pollFn = L.bind(function() {
			return L.resolveDefault(callUdpRead(), { result: [] }).then(function(res) {
				var data        = Array.isArray(res.result) ? res.result : [];
				var data_wanted = Math.floor(ctx.width / ctx.step);
				var lastEntry   = null;
				var i;

				for (i = 0; i < data.length; i++) {
					var entry = data[i];
					if (!Array.isArray(entry) || entry[0] <= ctx.timestamp)
						continue;
					ctx.timestamp = entry[0];
					var speed = entry[1] || 0;
					ctx.values.push(speed);
					if (ctx.values.length > data_wanted)
						ctx.values = ctx.values.slice(ctx.values.length - data_wanted);
					if (speed > ctx.peak) ctx.peak = speed;
					if (speed > 0) { ctx.sum += speed; ctx.count++; }
					lastEntry = entry;
				}

				self.redrawGraph(tab, lastEntry);
			});
		}, this);

		poll.add(pollFn, pollInterval);
	},

	stopPolling: function() {
		if (pollFn) {
			poll.remove(pollFn);
			pollFn = null;
		}
		graphCtx = null;
		isRxMode = false;
	},

	render: function(data) {
		var self   = this;
		var svg    = data[0];
		var status = data[1] || {};

		/* reset any stale state from a previous render */
		this.stopPolling();

		/* --- config form elements --- */
		var modeSelect = E('select', { 'class': 'cbi-input-select' }, [
			E('option', { 'value': 'rx' }, _('RX (Receiver)')),
			E('option', { 'value': 'tx' }, _('TX (Transmitter)'))
		]);

		var localIpInput = E('input', {
			'type': 'text',
			'class': 'cbi-input-text',
			'placeholder': '10.0.0.1'
		});

		var destIpInput = E('input', {
			'type': 'text',
			'class': 'cbi-input-text',
			'placeholder': '224.1.1.1'
		});

		var portInput = E('input', {
			'type': 'number',
			'class': 'cbi-input-text',
			'value': '56999',
			'min': '1',
			'max': '65535',
			'style': 'width:6em'
		});

		var pktLenInput = E('input', {
			'type': 'number',
			'class': 'cbi-input-text',
			'value': '512',
			'min': '1',
			'style': 'width:6em'
		});

		var bwInput = E('input', {
			'type': 'number',
			'class': 'cbi-input-text',
			'value': '128',
			'min': '1',
			'style': 'width:6em'
		});

		var txOnlyRows = [];

		var pktLenRow = E('tr', { 'class': 'tr' }, [
			E('td', { 'class': 'td left', 'style': 'width:180px' }, _('Packet Length (bytes)')),
			E('td', { 'class': 'td' }, pktLenInput)
		]);
		var bwRow = E('tr', { 'class': 'tr' }, [
			E('td', { 'class': 'td left' }, _('Bandwidth Limit (KB/s)')),
			E('td', { 'class': 'td' }, bwInput)
		]);
		txOnlyRows = [ pktLenRow, bwRow ];

		var setTxOnlyVisible = function(visible) {
			txOnlyRows.forEach(function(row) {
				row.style.display = visible ? '' : 'none';
			});
		};

		/* hide TX-only rows initially (RX mode default) */
		setTxOnlyVisible(false);

		modeSelect.addEventListener('change', function() {
			setTxOnlyVisible(this.value === 'tx');
		});

		var startStopBtn = E('button', {
			'class': 'btn cbi-button cbi-button-action'
		}, status.running ? _('Stop') : _('Start'));

		var setFormEnabled = function(enabled) {
			modeSelect.disabled   = !enabled;
			localIpInput.disabled = !enabled;
			destIpInput.disabled  = !enabled;
			portInput.disabled    = !enabled;
			pktLenInput.disabled  = !enabled;
			bwInput.disabled      = !enabled;
		};

		var configForm = E('div', { 'class': 'cbi-section' }, [
			E('div', { 'class': 'cbi-section-node' }, [
				E('table', { 'class': 'table' }, [
					E('tr', { 'class': 'tr' }, [
						E('td', { 'class': 'td left', 'style': 'width:180px' }, _('Mode')),
						E('td', { 'class': 'td' }, modeSelect)
					]),
					E('tr', { 'class': 'tr' }, [
						E('td', { 'class': 'td left' }, _('Local IP')),
						E('td', { 'class': 'td' }, localIpInput)
					]),
					E('tr', { 'class': 'tr' }, [
						E('td', { 'class': 'td left' }, _('Destination IP')),
						E('td', { 'class': 'td' }, destIpInput)
					]),
					E('tr', { 'class': 'tr' }, [
						E('td', { 'class': 'td left' }, _('Port')),
						E('td', { 'class': 'td' }, portInput)
					]),
					pktLenRow,
					bwRow
				])
			])
		]);

		var v = E('div', {}, [
			E('h2', {}, _('UDP Bandwidth Test')),
			configForm,
			E('div', { 'style': 'margin:0.5em 0' }, startStopBtn),
			svg,
			E('div', { 'class': 'right' }, E('small', { 'id': 'udp_scale' }, [ '-' ])),
			E('br'),
			E('table', { 'class': 'table', 'style': 'width:100%;table-layout:fixed' }, [
				E('tr', { 'class': 'tr' }, [
					E('td', { 'class': 'td right top' },
						E('strong', { 'style': 'border-bottom:2px solid #0066cc' }, [ _('Speed:') ])),
					E('td', { 'class': 'td', 'id': 'udp_cur' },  [ '0 KB/s' ]),
					E('td', { 'class': 'td right top' }, E('strong', {}, [ _('Average:') ])),
					E('td', { 'class': 'td', 'id': 'udp_avg' },  [ '0 KB/s' ]),
					E('td', { 'class': 'td right top' }, E('strong', {}, [ _('Peak:') ])),
					E('td', { 'class': 'td', 'id': 'udp_peak' }, [ '0 KB/s' ])
				]),
				/* packet loss row — hidden until RX mode data arrives */
				E('tr', { 'class': 'tr', 'id': 'udp_loss_row', 'style': 'display:none' }, [
					E('td', { 'class': 'td right top' }, E('strong', {}, [ _('Total:') ])),
					E('td', { 'class': 'td', 'id': 'udp_total' }, [ '0 pkts' ]),
					E('td', { 'class': 'td right top' }, E('strong', {}, [ _('Received:') ])),
					E('td', { 'class': 'td', 'id': 'udp_rx' },    [ '0 pkts' ]),
					E('td', { 'class': 'td right top' }, E('strong', {}, [ _('Lost:') ])),
					E('td', { 'class': 'td', 'id': 'udp_lost' },  [ '0 pkts' ])
				]),
				E('tr', { 'class': 'tr', 'id': 'udp_lossrate_row', 'style': 'display:none' }, [
					E('td', { 'class': 'td right top', 'colspan': '4' }),
					E('td', { 'class': 'td right top' }, E('strong', {}, [ _('Loss Rate:') ])),
					E('td', { 'class': 'td', 'id': 'udp_loss_pct' }, [ '0%' ])
				])
			])
		]);

		/* start/stop button handler */
		startStopBtn.addEventListener('click', function() {
			var running = (startStopBtn.textContent.trim() === _('Stop'));
			startStopBtn.disabled = true;

			if (running) {
				callUdpStop().then(function() {
					startStopBtn.textContent = _('Start');
					startStopBtn.disabled    = false;
					self.stopPolling();
					setFormEnabled(true);
					/* hide loss rows */
					var lr = v.querySelector('#udp_loss_row');
					var rr = v.querySelector('#udp_lossrate_row');
					if (lr) lr.style.display = 'none';
					if (rr) rr.style.display = 'none';
				}).catch(function() {
					startStopBtn.disabled = false;
				});
			} else {
				var mode    = modeSelect.value;
				var localIp = localIpInput.value.trim();
				var destIp  = destIpInput.value.trim();
				var port    = parseInt(portInput.value) || 56999;
				var pktLen  = parseInt(pktLenInput.value) || 512;
				var bw      = parseInt(bwInput.value) || 128;

				if (!localIp) {
					ui.addNotification(null, E('p', _('Local IP is required')), 'warning');
					startStopBtn.disabled = false;
					return;
				}
				if (!destIp) {
					ui.addNotification(null, E('p', _('Destination IP is required')), 'warning');
					startStopBtn.disabled = false;
					return;
				}

				var txMode = (mode === 'tx');
				isRxMode   = !txMode;

				/* show loss stats row when in RX mode */
				if (isRxMode) {
					var lr = v.querySelector('#udp_loss_row');
					var rr = v.querySelector('#udp_lossrate_row');
					if (lr) lr.style.display = '';
					if (rr) rr.style.display = '';
				}

				callUdpStart(localIp, destIp, txMode, port, pktLen, bw).then(function() {
					startStopBtn.textContent = _('Stop');
					startStopBtn.disabled    = false;
					setFormEnabled(false);
					self.initGraph(svg);
					self.startPolling(v);
				}).catch(function() {
					startStopBtn.disabled = false;
				});
			}
		});

		/* restore running state when navigating back to this page */
		if (status.running) {
			setFormEnabled(false);
			startStopBtn.textContent = _('Stop');
			this.initGraph(svg);
			this.startPolling(v);
		}

		return v;
	},

	handleSaveApply: null,
	handleSave:      null,
	handleReset:     null
});
