'use strict';
'require view';
'require poll';
'require request';
'require rpc';
'require ui';

var callTcpStart = rpc.declare({
	object: 'luci.bw_test',
	method: 'tcp_start',
	params: [ 'port', 'ipaddr', 'nodelay', 'bufsize', 'interval' ],
	expect: { code: 0 }
});

var callTcpStop = rpc.declare({
	object: 'luci.bw_test',
	method: 'tcp_stop'
});

var callTcpStatus = rpc.declare({
	object: 'luci.bw_test',
	method: 'tcp_status',
	expect: { running: false }
});

var callTcpRead = rpc.declare({
	object: 'luci.bw_test',
	method: 'tcp_read',
	expect: { result: [] }
});

/* module-level graph state */
var graphCtx   = null;
var pollFn     = null;
var pollInterval = 3;

Math.log2 = Math.log2 || function(x) { return Math.log(x) * Math.LOG2E; };

return view.extend({
	load: function() {
		return Promise.all([
			this.loadSVG(L.resource('svg/bw-test.svg')),
			L.resolveDefault(callTcpStatus(), { running: false })
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

	redrawGraph: function(tab) {
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

		var scaleEl = tab.querySelector('#tcp_scale');
		if (scaleEl) scaleEl.firstChild.data =
			'(%d minute window, %d second interval)'.format(
				Math.floor(values.length * pollInterval / 60), pollInterval);

		var curEl  = tab.querySelector('#tcp_cur');
		var avgEl  = tab.querySelector('#tcp_avg');
		var peakEl = tab.querySelector('#tcp_peak');
		if (curEl)  curEl.firstChild.data  = cur + ' KB/s';
		if (avgEl)  avgEl.firstChild.data  = avg + ' KB/s';
		if (peakEl) peakEl.firstChild.data = ctx.peak + ' KB/s';
	},

	startPolling: function(tab) {
		var self = this;
		var ctx  = graphCtx;
		if (!ctx) return;

		pollFn = L.bind(function() {
			return L.resolveDefault(callTcpRead(), { result: [] }).then(function(res) {
				var data       = Array.isArray(res.result) ? res.result : [];
				var data_wanted = Math.floor(ctx.width / ctx.step);
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
				}

				self.redrawGraph(tab);
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
	},

	render: function(data) {
		var self   = this;
		var svg    = data[0];
		var status = data[1] || {};

		/* reset any stale state from a previous render */
		this.stopPolling();

		/* --- config form elements --- */
		var modeSelect = E('select', { 'class': 'cbi-input-select' }, [
			E('option', { 'value': 'rx' }, _('RX (Server)')),
			E('option', { 'value': 'tx' }, _('TX (Client)'))
		]);

		var ipInput = E('input', {
			'type': 'text',
			'class': 'cbi-input-text',
			'placeholder': '192.168.x.x',
			'disabled': true
		});

		var portInput = E('input', {
			'type': 'number',
			'class': 'cbi-input-text',
			'value': '60001',
			'min': '1',
			'max': '65535',
			'style': 'width:6em'
		});

		var intervalInput = E('input', {
			'type': 'number',
			'class': 'cbi-input-text',
			'value': '1000',
			'min': '100',
			'style': 'width:7em'
		});

		modeSelect.addEventListener('change', function() {
			ipInput.disabled = (this.value !== 'tx');
		});

		var startStopBtn = E('button', {
			'class': 'btn cbi-button cbi-button-action'
		}, status.running ? _('Stop') : _('Start'));

		var setFormEnabled = function(enabled) {
			modeSelect.disabled   = !enabled;
			ipInput.disabled      = !enabled || modeSelect.value !== 'tx';
			portInput.disabled    = !enabled;
			intervalInput.disabled = !enabled;
		};

		var configForm = E('div', { 'class': 'cbi-section' }, [
			E('div', { 'class': 'cbi-section-node' }, [
				E('table', { 'class': 'table' }, [
					E('tr', { 'class': 'tr' }, [
						E('td', { 'class': 'td left', 'style': 'width:180px' }, _('Mode')),
						E('td', { 'class': 'td' }, modeSelect)
					]),
					E('tr', { 'class': 'tr' }, [
						E('td', { 'class': 'td left' }, _('Remote IP (TX mode)')),
						E('td', { 'class': 'td' }, ipInput)
					]),
					E('tr', { 'class': 'tr' }, [
						E('td', { 'class': 'td left' }, _('Port')),
						E('td', { 'class': 'td' }, portInput)
					]),
					E('tr', { 'class': 'tr' }, [
						E('td', { 'class': 'td left' }, _('Stats Interval (ms)')),
						E('td', { 'class': 'td' }, intervalInput)
					])
				])
			])
		]);

		var v = E('div', {}, [
			E('h2', {}, _('TCP Bandwidth Test')),
			configForm,
			E('div', { 'style': 'margin:0.5em 0' }, startStopBtn),
			svg,
			E('div', { 'class': 'right' }, E('small', { 'id': 'tcp_scale' }, [ '-' ])),
			E('br'),
			E('table', { 'class': 'table', 'style': 'width:100%;table-layout:fixed' }, [
				E('tr', { 'class': 'tr' }, [
					E('td', { 'class': 'td right top' },
						E('strong', { 'style': 'border-bottom:2px solid #0066cc' }, [ _('Speed:') ])),
					E('td', { 'class': 'td', 'id': 'tcp_cur' },  [ '0 KB/s' ]),
					E('td', { 'class': 'td right top' }, E('strong', {}, [ _('Average:') ])),
					E('td', { 'class': 'td', 'id': 'tcp_avg' },  [ '0 KB/s' ]),
					E('td', { 'class': 'td right top' }, E('strong', {}, [ _('Peak:') ])),
					E('td', { 'class': 'td', 'id': 'tcp_peak' }, [ '0 KB/s' ])
				])
			])
		]);

		/* start/stop button handler */
		startStopBtn.addEventListener('click', function() {
			var running = (startStopBtn.textContent.trim() === _('Stop'));
			startStopBtn.disabled = true;

			if (running) {
				callTcpStop().then(function() {
					startStopBtn.textContent = _('Start');
					startStopBtn.disabled    = false;
					self.stopPolling();
					setFormEnabled(true);
				}).catch(function() {
					startStopBtn.disabled = false;
				});
			} else {
				var mode   = modeSelect.value;
				var ipaddr = (mode === 'tx') ? ipInput.value.trim() : '';
				var port   = parseInt(portInput.value)   || 60001;
				var ival   = parseInt(intervalInput.value) || 1000;

				if (mode === 'tx' && !ipaddr) {
					ui.addNotification(null, E('p', _('Remote IP is required for TX mode')), 'warning');
					startStopBtn.disabled = false;
					return;
				}

				callTcpStart(port, ipaddr, false, 0, ival).then(function() {
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
