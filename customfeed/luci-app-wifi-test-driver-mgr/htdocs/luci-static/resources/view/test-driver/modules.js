'use strict';
'require view';
'require dom';
'require ui';
'require rpc';

var callListModules = rpc.declare({
	object: 'luci.test_driver',
	method: 'list_modules',
	expect: { modules: [] }
});

var callLoadModule = rpc.declare({
	object: 'luci.test_driver',
	method: 'load_module',
	params: [ 'filename', 'args' ]
});

var callUnloadModule = rpc.declare({
	object: 'luci.test_driver',
	method: 'unload_module',
	params: [ 'name' ]
});

var callDeleteModule = rpc.declare({
	object: 'luci.test_driver',
	method: 'delete_module',
	params: [ 'filename' ]
});

var callMoveUploaded = rpc.declare({
	object: 'luci.test_driver',
	method: 'move_uploaded',
	params: [ 'filename', 'destname' ]
});

return view.extend({
	load: function() {
		return callListModules();
	},

	_handleRpcError: function(err) {
		ui.addNotification(null, E('p', _('RPC error: ') + (err.message || err)), 'error');
	},

	_buildRow: function(table, mod) {
		var self = this;
		var modname = mod.filename.replace(/\.ko$/, '').replace(/-/g, '_');
		var sizeStr = mod.size > 1024
			? (mod.size / 1024).toFixed(1) + ' KB'
			: mod.size + ' B';

		var actionBtn;
		if (mod.loaded) {
			actionBtn = E('button', {
				'class': 'btn cbi-button cbi-button-action',
				'click': function(ev) { self.handleUnload(ev, modname, table); }
			}, _('Unload'));
		} else {
			var argsInput = E('input', {
				'type': 'text',
				'class': 'cbi-input-text',
				'placeholder': _('e.g. param1=val1'),
				'style': 'width:160px;margin-right:4px;font-size:90%;vertical-align:middle'
			});
			(function(fname, input) {
				actionBtn = E('span', {}, [
					input,
					E('button', {
						'class': 'btn cbi-button cbi-button-action',
						'click': function(ev) {
							self.handleLoad(ev, fname, input.value.trim(), table);
						}
					}, _('Load'))
				]);
			})(mod.filename, argsInput);
		}

		var deleteBtn = E('button', {
			'class': 'btn cbi-button cbi-button-negative',
			'style': 'margin-left:4px',
			'click': function(ev) { self.handleDelete(ev, mod.filename, table); }
		}, _('Delete'));

		table.appendChild(E('tr', { 'class': 'tr' }, [
			E('td', { 'class': 'td' }, mod.filename),
			E('td', { 'class': 'td' }, sizeStr),
			E('td', { 'class': 'td' }, mod.loaded
				? E('span', { 'style': 'color:green' }, _('Loaded'))
				: E('span', { 'style': 'color:gray' }, _('Not loaded'))),
			E('td', { 'class': 'td cbi-section-actions' }, [ actionBtn, deleteBtn ])
		]));
	},

	render: function(modules) {
		var self = this;

		var table = E('table', { 'class': 'table cbi-section-table' }, [
			E('tr', { 'class': 'tr table-titles' }, [
				E('th', { 'class': 'th' }, _('Filename')),
				E('th', { 'class': 'th' }, _('Size')),
				E('th', { 'class': 'th' }, _('Status')),
				E('th', { 'class': 'th cbi-section-actions' }, _('Actions'))
			])
		]);

		if (!modules.length) {
			table.appendChild(E('tr', { 'class': 'tr placeholder' }, [
				E('td', { 'class': 'td', 'colspan': '4' }, _('No test drivers in /test_ko'))
			]));
		}

		modules.forEach(function(mod) {
			self._buildRow(table, mod);
		});

		var uploadBtn = E('button', {
			'class': 'btn cbi-button cbi-button-action',
			'click': function(ev) { self.handleUpload(ev, table); }
		}, _('Upload .ko file'));

		return E('div', {}, [
			E('h2', {}, _('Test Drivers')),
			E('p', {}, _('Manage test driver modules in /test_ko. Upload .ko files, then load or unload them.')),
			table,
			E('div', { 'style': 'margin-top:1em' }, uploadBtn)
		]);
	},

	handleUpload: function(ev, table) {
		var self = this;
		return ui.uploadFile('/tmp/test-ko-upload.ko').then(function(reply) {
			if (!reply || !reply.name)
				return;
			var origname = reply.name.replace(/.*[/\\]/, '');
			if (!origname.match(/\.ko$/)) {
				ui.addNotification(null, E('p', _('Only .ko files are supported.')), 'error');
				return;
			}
			return callMoveUploaded('/tmp/test-ko-upload.ko', origname).then(function(res) {
				if (res.code !== 0) {
					ui.addNotification(null, E('p', _('Failed to save module: ') + (res.error || '')), 'error');
					return;
				}
				return self.refreshTable(table);
			});
		}).catch(self._handleRpcError);
	},

	handleLoad: function(ev, filename, args, table) {
		var self = this;
		var btn = ev.target;
		btn.disabled = true;
		return callLoadModule(filename, args || '').then(function(res) {
			if (res.code !== 0) {
				btn.disabled = false;
				ui.addNotification(null, E('p', _('Failed to load module: ') + (res.error || '')), 'error');
				return;
			}
			return self.refreshTable(table);
		}).catch(function(err) {
			btn.disabled = false;
			self._handleRpcError(err);
		});
	},

	handleUnload: function(ev, name, table) {
		var self = this;
		var btn = ev.target;
		btn.disabled = true;
		return callUnloadModule(name).then(function(res) {
			if (res.code !== 0) {
				btn.disabled = false;
				ui.addNotification(null, E('p', _('Failed to unload module: ') + (res.error || '')), 'error');
				return;
			}
			return self.refreshTable(table);
		}).catch(function(err) {
			btn.disabled = false;
			self._handleRpcError(err);
		});
	},

	handleDelete: function(ev, filename, table) {
		var self = this;
		return ui.showModal(_('Confirm Delete'), [
			E('p', _('Delete %s from /test_ko?').format(filename)),
			E('div', { 'class': 'right' }, [
				E('button', {
					'class': 'btn',
					'click': ui.hideModal
				}, _('Cancel')),
				E('button', {
					'class': 'btn cbi-button-negative',
					'style': 'margin-left:4px',
					'click': function() {
						this.disabled = true;
						ui.hideModal();
						callDeleteModule(filename).then(function(res) {
							if (res.code !== 0) {
								ui.addNotification(null, E('p', _('Failed to delete module: ') + (res.error || '')), 'error');
								return;
							}
							return self.refreshTable(table);
						}).catch(self._handleRpcError);
					}
				}, _('Delete'))
			])
		]);
	},

	refreshTable: function(table) {
		var self = this;
		return callListModules().then(function(modules) {
			var rows = table.querySelectorAll('tr.tr:not(.table-titles):not(.placeholder)');
			rows.forEach(function(r) { r.remove(); });
			var placeholder = table.querySelector('tr.placeholder');
			if (placeholder) placeholder.remove();

			if (!modules.length) {
				table.appendChild(E('tr', { 'class': 'tr placeholder' }, [
					E('td', { 'class': 'td', 'colspan': '4' }, _('No test drivers in /test_ko'))
				]));
			} else {
				modules.forEach(function(mod) {
					self._buildRow(table, mod);
				});
			}
		}).catch(self._handleRpcError);
	}
});
