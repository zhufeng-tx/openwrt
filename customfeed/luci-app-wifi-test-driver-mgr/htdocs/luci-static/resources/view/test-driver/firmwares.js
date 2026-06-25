'use strict';
'require view';
'require dom';
'require ui';
'require rpc';

var callListFirmwares = rpc.declare({
	object: 'luci.test_driver',
	method: 'list_firmwares',
	expect: { firmwares: [] }
});

var callMoveUploadedFirmware = rpc.declare({
	object: 'luci.test_driver',
	method: 'move_uploaded_firmware',
	params: [ 'filename', 'destname' ]
});

var callCreateSymlink = rpc.declare({
	object: 'luci.test_driver',
	method: 'create_symlink',
	params: [ 'filename', 'linkname' ]
});

var callRemoveSymlink = rpc.declare({
	object: 'luci.test_driver',
	method: 'remove_symlink',
	params: [ 'linkname' ]
});

var callDeleteFirmware = rpc.declare({
	object: 'luci.test_driver',
	method: 'delete_firmware',
	params: [ 'filename' ]
});

return view.extend({
	load: function() {
		return callListFirmwares();
	},

	_handleRpcError: function(err) {
		ui.addNotification(null, E('p', _('RPC error: ') + (err.message || err)), 'error');
	},

	_buildRow: function(table, fw) {
		var self = this;
		var sizeStr = fw.size > 1024
			? (fw.size / 1024).toFixed(1) + ' KB'
			: fw.size + ' B';

		var symlinkCell;
		var actionBtn;

		if (fw.linked) {
			symlinkCell = E('span', { 'style': 'color:green' },
				_('Linked as: %s').format(fw.link_name));
			actionBtn = E('button', {
				'class': 'btn cbi-button cbi-button-action',
				'click': function(ev) { self.handleRemoveSymlink(ev, fw.link_name, table); }
			}, _('Remove Symlink'));
		} else {
			symlinkCell = E('span', { 'style': 'color:gray' }, _('Not linked'));
			(function(fname) {
				actionBtn = E('button', {
					'class': 'btn cbi-button cbi-button-action',
					'click': function(ev) { self.handleLink(ev, fname, table); }
				}, _('Link'));
			})(fw.filename);
		}

		var deleteBtn = E('button', {
			'class': 'btn cbi-button cbi-button-negative',
			'style': 'margin-left:4px',
			'click': function(ev) { self.handleDelete(ev, fw.filename, table); }
		}, _('Delete'));

		table.appendChild(E('tr', { 'class': 'tr' }, [
			E('td', { 'class': 'td' }, fw.filename),
			E('td', { 'class': 'td' }, sizeStr),
			E('td', { 'class': 'td' }, [ symlinkCell ]),
			E('td', { 'class': 'td cbi-section-actions' }, [ actionBtn, deleteBtn ])
		]));
	},

	render: function(firmwares) {
		var self = this;

		var table = E('table', { 'class': 'table cbi-section-table' }, [
			E('tr', { 'class': 'tr table-titles' }, [
				E('th', { 'class': 'th' }, _('Filename')),
				E('th', { 'class': 'th' }, _('Size')),
				E('th', { 'class': 'th' }, _('Symlink in /lib/firmware')),
				E('th', { 'class': 'th cbi-section-actions' }, _('Actions'))
			])
		]);

		if (!firmwares.length) {
			table.appendChild(E('tr', { 'class': 'tr placeholder' }, [
				E('td', { 'class': 'td', 'colspan': '4' }, _('No firmware files in /test_firmware'))
			]));
		}

		firmwares.forEach(function(fw) {
			self._buildRow(table, fw);
		});

		var uploadBtn = E('button', {
			'class': 'btn cbi-button cbi-button-action',
			'click': function(ev) { self.handleUpload(ev, table); }
		}, _('Upload firmware file'));

		return E('div', {}, [
			E('h2', {}, _('Firmwares')),
			E('p', {}, _('Manage firmware files in /test_firmware. Upload files, then symlink them into /lib/firmware with an optional rename.')),
			table,
			E('div', { 'style': 'margin-top:1em' }, uploadBtn)
		]);
	},

	handleUpload: function(ev, table) {
		var self = this;
		return ui.uploadFile('/tmp/test-fw-upload.bin').then(function(reply) {
			if (!reply || !reply.name)
				return;
			var origname = reply.name.replace(/.*[/\\]/, '');
			if (!origname) {
				ui.addNotification(null, E('p', _('Could not determine filename.')), 'error');
				return;
			}
			return callMoveUploadedFirmware('/tmp/test-fw-upload.bin', origname).then(function(res) {
				if (res.code !== 0) {
					ui.addNotification(null, E('p', _('Failed to save firmware: ') + (res.error || '')), 'error');
					return;
				}
				return self.refreshTable(table);
			});
		}).catch(self._handleRpcError);
	},

	handleLink: function(ev, filename, table) {
		var self = this;
		var nameInput = E('input', {
			'type': 'text',
			'class': 'cbi-input-text',
			'value': filename,
			'style': 'width:100%;margin-top:4px'
		});
		return ui.showModal(_('Create Firmware Symlink'), [
			E('p', _('Creates /lib/firmware/<name> → /test_firmware/%s').format(filename)),
			E('label', {}, _('Symlink name in /lib/firmware/:')),
			nameInput,
			E('div', { 'class': 'right', 'style': 'margin-top:1em' }, [
				E('button', {
					'class': 'btn',
					'click': ui.hideModal
				}, _('Cancel')),
				E('button', {
					'class': 'btn cbi-button-action',
					'style': 'margin-left:4px',
					'click': function() {
						var linkname = nameInput.value.trim();
						if (!linkname) {
							ui.addNotification(null, E('p', _('Link name cannot be empty.')), 'error');
							return;
						}
						ui.hideModal();
						callCreateSymlink(filename, linkname).then(function(res) {
							if (res.code !== 0) {
								ui.addNotification(null, E('p', _('Failed to create symlink: ') + (res.error || '')), 'error');
								return;
							}
							return self.refreshTable(table);
						}).catch(self._handleRpcError);
					}
				}, _('Create'))
			])
		]);
	},

	handleRemoveSymlink: function(ev, linkname, table) {
		var self = this;
		var btn = ev.target;
		btn.disabled = true;
		return callRemoveSymlink(linkname).then(function(res) {
			if (res.code !== 0) {
				btn.disabled = false;
				ui.addNotification(null, E('p', _('Failed to remove symlink: ') + (res.error || '')), 'error');
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
			E('p', _('Delete %s from /test_firmware? Any symlinks pointing to it will also be removed.').format(filename)),
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
						callDeleteFirmware(filename).then(function(res) {
							if (res.code !== 0) {
								ui.addNotification(null, E('p', _('Failed to delete firmware: ') + (res.error || '')), 'error');
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
		return callListFirmwares().then(function(firmwares) {
			var rows = table.querySelectorAll('tr.tr:not(.table-titles):not(.placeholder)');
			rows.forEach(function(r) { r.remove(); });
			var placeholder = table.querySelector('tr.placeholder');
			if (placeholder) placeholder.remove();

			if (!firmwares.length) {
				table.appendChild(E('tr', { 'class': 'tr placeholder' }, [
					E('td', { 'class': 'td', 'colspan': '4' }, _('No firmware files in /test_firmware'))
				]));
			} else {
				firmwares.forEach(function(fw) {
					self._buildRow(table, fw);
				});
			}
		}).catch(self._handleRpcError);
	}
});
