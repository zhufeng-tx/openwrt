define Package/base-files/install-target
	$(INSTALL_DIR) $(1)/etc/rc.d
	$(LN) ../init.d/telnetd $(1)/etc/rc.d/S50telnetd
	$(LN) ../init.d/telnetd $(1)/etc/rc.d/K50telnetd
endef
