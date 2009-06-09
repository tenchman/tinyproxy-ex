# Redhat spec files (from RPMs)
REDHAT_DIR = packaging/redhat
REDHAT = \
	$(REDHAT_DIR)/tinyproxy-1.5.2-config-patch \
	$(REDHAT_DIR)/tinyproxy-initd \
	$(REDHAT_DIR)/tinyproxy.spec

AUTO_FILES = config.guess config.sub depcomp ltmain.sh missing ylwrap m4/*.m4

# Packaging files
PACKAGING = $(REDHAT)

EXTRA_DIST = TODO $(PACKAGING)
SUBDIRS = src doc

ACLOCAL_AMFLAGS = -I m4
install-data-local: tinyproxy-configure-file tinyproxy-html-files
uninstall-local: uninstall-tinyproxy-configure-file uninstall-tinyproxy-html-files

# Install the configuration file if it doesn't already exist
tinyproxy-configure-file:
	$(mkinstalldirs) $(DESTDIR)@TINYPROXY_CONFIG_DIR@
	$(INSTALL) -m 600 $(srcdir)/doc/tinyproxy.conf \
		$(DESTDIR)@TINYPROXY_CONFIG_DIR@/@TINYPROXY_CONFIG_FILE@-dist
	test -f $(DESTDIR)@TINYPROXY_CONFIG_DIR@/@TINYPROXY_CONFIG_FILE@ \
		|| $(INSTALL) -m 600 $(srcdir)/doc/tinyproxy.conf \
			$(DESTDIR)@TINYPROXY_CONFIG_DIR@/@TINYPROXY_CONFIG_FILE@
	@echo ""
	@echo "A configuration file has been copied to:"
	@echo ""
	@echo "@TINYPROXY_CONFIG_DIR@/@TINYPROXY_CONFIG_FILE@-dist"
	@echo ""
	@echo "You will need to rename this file to:"
	@echo ""
	@echo "@TINYPROXY_CONFIG_DIR@/@TINYPROXY_CONFIG_FILE@"
	@echo ""
	@echo "and modify the values to suit your local system."
	@echo ""
	@echo "All the configuration directives are commented in the file, so"
	@echo "you should not have any problems configuring your system."
	@echo ""

# Install the HTML files
tinyproxy-html-files:
	$(mkinstalldirs) $(DESTDIR)$(datadir)/@PACKAGE@

	for file in debug default stats 403; do \
	  $(INSTALL) -m 644 $(srcdir)/doc/$$file.html $(DESTDIR)$(datadir)/@PACKAGE@/$$file.html.dist ; \
	  test -f $(DESTDIR)$(datadir)/@PACKAGE@/$$file.html || \
	    $(INSTALL) -m 644 $(srcdir)/doc/$$file.html $(DESTDIR)$(datadir)/@PACKAGE@/$$file.html ; \
	done
	for file in $(srcdir)/doc/icons/*.png; do \
	  $(INSTALL) -m 644 $$file $(DESTDIR)$(datadir)/@PACKAGE@/ ; \
	done
	$(INSTALL) -m 644 $(srcdir)/doc/HTML_VARIABLES $(DESTDIR)$(datadir)/@PACKAGE@/HTML_VARIABLES
	$(INSTALL) -m 644 $(srcdir)/doc/tinyproxy-ex.css $(DESTDIR)$(datadir)/@PACKAGE@/tinyproxy-ex.css

uninstall-tinyproxy-html-files:
	rm -f $(DESTDIR)$(datadir)/@PACKAGE@/*.dist

uninstall-tinyproxy-configure-file:
	rm -f $(DESTDIR)@TINYPROXY_CONFIG_DIR@/@TINYPROXY_CONFIG_FILE@-dist

