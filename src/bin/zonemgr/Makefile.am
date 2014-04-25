SUBDIRS = . tests

pkglibexecdir = $(libexecdir)/@PACKAGE@

pkglibexec_SCRIPTS = bundy-zonemgr

bundy_zonemgrdir = $(pkgdatadir)
bundy_zonemgr_DATA = zonemgr.spec

nodist_pylogmessage_PYTHON = $(PYTHON_LOGMSGPKG_DIR)/work/zonemgr_messages.py
pylogmessagedir = $(pyexecdir)/bundy/log_messages/

CLEANFILES  = bundy-zonemgr zonemgr.pyc zonemgr.spec
CLEANFILES += $(PYTHON_LOGMSGPKG_DIR)/work/zonemgr_messages.py
CLEANFILES += $(PYTHON_LOGMSGPKG_DIR)/work/zonemgr_messages.pyc

man_MANS = bundy-zonemgr.8
DISTCLEANFILES = $(man_MANS)
EXTRA_DIST = $(man_MANS) bundy-zonemgr.xml zonemgr_messages.mes

if GENERATE_DOCS

bundy-zonemgr.8: bundy-zonemgr.xml
	@XSLTPROC@ --novalid --xinclude --nonet -o $@ http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl $(srcdir)/bundy-zonemgr.xml

else

$(man_MANS):
	@echo Man generation disabled.  Creating dummy $@.  Configure with --enable-generate-docs to enable it.
	@echo Man generation disabled.  Remove this file, configure with --enable-generate-docs, and rebuild BUNDY > $@

endif

# Build logging source file from message files
$(PYTHON_LOGMSGPKG_DIR)/work/zonemgr_messages.py : zonemgr_messages.mes
	$(top_builddir)/src/lib/log/compiler/message \
	-d $(PYTHON_LOGMSGPKG_DIR)/work -p $(srcdir)/zonemgr_messages.mes

zonemgr.spec: zonemgr.spec.pre
	$(SED) -e "s|@@LOCALSTATEDIR@@|$(localstatedir)|" zonemgr.spec.pre >$@

bundy-zonemgr: zonemgr.py $(PYTHON_LOGMSGPKG_DIR)/work/zonemgr_messages.py
	$(SED) -e "s|@@PYTHONPATH@@|@pyexecdir@|" \
	       -e "s|@@LOCALSTATEDIR@@|$(localstatedir)|" zonemgr.py >$@
	chmod a+x $@

CLEANDIRS = __pycache__

clean-local:
	rm -rf $(CLEANDIRS)
