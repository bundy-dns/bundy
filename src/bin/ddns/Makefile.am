SUBDIRS = . tests

pkglibexecdir = $(libexecdir)/@PACKAGE@

pkglibexec_SCRIPTS = bundy-ddns

bundy_ddnsdir = $(pkgdatadir)
bundy_ddns_DATA = ddns.spec

nodist_pylogmessage_PYTHON = $(PYTHON_LOGMSGPKG_DIR)/work/ddns_messages.py
pylogmessagedir = $(pyexecdir)/bundy/log_messages/

CLEANFILES = bundy-ddns ddns.pyc
CLEANFILES += $(PYTHON_LOGMSGPKG_DIR)/work/ddns_messages.py
CLEANFILES += $(PYTHON_LOGMSGPKG_DIR)/work/ddns_messages.pyc

EXTRA_DIST =  ddns_messages.mes ddns.spec

man_MANS = bundy-ddns.8
DISTCLEANFILES = $(man_MANS)
EXTRA_DIST += $(man_MANS) bundy-ddns.xml

if GENERATE_DOCS

bundy-ddns.8: bundy-ddns.xml
	@XSLTPROC@ --novalid --xinclude --nonet -o $@ http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl $(srcdir)/bundy-ddns.xml

else

$(man_MANS):
	@echo Man generation disabled.  Creating dummy $@.  Configure with --enable-generate-docs to enable it.
	@echo Man generation disabled.  Remove this file, configure with --enable-generate-docs, and rebuild BUNDY > $@

endif

# Define rule to build logging source files from message file
$(PYTHON_LOGMSGPKG_DIR)/work/ddns_messages.py : ddns_messages.mes
	$(top_builddir)/src/lib/log/compiler/message \
	-d $(PYTHON_LOGMSGPKG_DIR)/work -p $(srcdir)/ddns_messages.mes

# this is done here since configure.ac AC_OUTPUT doesn't expand exec_prefix
bundy-ddns: ddns.py $(PYTHON_LOGMSGPKG_DIR)/work/ddns_messages.py
	$(SED) -e "s|@@PYTHONPATH@@|@pyexecdir@|" \
	       -e "s|@@LOCALSTATEDIR@@|$(localstatedir)|" ddns.py >$@
	chmod a+x $@

CLEANDIRS = __pycache__

clean-local:
	rm -rf $(CLEANDIRS)
