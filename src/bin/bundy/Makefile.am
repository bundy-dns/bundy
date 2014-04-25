SUBDIRS = . tests

sbin_SCRIPTS = bundy
pkglibexec_SCRIPTS = bundy-init
CLEANFILES = bundy-init bundy-init.pyc init.pyc
CLEANFILES += $(PYTHON_LOGMSGPKG_DIR)/work/init_messages.py
CLEANFILES += $(PYTHON_LOGMSGPKG_DIR)/work/init_messages.pyc

pkglibexecdir = $(libexecdir)/@PACKAGE@

nodist_pylogmessage_PYTHON = $(PYTHON_LOGMSGPKG_DIR)/work/init_messages.py
pylogmessagedir = $(pyexecdir)/bundy/log_messages/

noinst_SCRIPTS = run_bundy.sh

bundydir = $(pkgdatadir)
bundy_DATA = init.spec
EXTRA_DIST = init.spec bundy.in

man_MANS = bundy-init.8 bundy.8
DISTCLEANFILES = $(man_MANS) bundy
EXTRA_DIST += $(man_MANS) bundy-init.xml bundy.xml init_messages.mes

if GENERATE_DOCS

bundy.8: bundy.xml
	@XSLTPROC@ --novalid --xinclude --nonet -o $@ http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl $(srcdir)/bundy.xml

bundy-init.8: bundy-init.xml
	@XSLTPROC@ --novalid --xinclude --nonet -o $@ http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl $(srcdir)/bundy-init.xml

#dist-local-check-mans-enabled:
#	@if grep "Man generation disabled" $(man_MANS) >/dev/null; then $(RM) $(man_MANS); fi

else

$(man_MANS):
	@echo Man generation disabled.  Creating dummy $@.  Configure with --enable-generate-docs to enable it.
	@echo Man generation disabled.  Remove this file, configure with --enable-generate-docs, and rebuild BUNDY > $@

#dist-local-check-mans-enabled:
#	@echo "*** --enable-generate-docs must be used in order to make dist"
#	@false

endif

$(PYTHON_LOGMSGPKG_DIR)/work/init_messages.py : init_messages.mes
	$(top_builddir)/src/lib/log/compiler/message \
	-d $(PYTHON_LOGMSGPKG_DIR)/work -p $(srcdir)/init_messages.mes

# this is done here since configure.ac AC_OUTPUT doesn't expand exec_prefix
bundy-init: init.py $(PYTHON_LOGMSGPKG_DIR)/work/init_messages.py
	$(SED) -e "s|@@PYTHONPATH@@|@pyexecdir@|" \
	       -e "s|@@LIBDIR@@|$(libdir)|" \
	       -e "s|@@LIBEXECDIR@@|$(pkglibexecdir)|" init.py >$@
	chmod a+x $@

pytest:
	$(SHELL) tests/bundy_test

CLEANDIRS = __pycache__

clean-local:
	rm -rf $(CLEANDIRS)
