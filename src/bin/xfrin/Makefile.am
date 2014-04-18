SUBDIRS = . tests

pkglibexecdir = $(libexecdir)/@PACKAGE@

pkglibexec_SCRIPTS = bundy-xfrin

bundy_xfrindir = $(pkgdatadir)
bundy_xfrin_DATA = xfrin.spec

nodist_pylogmessage_PYTHON = $(PYTHON_LOGMSGPKG_DIR)/work/xfrin_messages.py
pylogmessagedir = $(pyexecdir)/isc/log_messages/

CLEANFILES = bundy-xfrin xfrin.pyc xfrinlog.py
CLEANFILES += $(PYTHON_LOGMSGPKG_DIR)/work/xfrin_messages.py
CLEANFILES += $(PYTHON_LOGMSGPKG_DIR)/work/xfrin_messages.pyc

man_MANS = bundy-xfrin.8
DISTCLEANFILES = $(man_MANS)
EXTRA_DIST = $(man_MANS) bundy-xfrin.xml
EXTRA_DIST += xfrin.spec xfrin_messages.mes

if GENERATE_DOCS

bundy-xfrin.8: bundy-xfrin.xml
	@XSLTPROC@ --novalid --xinclude --nonet -o $@ http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl $(srcdir)/bundy-xfrin.xml

else

$(man_MANS):
	@echo Man generation disabled.  Creating dummy $@.  Configure with --enable-generate-docs to enable it.
	@echo Man generation disabled.  Remove this file, configure with --enable-generate-docs, and rebuild BUNDY > $@

endif

# Define rule to build logging source files from message file
$(PYTHON_LOGMSGPKG_DIR)/work/xfrin_messages.py : xfrin_messages.mes
	$(top_builddir)/src/lib/log/compiler/message \
	-d $(PYTHON_LOGMSGPKG_DIR)/work -p $(srcdir)/xfrin_messages.mes

# this is done here since configure.ac AC_OUTPUT doesn't expand exec_prefix
bundy-xfrin: xfrin.py $(PYTHON_LOGMSGPKG_DIR)/work/xfrin_messages.py
	$(SED) -e "s|@@PYTHONPATH@@|@pyexecdir@|" \
	       -e "s|@@LOCALSTATEDIR@@|$(localstatedir)|" xfrin.py >$@
	chmod a+x $@

CLEANDIRS = __pycache__

clean-local:
	rm -rf $(CLEANDIRS)
