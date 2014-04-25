SUBDIRS = . tests

pkglibexecdir = $(libexecdir)/@PACKAGE@

pkglibexec_SCRIPTS = bundy-xfrout

bundy_xfroutdir = $(pkgdatadir)
bundy_xfrout_DATA = xfrout.spec

nodist_pylogmessage_PYTHON = $(PYTHON_LOGMSGPKG_DIR)/work/xfrout_messages.py
pylogmessagedir = $(pyexecdir)/bundy/log_messages/

CLEANFILES = bundy-xfrout xfrout.pyc xfrout.spec
CLEANFILES += $(PYTHON_LOGMSGPKG_DIR)/work/xfrout_messages.py
CLEANFILES += $(PYTHON_LOGMSGPKG_DIR)/work/xfrout_messages.pyc

man_MANS = bundy-xfrout.8
DISTCLEANFILES = $(man_MANS)
EXTRA_DIST = $(man_MANS) bundy-xfrout.xml xfrout_messages.mes

if GENERATE_DOCS

bundy-xfrout.8: bundy-xfrout.xml
	@XSLTPROC@ --novalid --xinclude --nonet -o $@ http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl $(srcdir)/bundy-xfrout.xml

else

$(man_MANS):
	@echo Man generation disabled.  Creating dummy $@.  Configure with --enable-generate-docs to enable it.
	@echo Man generation disabled.  Remove this file, configure with --enable-generate-docs, and rebuild BUNDY > $@

endif

# Define rule to build logging source files from message file
$(PYTHON_LOGMSGPKG_DIR)/work/xfrout_messages.py : xfrout_messages.mes
	$(top_builddir)/src/lib/log/compiler/message \
	-d $(PYTHON_LOGMSGPKG_DIR)/work -p $(srcdir)/xfrout_messages.mes

xfrout.spec: xfrout.spec.pre
	$(SED) -e "s|@@LOCALSTATEDIR@@|$(localstatedir)|" xfrout.spec.pre >$@

# this is done here since configure.ac AC_OUTPUT doesn't expand exec_prefix
bundy-xfrout: xfrout.py $(PYTHON_LOGMSGPKG_DIR)/work/xfrout_messages.py
	$(SED) -e "s|@@PYTHONPATH@@|@pyexecdir@|" \
	       -e "s|@@LOCALSTATEDIR@@|$(localstatedir)|" xfrout.py >$@
	chmod a+x $@

CLEANDIRS = __pycache__

clean-local:
	rm -rf $(CLEANDIRS)
