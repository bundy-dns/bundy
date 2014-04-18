SUBDIRS = . tests

pkglibexecdir = $(libexecdir)/@PACKAGE@

pkglibexec_SCRIPTS = bundy-cmdctl

bin_PROGRAMS = bundy-certgen

nodist_pylogmessage_PYTHON = $(PYTHON_LOGMSGPKG_DIR)/work/cmdctl_messages.py
pylogmessagedir = $(pyexecdir)/isc/log_messages/

bundy_cmdctldir = $(pkgdatadir)

CERTFILES = cmdctl-keyfile.pem cmdctl-certfile.pem

bundy_cmdctl_DATA = cmdctl.spec

CLEANFILES= bundy-cmdctl cmdctl.pyc cmdctl.spec
CLEANFILES += $(PYTHON_LOGMSGPKG_DIR)/work/cmdctl_messages.py
CLEANFILES += $(PYTHON_LOGMSGPKG_DIR)/work/cmdctl_messages.pyc

man_MANS = bundy-cmdctl.8 bundy-certgen.1
DISTCLEANFILES = $(man_MANS) cmdctl-certfile.pem cmdctl-keyfile.pem
EXTRA_DIST  = $(man_MANS) bundy-certgen.xml bundy-cmdctl.xml cmdctl_messages.mes
EXTRA_DIST += cmdctl-accounts.csv

if GENERATE_DOCS

bundy-cmdctl.8: bundy-cmdctl.xml
	@XSLTPROC@ --novalid --xinclude --nonet -o $@ http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl $(srcdir)/bundy-cmdctl.xml

bundy-certgen.1: bundy-certgen.xml
	@XSLTPROC@ --novalid --xinclude --nonet -o $@ http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl $(srcdir)/bundy-certgen.xml

else

$(man_MANS):
	@echo Man generation disabled.  Creating dummy $@.  Configure with --enable-generate-docs to enable it.
	@echo Man generation disabled.  Remove this file, configure with --enable-generate-docs, and rebuild BUNDY > $@

endif

cmdctl.spec: cmdctl.spec.pre
	$(SED) -e "s|@@SYSCONFDIR@@|$(sysconfdir)|" cmdctl.spec.pre >$@

$(PYTHON_LOGMSGPKG_DIR)/work/cmdctl_messages.py : cmdctl_messages.mes
	$(top_builddir)/src/lib/log/compiler/message \
	-d $(PYTHON_LOGMSGPKG_DIR)/work -p $(srcdir)/cmdctl_messages.mes

# this is done here since configure.ac AC_OUTPUT doesn't expand exec_prefix
bundy-cmdctl: cmdctl.py $(PYTHON_LOGMSGPKG_DIR)/work/cmdctl_messages.py $(CERTFILES)
	$(SED) "s|@@PYTHONPATH@@|@pyexecdir@|" cmdctl.py >$@
	chmod a+x $@

bundy_certgen_SOURCES = bundy-certgen.cc
bundy_certgen_CXXFLAGS = $(BOTAN_INCLUDES)
bundy_certgen_LDFLAGS = $(BOTAN_LIBS)

# Generate the initial certificates immediately
cmdctl-keyfile.pem: bundy-certgen
	./bundy-certgen -q -w

# This is a hack, as bundy-certgen creates both cmdctl-keyfile.pem and
# cmdctl-certfile.pem, and in a parallel make, making these targets
# simultaneously may result in corrupted files. With GNU make, there is
# a non-portable way of working around this with pattern rules, but we
# adopt this hack instead. The downside is that cmdctl-certfile.pem will
# not be re-generated if cmdctl-keyfile.pem exists and is older. See
# Trac ticket #2962.
cmdctl-certfile.pem: cmdctl-keyfile.pem
	touch $(builddir)/cmdctl-keyfile.pem

if INSTALL_CONFIGURATIONS

# Below we intentionally use ${INSTALL} -m 640 instead of $(INSTALL_DATA)
# because these file will contain sensitive information.
install-data-local:
	$(mkinstalldirs) $(DESTDIR)/@sysconfdir@/@PACKAGE@
	for f in $(CERTFILES) ; do	\
	  if test ! -f $(DESTDIR)$(sysconfdir)/@PACKAGE@/$$f; then	\
	    ${INSTALL} -m 640 $$f $(DESTDIR)$(sysconfdir)/@PACKAGE@/ ;	\
	  fi ;	\
	done

endif

CLEANDIRS = __pycache__

clean-local:
	rm -rf $(CLEANDIRS)
