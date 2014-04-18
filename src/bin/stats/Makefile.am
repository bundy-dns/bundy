SUBDIRS = tests

pkglibexecdir = $(libexecdir)/@PACKAGE@

pkglibexec_SCRIPTS = bundy-stats bundy-stats-httpd

bundy_statsdir = $(pkgdatadir)
bundy_stats_DATA = stats.spec stats-httpd.spec
bundy_stats_DATA += stats-httpd-xml.tpl stats-httpd-xsd.tpl stats-httpd-xsl.tpl

nodist_pylogmessage_PYTHON = $(PYTHON_LOGMSGPKG_DIR)/work/stats_messages.py
nodist_pylogmessage_PYTHON += $(PYTHON_LOGMSGPKG_DIR)/work/stats_httpd_messages.py
pylogmessagedir = $(pyexecdir)/bundy/log_messages/

CLEANFILES = bundy-stats stats.pyc
CLEANFILES += bundy-stats-httpd stats_httpd.pyc
CLEANFILES += $(PYTHON_LOGMSGPKG_DIR)/work/stats_messages.py
CLEANFILES += $(PYTHON_LOGMSGPKG_DIR)/work/stats_messages.pyc
CLEANFILES += $(PYTHON_LOGMSGPKG_DIR)/work/stats_httpd_messages.py
CLEANFILES += $(PYTHON_LOGMSGPKG_DIR)/work/stats_httpd_messages.pyc

man_MANS = bundy-stats.8 bundy-stats-httpd.8
DISTCLEANFILES = $(man_MANS)
EXTRA_DIST = $(man_MANS) bundy-stats.xml bundy-stats-httpd.xml
EXTRA_DIST += stats.spec stats-httpd.spec
EXTRA_DIST += stats-httpd-xml.tpl stats-httpd-xsd.tpl stats-httpd-xsl.tpl
EXTRA_DIST += stats_messages.mes stats_httpd_messages.mes

if GENERATE_DOCS

bundy-stats.8: bundy-stats.xml
	@XSLTPROC@ --novalid --xinclude --nonet -o $@ http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl $(srcdir)/bundy-stats.xml

bundy-stats-httpd.8: bundy-stats-httpd.xml
	@XSLTPROC@ --novalid --xinclude --nonet -o $@ http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl $(srcdir)/bundy-stats-httpd.xml

else

$(man_MANS):
	@echo Man generation disabled.  Creating dummy $@.  Configure with --enable-generate-docs to enable it.
	@echo Man generation disabled.  Remove this file, configure with --enable-generate-docs, and rebuild BUNDY > $@

endif

$(PYTHON_LOGMSGPKG_DIR)/work/stats_messages.py : stats_messages.mes
	$(top_builddir)/src/lib/log/compiler/message \
	-d $(PYTHON_LOGMSGPKG_DIR)/work -p $(srcdir)/stats_messages.mes

$(PYTHON_LOGMSGPKG_DIR)/work/stats_httpd_messages.py : stats_httpd_messages.mes
	$(top_builddir)/src/lib/log/compiler/message \
	-d $(PYTHON_LOGMSGPKG_DIR)/work -p $(srcdir)/stats_httpd_messages.mes

# this is done here since configure.ac AC_OUTPUT doesn't expand exec_prefix
bundy-stats: stats.py $(PYTHON_LOGMSGPKG_DIR)/work/stats_messages.py
	$(SED) -e "s|@@PYTHONPATH@@|@pyexecdir@|"  stats.py >$@
	chmod a+x $@

bundy-stats-httpd: stats_httpd.py $(PYTHON_LOGMSGPKG_DIR)/work/stats_httpd_messages.py
	$(SED) -e "s|@@PYTHONPATH@@|@pyexecdir@|" stats_httpd.py >$@
	chmod a+x $@

CLEANDIRS = __pycache__

clean-local:
	rm -rf $(CLEANDIRS)
