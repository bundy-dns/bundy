SUBDIRS = . plugins local_plugins tests

pkglibexecdir = $(libexecdir)/@PACKAGE@

pkglibexec_SCRIPTS = bundy-cfgmgr

CLEANFILES = bundy-cfgmgr bundy-cfgmgr.pyc

bundy_cfgmgrdir = @localstatedir@/@PACKAGE@
#BUNDY_cfgmgr_DATA = 

man_MANS = bundy-cfgmgr.8
DISTCLEANFILES = $(man_MANS)
EXTRA_DIST = $(man_MANS) bundy-cfgmgr.xml

if GENERATE_DOCS

bundy-cfgmgr.8: bundy-cfgmgr.xml
	@XSLTPROC@ --novalid --xinclude --nonet -o $@ http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl $(srcdir)/bundy-cfgmgr.xml

else

$(man_MANS):
	@echo Man generation disabled.  Creating dummy $@.  Configure with --enable-generate-docs to enable it.
	@echo Man generation disabled.  Remove this file, configure with --enable-generate-docs, and rebuild BUNDY > $@

endif

# this is done here since configure.ac AC_OUTPUT doesn't expand exec_prefix
bundy-cfgmgr: bundy-cfgmgr.py
	$(SED) "s|@@PYTHONPATH@@|@pyexecdir@|" bundy-cfgmgr.py >$@
	chmod a+x $@

install-data-local:
	$(mkinstalldirs) $(DESTDIR)/@localstatedir@/@PACKAGE@

install-data-hook:
	-chmod 2770 $(DESTDIR)/@localstatedir@/@PACKAGE@

CLEANDIRS = __pycache__

clean-local:
	rm -rf $(CLEANDIRS)
