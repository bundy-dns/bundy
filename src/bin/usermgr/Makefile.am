SUBDIRS = tests

sbin_SCRIPTS = bundy-cmdctl-usermgr
noinst_SCRIPTS = run_bundy-cmdctl-usermgr.sh

bundy_cmdctl_usermgrdir = $(pkgdatadir)

CLEANFILES=	bundy-cmdctl-usermgr bundy-cmdctl-usermgr.pyc

man_MANS = bundy-cmdctl-usermgr.8
DISTCLEANFILES = $(man_MANS)
EXTRA_DIST = $(man_MANS) bundy-cmdctl-usermgr.xml

if GENERATE_DOCS

bundy-cmdctl-usermgr.8: bundy-cmdctl-usermgr.xml
	@XSLTPROC@ --novalid --xinclude --nonet -o $@ http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl $(srcdir)/bundy-cmdctl-usermgr.xml

else

$(man_MANS):
	@echo Man generation disabled.  Creating dummy $@.  Configure with --enable-generate-docs to enable it.
	@echo Man generation disabled.  Remove this file, configure with --enable-generate-docs, and rebuild BUNDY > $@

endif

# this is done here since configure.ac AC_OUTPUT doesn't expand exec_prefix
bundy-cmdctl-usermgr: bundy-cmdctl-usermgr.py
	$(SED) "s|@@PYTHONPATH@@|@pyexecdir@|" bundy-cmdctl-usermgr.py >$@
	chmod a+x $@

CLEANDIRS = __pycache__
clean-local:
	rm -rf $(CLEANDIRS)
