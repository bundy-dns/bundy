SUBDIRS = . tests

bin_SCRIPTS = bundyctl
man_MANS = bundyctl.1

EXTRA_DIST = $(man_MANS) bundyctl.xml

noinst_SCRIPTS = run_bundyctl.sh

python_PYTHON = __init__.py bindcmd.py cmdparse.py exception.py moduleinfo.py \
		mycollections.py command_sets.py
pythondir = $(pyexecdir)/bundyctl

bundyctldir = $(pkgdatadir)

CLEANFILES = bundyctl bundyctl_main.pyc
DISTCLEANFILES = $(man_MANS)

if GENERATE_DOCS

bundyctl.1: bundyctl.xml
	@XSLTPROC@ --novalid --xinclude --nonet -o $@ http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl $(srcdir)/bundyctl.xml

else

$(man_MANS):
	@echo Man generation disabled.  Creating dummy $@.  Configure with --enable-generate-docs to enable it.
	@echo Man generation disabled.  Remove this file, configure with --enable-generate-docs, and rebuild BUNDY > $@

endif

bundyctl: bundyctl_main.py
	$(SED) -e "s|@@PYTHONPATH@@|@pyexecdir@|" \
	       -e "s|@@SYSCONFDIR@@|@sysconfdir@|" \
	       -e "s|@@LIBEXECDIR@@|$(pkglibexecdir)|" bundyctl_main.py >$@
	chmod a+x $@

CLEANDIRS = __pycache__

clean-local:
	rm -rf $(CLEANDIRS)
