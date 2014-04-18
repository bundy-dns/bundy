bin_SCRIPTS = bundy-sysinfo
noinst_SCRIPTS = run_sysinfo.sh

CLEANFILES = bundy-sysinfo sysinfo.pyc

# this is done here since configure.ac AC_OUTPUT doesn't expand exec_prefix
bundy-sysinfo: sysinfo.py
	$(SED) -e "s|@@PYTHONPATH@@|@pyexecdir@|" sysinfo.py >$@
	chmod a+x $@

MAN1_FILES = \
	bundy-sysinfo.xml

man_MANS = \
	$(MAN1_FILES:.xml=.1)
DISTCLEANFILES = $(man_MANS)

if GENERATE_DOCS

.xml.1:
	@XSLTPROC@ --novalid --xinclude --nonet -o $@ http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl $<

else

$(man_MANS):
	@echo Man generation disabled.  Creating dummy $@.  Configure with --enable-generate-docs to enable it.
	@echo Man generation disabled.  Remove this file, configure with --enable-generate-docs, and rebuild BUNDY > $@

endif

EXTRA_DIST = $(man_MANS) $(MAN1_FILES)

CLEANDIRS = __pycache__

clean-local:
	rm -rf $(CLEANDIRS)
