# generated documentation
HTMLDOCS = bundy-guide.html bundy-messages.html
DOCS = bundy-guide.txt

dist_doc_DATA = $(DOCS)
dist_html_DATA = $(HTMLDOCS) bundy-guide.css

EXTRA_DIST = bundy-guide.xml
DISTCLEANFILES = $(HTMLDOCS) $(DOCS) bundy-messages.xml

# This is not a "man" manual, but reuse this for now for docbook.
if GENERATE_DOCS

bundy-guide.html: bundy-guide.xml
	@XSLTPROC@ --novalid --xinclude --nonet \
		--path $(top_builddir)/doc \
		-o $@ \
		--stringparam section.autolabel 1 \
		--stringparam section.label.includes.component.label 1 \
		--stringparam html.stylesheet bundy-guide.css \
		http://docbook.sourceforge.net/release/xsl/current/html/docbook.xsl \
		$(srcdir)/bundy-guide.xml

bundy-guide.txt: bundy-guide.html
	@ELINKS@ -dump -no-numbering -no-references bundy-guide.html > $@

bundy-messages.html: bundy-messages.xml
	@XSLTPROC@ --novalid --xinclude --nonet \
		--path $(top_builddir)/doc \
		-o $@ \
		--stringparam html.stylesheet bundy-guide.css \
		http://docbook.sourceforge.net/release/xsl/current/html/docbook.xsl \
		bundy-messages.xml

bundy-messages.xml:
	$(PYTHON) $(top_srcdir)/tools/system_messages.py -o $@ $(top_srcdir)

else

$(HTMLDOCS) $(DOCS):
	@echo Doc generation disabled.  Creating dummy $@.  Configure with --enable-generate-docs to enable it.
	@echo Doc generation disabled.  Remove this file, configure with --enable-generate-docs, and rebuild BUNDY > $@

endif
