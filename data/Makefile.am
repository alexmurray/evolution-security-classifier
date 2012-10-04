gsettings_SCHEMAS = \
	org.gnome.evolution.plugin.security-classifier.gschema.xml

@INTLTOOL_XML_NOMERGE_RULE@

@GSETTINGS_RULES@

EXTRA_DIST =        \
	$(gsettings_SCHEMAS:.xml=.xml.in)

DISTCLEANFILES =    \
	$(gsettings_SCHEMAS)

-include $(top_srcdir)/git.mk
