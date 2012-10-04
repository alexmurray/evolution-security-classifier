
INCLUDES =							\
	-I$(top_srcdir)						\
	-DGETTEXT_PACKAGE="\"$(GETTEXT_PACKAGE)\""		\
	-DLOCALEDIR="\"$(LOCALEDIR)\""				\
	$(SECURITY_CLASSIFIER_EPLUGIN_CFLAGS)

%.eplug.in: %.eplug.xml
	LC_ALL=C $(INTLTOOL_MERGE) -x -u /tmp $< $@

%.eplug: %.eplug.in
	sed -e "s%+PLUGIN_DIR+%$(PLUGIN_DIR)%" \
	-e "s%+GETTEXT_PACKAGE+%$(GETTEXT_PACKAGE)%" \
	-e "s%+LOCALEDIR+%$(LOCALEDIR)%" \
	-e "s%+VERSION+%$(VERSION)%" \
	-e "s%+SOEXT+%$(SOEXT)%" \
	$< > $@

%.error.in: %.error.xml
	LC_ALL=C $(INTLTOOL_MERGE) -x -u /tmp $< $@

%.error: %.error.in
	sed -e "s%+PLUGIN_DIR+%$(PLUGIN_DIR)%" \
	-e "s%+GETTEXT_PACKAGE+%$(GETTEXT_PACKAGE)%" \
	-e "s%+LOCALEDIR+%$(LOCALEDIR)%" \
	$< > $@

errordir = $(ERROR_DIR)
error_DATA = org-gnome-evolution-security-classifier.error

plugindir = $(PLUGIN_DIR)
plugin_DATA = org-gnome-evolution-security-classifier.eplug

plugin_LTLIBRARIES = liborg-gnome-evolution-security-classifier.la


SOURCES = security-classifier.c

liborg_gnome_evolution_security_classifier_la_SOURCES = $(SOURCES)
liborg_gnome_evolution_security_classifier_la_LIBADD = $(DATASERVER_LIBS) $(DBUS_LIBS) $(NO_UNDEFINED_LIBS)
liborg_gnome_evolution_security_classifier_la_LDFLAGS = -module -avoid-version $(NO_UNDEFINED)


CLEANFILES	= $(BUILT_SOURCES)	\
	org-gnome-evolution-security-classifier.eplug	\
	org-gnome-evolution-security-classifier.error

EXTRA_DIST = security-classifier.c				\
	org-gnome-evolution-security-classifier.eplug.xml	\
	org-gnome-evolution-security-classifier.error.xml


-include $(top_srcdir)/git.mk
