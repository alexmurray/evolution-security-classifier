/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) version 3.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with the program; if not, see <http://www.gnu.org/licenses/>
 *
 *
 * Authors:
 *                Alex Murray <murray.alex@gmail.com>
 *
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <gtk/gtk.h>
#include <glib/gi18n.h>
#include <string.h>

#include <e-util/e-util.h>
#include <e-util/e-plugin.h>
#include <e-util/e-config.h>
#include <mail/em-config.h>
#include <mail/em-event.h>
#include <mail/em-utils.h>
#include <libevolution-utils/e-alert-dialog.h>


gint e_plugin_lib_enable (EPlugin *ep, gint enable);
gboolean init_composer_ui (GtkUIManager *manager, EMsgComposer *composer);
void org_gnome_evolution_security_classifier (EPlugin *ep, EMEventTargetComposer *t);

typedef struct _SecurityLabel
{
        const gchar *name;
        const gchar *accel;
} SecurityLabel;

static const SecurityLabel security_labels[] = {
        { N_("UNCLASSIFIED"), "<Control><Shift>u" },
        { N_("IN-CONFIDENCE"), "<Control><Shift>i" } ,
        { N_("RESTRICTED"), "<Control><Shift>r"} ,
        { NULL, NULL} };

/* privacy's don't have accelerators */
static const gchar * privacys[] = { N_("AUDIT"),
                                    N_("CLIENT"),
                                    N_("COMMERCIAL"),
                                    N_("HONOURS"),
                                    N_("INTELLIGENCE"),
                                    N_("LEGAL"),
                                    N_("MEDICAL"),
                                    N_("PERSONNEL"),
                                    N_("PSYCHOLOGY"),
                                    N_("SECURITY"),
                                    N_("STAFF"),
                                    NULL};

static gboolean enabled = FALSE;

gint
e_plugin_lib_enable (EPlugin *ep,
                     gint enable)
{
        enabled = enable;
        return 0;
}

#define CLASSIFICATION_PATTERN "\\[SEC=([A-Z-]+)(:([A-Z-]+))?\\]"

static gboolean
strip_classification (gchar *subject)
{
        GRegex *regex;
        GMatchInfo *match_info;
        gboolean ret;

        /* don't use classification regex as is too specific - we want
           everything inside the SEC= incase it is misformatted - but make
           non-greedy */
        regex = g_regex_new ("\\[SEC=.*?\\]", 0, 0, NULL);
        ret = g_regex_match (regex, subject, 0, &match_info);

        if (ret) {
                gint start;
                /* get last occurrence */
                while (g_match_info_matches (match_info)) {
                        g_match_info_fetch_pos (match_info, 0, &start, NULL);
                        g_match_info_next (match_info, NULL);
                }
                /* strip off classification subject */
                subject[start] = '\0';
        }
        g_match_info_free (match_info);
        g_regex_unref (regex);
        return ret;
}

typedef struct _Classification
{
        gchar *security;
        gchar *privacy;
} Classification;

static gboolean
extract_classification (const gchar *subject,
                        Classification *classification)
{
        GRegex *regex;
        GMatchInfo *match_info;
        gboolean ret;

        regex = g_regex_new (CLASSIFICATION_PATTERN, 0, 0, NULL);
        ret = g_regex_match (regex, subject, 0, &match_info);

        if (ret) {
                /* extract classification if required */
                if (classification) {
                        /* loop over all matches so we get the last one and keep
                           it */
                        gchar *security = NULL;
                        gchar *privacy = NULL;
                        while (g_match_info_matches (match_info)) {
                                /* free any existing versions of security and
                                   privacy */
                                g_free (security);
                                g_free (privacy);
                                security = g_match_info_fetch (match_info, 1);
                                privacy = g_match_info_fetch (match_info, 3);
                                g_match_info_next (match_info, NULL);
                        }
                        classification->security = security;
                        classification->privacy = privacy;
                }
        }
        g_match_info_free (match_info);
        g_regex_unref (regex);
        return ret;
}

static void classify (EMsgComposer *composer,
                      const gchar *security,
                      const gchar *privacy)
{
        EComposerHeaderTable *header;
        gchar *subject = NULL, *new_subject = NULL;

        header = e_msg_composer_get_header_table (composer);
        subject = g_strdup (e_composer_header_table_get_subject (header));

        if (extract_classification (subject, NULL)) {
                strip_classification (subject);
                /* strip any trailing whitespace too */
                subject = g_strchomp (subject);
        }

        /* get any existing security / privacy */
        if (!security) {
                security = g_object_get_data (G_OBJECT (composer),
                                              "security-classification");
        }
        if (!privacy) {
                privacy = g_object_get_data (G_OBJECT (composer),
                                             "privacy-classification");
        }

        /* only set if no security label */
        if (security) {
                gchar *marking = g_strjoin (":", security, privacy, NULL);
                /* set this as the classification */
                new_subject = g_strdup_printf ("%s [SEC=%s]", subject, marking);
                g_free (marking);
        } else {
                new_subject = g_strdup (subject);
        }
        /* set before actually setting subject so we reclassify with same
         * value */
        g_object_set_data_full (G_OBJECT (composer), "security-classification",
                                g_strdup (security), g_free);
        g_object_set_data_full (G_OBJECT (composer), "privacy-classification",
                                g_strdup (privacy), g_free);

        /* set this new subject */
        e_composer_header_table_set_subject (header, new_subject);

        g_free (new_subject);
        g_free (subject);
}

static void
activate_action (EMsgComposer *composer,
                 const gchar *prefix,
                 const gchar *label)
{
        gchar *downcase_label;
        gchar *path;
        GtkUIManager *ui_manager;
        GtkAction *action;

        downcase_label = g_utf8_strdown (label, -1);
        path = g_strdup_printf ("/main-menu/classify-menu/%s-%s", prefix, downcase_label);
        ui_manager = gtkhtml_editor_get_ui_manager (GTKHTML_EDITOR (composer));
        action = gtk_ui_manager_get_action (ui_manager, path);
        if (action) {
                gtk_action_activate (action);
        } else {
                g_warning ("Unable to find action for path %s", path);
        }
        g_free (path);
        g_free (downcase_label);
}

static void
subject_changed (EComposerHeaderTable *header,
                 GParamSpec *pspec,
                 EMsgComposer *composer)
{
        const gchar *subject;

        subject = e_composer_header_table_get_subject (header);

        if (!g_object_get_data (G_OBJECT (composer), "security-classification")) {
                gboolean ret;
                Classification classification = { NULL, NULL };

                ret = extract_classification (subject, &classification);

                if (ret) {
                        activate_action (composer, "security", classification.security);
                        if (classification.privacy) {
                                activate_action (composer, "privacy", classification.privacy);
                        }
                }
        } else {
                classify (composer, NULL, NULL);
        }
}

static gboolean
ask_for_classification (EPlugin *ep,
                        GtkWindow *window,
                        Classification *classification)
{
        GtkWidget *hbox;
        GtkWidget *security_combo, *privacy_combo;
        GtkWidget *dialog;
        GtkWidget *container;
        const SecurityLabel *label;
        const gchar **privacy;
        gchar *security;
        gchar *marking;
        gint response;

        dialog = e_alert_dialog_new_for_args (
                window, "org.gnome.evolution.plugins.security_classifier:"
                "security-classifier", NULL);

        container = e_alert_dialog_get_content_area (E_ALERT_DIALOG (dialog));

        hbox = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 0);

        /* Security list */
        security_combo = gtk_combo_box_text_new ();
        label = security_labels;
        while (label->name) {
                gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (security_combo),
                                                gettext (label->name));
                label++;
        }
        gtk_box_pack_start (GTK_BOX (hbox), security_combo, FALSE, FALSE, 0);

        /* privacy list */
        privacy_combo = gtk_combo_box_text_new ();
        privacy = privacys;
        while (*privacy) {
                gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (privacy_combo),
                                                gettext (*privacy));
                privacy++;
        }
        gtk_box_pack_start (GTK_BOX (hbox), privacy_combo, FALSE, FALSE, 0);

        gtk_box_pack_start (GTK_BOX (container), hbox, FALSE, FALSE, 0);
        gtk_widget_show_all (hbox);
        response = gtk_dialog_run (GTK_DIALOG (dialog));
        security = gtk_combo_box_text_get_active_text (GTK_COMBO_BOX_TEXT (security_combo));
        marking = gtk_combo_box_text_get_active_text (GTK_COMBO_BOX_TEXT (privacy_combo));
        gtk_widget_destroy (dialog);

        /* if user didn't choose to send then don't apply any classification */
        if (response != GTK_RESPONSE_YES) {
                /* no classification selected, return NULL */
                g_free (security);
                security = NULL;
                g_free (marking);
                marking = NULL;
        }
        if (security && security[0] != '\0') {
                classification->security = g_utf8_strup (security, -1);
                if (marking && marking[0] != '\0') {
                        classification->privacy = g_utf8_strup (marking, -1);
                }
        } else {
                /* make it look like cancelled as nothing was selected */
                response = GTK_RESPONSE_CANCEL;
        }

        return response == GTK_RESPONSE_YES;
}

void
org_gnome_evolution_security_classifier (EPlugin *ep,
                                         EMEventTargetComposer *t)
{
        Classification classification = { NULL, NULL };
        gchar *u_upcase;
        gchar *marking, *header;
        GtkhtmlEditor *editor = GTKHTML_EDITOR (t->composer);
        EComposerHeaderTable *table;
        EAccount *account;
        EWebView *web_view;

        table = e_msg_composer_get_header_table (t->composer);

        classification.security = g_strdup (g_object_get_data (G_OBJECT (t->composer),
                                                               "security-classification"));
        classification.privacy = g_strdup (g_object_get_data (G_OBJECT (t->composer),
                                                              "privacy-classification"));

        if (!classification.security)
        {
                ask_for_classification (ep, GTK_WINDOW(t->composer),
                                        &classification);
                if (classification.security) {
                        classify (t->composer, classification.security, classification.privacy);
                } else {
                        /* user didn't select a classification */
                        g_object_set_data ((GObject *) t->composer,
                                           "presend_check_status", GINT_TO_POINTER(1));
                        goto out;
                }
        }

        /* if security is NOT unclassified, check recipients are all within the
         * domain */
        u_upcase = g_utf8_strup (security_labels[0].name, -1);
        if (g_utf8_collate (classification.security, u_upcase)) {
                EDestination **destinations, **destination;
                destinations = e_composer_header_table_get_destinations (table);
                destination = destinations;

                while (*destination) {
                        EAlert *alert;
                        const gchar *email = e_destination_get_email (*destination);
                        if ((g_str_has_suffix (email, "defence.gov.au"))) {
                                destination++;
                                continue;
                        }
                        alert = e_alert_new ("org.gnome.evolution.plugins.security_classifier:"
                                             "classified-external-recipient", NULL);
                        e_alert_sink_submit_alert (E_ALERT_SINK (t->composer), alert);
                        g_object_unref (alert);
                        g_warning ("Attempting to email a %s classified email outside of the %s network to recipient %s",
                                   classification.security, "defence.gov.au", email);
                        g_object_set_data ((GObject *) t->composer,
                                           "presend_check_status", GINT_TO_POINTER(1));
                        goto out;
                }
                e_destination_freev (destinations);
        }
        g_free (u_upcase);

        /* classification has been set - insert this at the top of the
         * message if is editable */
        marking = g_strjoin (":", classification.security,
                             classification.privacy, NULL);
        g_free (classification.security);
        g_free (classification.privacy);

        web_view = e_msg_composer_get_web_view (t->composer);
        if (e_web_view_get_editable (web_view))
        {
                if (gtkhtml_editor_get_html_mode (editor)) {
                        gchar *html = gtkhtml_editor_get_text_html (editor, NULL);
                        /* find where <body> tag starts */
                        gchar *body = g_strrstr (html, "<body>");
                        if (!body) {
                                body = g_strrstr (html, "<BODY>");
                        }
                        if (body) {
                                gchar *tail;
                                gchar *new_html;

                                /* duplicate text beyond <body> tag and truncate
                                   html at end of body tag */
                                body += strlen ("<body>");
                                tail = g_strdup (body);
                                body[0] = '\0';

                                /* generate new html with our inserted
                                   classification marking */
                                new_html = g_strdup_printf ("%s\n<p><b>%s</b></p>%s",
                                                            html, marking, tail);
                                gtkhtml_editor_set_text_html (editor, new_html, -1);
                                g_free (new_html);
                                g_free (tail);
                        }
                        g_free (html);
                } else {
                        gchar *text = gtkhtml_editor_get_text_plain (editor, NULL);
                        gchar *new_text = g_strdup_printf ("%s\n\n%s", marking, text);
                        /* clear existing text then insert ours */
                        gtkhtml_editor_set_text_html (editor, "", -1);
                        gtkhtml_editor_insert_text (editor, new_text);
                        g_free (new_text);
                        g_free (text);
                }
        }

        /* also set x-protective-marking header as per Email Protective
           Marking Standard for the Australian Government October 2005 -
           http://www.finance.gov.au/e-government/security-and-authentication/docs/Email_Protective.pdf */
        account = e_composer_header_table_get_account (table);
        header = g_strdup_printf ("VER=2005.6, NS=gov.au, SEC=%s, ORIGIN=%s",
                                  marking, e_account_get_string (account, E_ACCOUNT_ID_ADDRESS));
        e_msg_composer_set_header (t->composer, "x-protective-marking", header);
        g_free (header);

        /* and finally set our version */
        e_msg_composer_set_header (t->composer, "x-" PACKAGE_NAME "-version",
                                   PACKAGE_VERSION);
out:
        return;
}

static void security_action (GtkAction *action, EMsgComposer *composer)
{
        gchar *security;
        gint i;
        GtkComboBox *combo_box;

        security = g_utf8_strup (gtk_action_get_label (action), -1);

        /* update the combo box */
        i = gtk_radio_action_get_current_value (GTK_RADIO_ACTION (action));
        combo_box = g_object_get_data (G_OBJECT (composer), "security-combo");
        gtk_combo_box_set_active (combo_box, i);
        classify (composer, security, NULL);
        g_free (security);
}

static void privacy_action (GtkAction *action, EMsgComposer *composer)
{
        gchar *privacy;
        gint i;
        GtkComboBox *combo_box;

        privacy = g_utf8_strup (gtk_action_get_label (action), -1);

        /* update the combo box */
        i = gtk_radio_action_get_current_value (GTK_RADIO_ACTION (action));
        combo_box = g_object_get_data (G_OBJECT (composer), "privacy-combo");
        gtk_combo_box_set_active (combo_box, i);
        classify (composer, NULL, privacy);
        g_free (privacy);
}

static void security_combo_changed (GtkComboBox *combo_box,
                                    EMsgComposer *composer)
{
        gchar *label;

        label = gtk_combo_box_text_get_active_text (GTK_COMBO_BOX_TEXT (combo_box));
        activate_action (composer, "security", label);
        g_free (label);
}

static void privacy_combo_changed (GtkComboBox *combo_box,
                                   EMsgComposer *composer)
{
        gchar *label;

        label = gtk_combo_box_text_get_active_text (GTK_COMBO_BOX_TEXT (combo_box));
        activate_action (composer, "privacy", label);
        g_free (label);
}

static void
create_radio_action (const gchar *prefix,
                     const gchar *label,
                     const gchar *accel,
                     gint i,
                     GCallback callback,
                     EMsgComposer *composer,
                     GtkRadioAction **radio_group,
                     GtkActionGroup *action_group,
                     GtkUIManager *ui_manager,
                     gint merge_id)
{
        gchar *downcase_label;
        gchar *action_name;
        GtkRadioAction *action;

        downcase_label = g_utf8_strdown (label, -1);
        action_name = g_strdup_printf ("%s-%s", prefix, downcase_label);
        g_free (downcase_label);
        action = gtk_radio_action_new (action_name,
                                       label,
                                       NULL, NULL, i);
        g_signal_connect (action, "activate",
                          callback, composer);
        if (!*radio_group) {
                *radio_group = action;
        } else {
                gtk_radio_action_join_group (action, *radio_group);
        }
        gtk_action_group_add_action_with_accel (action_group, GTK_ACTION (action),
                                                accel);
        gtk_ui_manager_add_ui (ui_manager, merge_id, "/main-menu/classify-menu",
                               action_name, action_name,
                               GTK_UI_MANAGER_AUTO, FALSE);

        g_free (action_name);
}

gboolean
init_composer_ui (GtkUIManager *manager,
                  EMsgComposer *composer)
{
        EComposerHeaderTable *header;
        const SecurityLabel *label;
        const gchar **privacy;
        GtkUIManager *ui_manager;
        GtkhtmlEditor *editor;
        GtkRadioAction *radio_group = NULL;
        GtkActionGroup *action_group;
        guint merge_id;
        gint i;
        GtkSizeGroup *size_group;
        GtkWidget *security_combo, *privacy_combo;
        GtkToolItem *item;
        GtkWidget *toolbar;

        /* if we've been disabled don't do anything */
        if (!enabled) {
                goto out;
        }

        editor = GTKHTML_EDITOR (composer);
        /* add to our own action group */
        action_group = gtk_action_group_new ("security-classifier");
        ui_manager = gtkhtml_editor_get_ui_manager (editor);
        gtk_ui_manager_insert_action_group (ui_manager, action_group, 0);
        merge_id = gtk_ui_manager_new_merge_id (ui_manager);

        /* create the action for the menu */
        gtk_action_group_add_action (action_group,
                                     gtk_action_new ("classify-menu",
                                                     _("Classification"),
                                                     NULL, NULL));

        gtk_ui_manager_add_ui (ui_manager, merge_id, "/main-menu",
                               "classify-menu", "classify-menu",
                               GTK_UI_MANAGER_MENU, FALSE);

        security_combo = gtk_combo_box_text_new ();
        g_signal_connect (security_combo, "changed", G_CALLBACK (security_combo_changed), composer);
        g_object_set_data (G_OBJECT (composer), "security-combo", security_combo);
        /* create action entries from the list of possible classifications */
        label = security_labels;
        i = 0;
        while (label->name) {
                create_radio_action ("security",
                                     gettext (label->name),
                                     label->accel,
                                     i,
                                     G_CALLBACK (security_action),
                                     composer,
                                     &radio_group,
                                     action_group,
                                     ui_manager,
                                     merge_id);
                gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (security_combo),
                                                gettext (label->name));
                label++, i++;
        }
        /* add a separator before privacy labels */
        gtk_ui_manager_add_ui (ui_manager, merge_id, "/main-menu/classify-menu",
                               NULL, NULL,
                               GTK_UI_MANAGER_SEPARATOR, FALSE);

        /* now add privacy labels */
        radio_group = NULL;
        i = 0;
        privacy = privacys;
        privacy_combo = gtk_combo_box_text_new ();
        g_signal_connect (privacy_combo, "changed", G_CALLBACK (privacy_combo_changed), composer);
        g_object_set_data (G_OBJECT (composer), "privacy-combo", privacy_combo);
        while (*privacy) {
                create_radio_action ("privacy",
                                     gettext (*privacy),
                                     NULL,
                                     i,
                                     G_CALLBACK (privacy_action),
                                     composer,
                                     &radio_group,
                                     action_group,
                                     ui_manager,
                                     merge_id);
                gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (privacy_combo),
                                                gettext (*privacy));
                i++;
                privacy++;
        }

        gtk_ui_manager_ensure_update (ui_manager);

        /* add combo_box's to the edit toolbar - make sure have same size */
        size_group = gtk_size_group_new (GTK_SIZE_GROUP_HORIZONTAL);
        gtk_size_group_add_widget (size_group, security_combo);
        gtk_size_group_add_widget (size_group, privacy_combo);
        g_object_unref (size_group);

        toolbar = gtk_ui_manager_get_widget (ui_manager, "/edit-toolbar");
        item = gtk_separator_tool_item_new();
        gtk_toolbar_insert (GTK_TOOLBAR (toolbar), item, -1);
        gtk_widget_show_all (GTK_WIDGET (item));
        item = gtk_tool_item_new ();
        gtk_container_add (GTK_CONTAINER (item), security_combo);
        gtk_toolbar_insert (GTK_TOOLBAR (toolbar), item, -1);
        gtk_widget_show_all (GTK_WIDGET (item));
        item = gtk_tool_item_new ();
        gtk_container_add (GTK_CONTAINER (item), privacy_combo);
        gtk_toolbar_insert (GTK_TOOLBAR (toolbar), item, -1);
        gtk_widget_show_all (GTK_WIDGET (item));

        /* whenever subject is updated we should ensure we maintain the security
           labelling */
        header = e_msg_composer_get_header_table (composer);
        g_signal_connect (header, "notify::subject",
                          G_CALLBACK (subject_changed),
                          composer);

out:
        return TRUE;
}
