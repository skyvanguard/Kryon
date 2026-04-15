# F13.2 — GnuCash labeling worksheet

Seed: 42 (deterministic). Repo: gnucash@9f8f4d9e.

## Summary

| Category | Pool | Sampled | Test-files in sample |
|----------|------|---------|----------------------|
| CWE-476 | 143 | 30 | 4 |
| CWE-121 | 17 | 17 | 0 |
| CWE-190 | 3 | 3 | 0 |
| heuristic-other | 0 | 0 | 0 |

## Labeling scheme

- **TP**: real vulnerability or suspicious code worth investigation.
- **FP**: rule matched but code is safe (sentinel-NULL check, dead code, test harness, etc.).
- **UNK**: cannot determine without more context (mark rare).

## Category: CWE-476

### CWE-476-01 — idx=28 

- **File**: `gnucash/gnome/dialog-invoice.c`
- **Line**: 2508-2536
- **CWE**: CWE-476
- **Rule**: `kryon-rules.kryon.cwe-476.null-assign-deref`
- **Hunter**: semgrep-kryon
- **Severity**: ERROR
- **Message**: Pointer explicitly assigned NULL then dereferenced. CWE-476. 

Code context:
```c
     2500  #define KEY_OWNER_GUID          "OwnerGUID"
     2501  
     2502  GncPluginPage *
     2503  gnc_invoice_recreate_page (GncMainWindow *window,
     2504                             GKeyFile *key_file,
     2505                             const gchar *group_name)
     2506  {
     2507      InvoiceWindow *iw;
>>>  2508      GError *error = NULL;
     2509      char *tmp_string = NULL, *owner_type = NULL;
     2510      InvoiceDialogType type;
     2511      GncInvoice *invoice;
     2512      GncGUID guid;
     2513      QofBook *book;
     2514      GncOwner owner = { 0 };
     2515  
     2516      /* Get Invoice Type */
```

**Label**: [ ] TP  [ ] FP  [ ] UNK

**Rationale**:

---

### CWE-476-02 — idx=6 

- **File**: `gnucash/gnome-utils/gnc-main-window.cpp`
- **Line**: 456-472
- **CWE**: CWE-476
- **Rule**: `kryon-rules.kryon.cwe-476.null-assign-deref`
- **Hunter**: semgrep-kryon
- **Severity**: ERROR
- **Message**: Pointer explicitly assigned NULL then dereferenced. CWE-476. 

Code context:
```c
      448  static gboolean
      449  gnc_main_window_restore_page (GncMainWindow *window,
      450                                GncMainWindowSaveData *data)
      451  {
      452      GncMainWindowPrivate *priv;
      453      GncPluginPage *page = nullptr;
      454      gchar *page_group, *page_type = nullptr, *name = nullptr;
      455      const gchar *class_type;
>>>   456      GError *error = nullptr;
      457  
      458      ENTER("window %p, data %p (key file %p, window %d, page start %d, page num %d)",
      459            window, data, data->key_file, data->window_num, data->page_offset,
      460            data->page_num);
      461  
      462      priv = GNC_MAIN_WINDOW_GET_PRIVATE(window);
      463      page_group = g_strdup_printf(PAGE_STRING,
      464                                   data->page_offset + data->page_num);
```

**Label**: [ ] TP  [ ] FP  [ ] UNK

**Rationale**:

---

### CWE-476-03 — idx=71 

- **File**: `gnucash/import-export/aqb/gnc-gwen-gui.c`
- **Line**: 918-949
- **CWE**: CWE-476
- **Rule**: `kryon-rules.kryon.cwe-476.null-assign-deref`
- **Hunter**: semgrep-kryon
- **Severity**: ERROR
- **Message**: Pointer explicitly assigned NULL then dereferenced. CWE-476. 

Code context:
```c
      910      GtkWidget *dialog;
      911      GtkWidget *heading_label;
      912      GtkWidget *input_entry;
      913      GtkWidget *confirm_entry;
      914      GtkWidget *confirm_label;
      915      GtkWidget *remember_pin_checkbutton;
      916      GtkImage *optical_challenge;
      917  
>>>   918      static GncFlickerGui *flickergui = NULL;
      919  
      920      const gchar *internal_input, *internal_confirmed;
      921      gboolean confirm = (flags & GWEN_GUI_INPUT_FLAGS_CONFIRM) != 0;
      922      gboolean is_tan = (flags & GWEN_GUI_INPUT_FLAGS_TAN) != 0;
      923  
      924      g_return_if_fail(input);
      925      g_return_if_fail(max_len >= min_len && max_len > 0);
      926  
```

**Label**: [ ] TP  [ ] FP  [ ] UNK

**Rationale**:

---

### CWE-476-04 — idx=63 

- **File**: `gnucash/gnome/top-level.c`
- **Line**: 282-317
- **CWE**: CWE-476
- **Rule**: `kryon-rules.kryon.cwe-476.null-assign-deref`
- **Hunter**: semgrep-kryon
- **Severity**: ERROR
- **Message**: Pointer explicitly assigned NULL then dereferenced. CWE-476. 

Code context:
```c
      274   *  @param session A pointer to the current session.
      275   *
      276   *  @param unused An unused pointer. */
      277  static void
      278  gnc_restore_all_state (gpointer session, gpointer unused)
      279  {
      280      GKeyFile *keyfile = NULL;
      281      gchar *file_guid = NULL;
>>>   282      GError *error = NULL;
      283  
      284      keyfile = gnc_state_load (session);
      285  
      286  #ifdef DEBUG
      287      /*  Debugging: dump a copy to the trace log */
      288      {
      289          gchar *file_data;
      290          gsize file_length;
```

**Label**: [ ] TP  [ ] FP  [ ] UNK

**Rationale**:

---

### CWE-476-05 — idx=57 

- **File**: `gnucash/gnome/gnc-plugin-page-report.cpp`
- **Line**: 1009-1027
- **CWE**: CWE-476
- **Rule**: `kryon-rules.kryon.cwe-476.null-assign-deref`
- **Hunter**: semgrep-kryon
- **Severity**: ERROR
- **Message**: Pointer explicitly assigned NULL then dereferenced. CWE-476. 

Code context:
```c
     1001  static GncPluginPage *
     1002  gnc_plugin_page_report_recreate_page (GtkWidget *window,
     1003                                        GKeyFile *key_file,
     1004                                        const gchar *group_name)
     1005  {
     1006      GncPluginPage *page;
     1007      gchar **keys;
     1008      gsize i, num_keys;
>>>  1009      GError *error = nullptr;
     1010      gchar *option_string;
     1011      gint report_id;
     1012      SCM scm_id, final_id = SCM_BOOL_F;
     1013      SCM report;
     1014  
     1015      g_return_val_if_fail(key_file, nullptr);
     1016      g_return_val_if_fail(group_name, nullptr);
     1017      ENTER("key_file %p, group_name %s", key_file, group_name);
```

**Label**: [ ] TP  [ ] FP  [ ] UNK

**Rationale**:

---

### CWE-476-06 — idx=35 

- **File**: `gnucash/gnome/dialog-print-check.c`
- **Line**: 958-1156
- **CWE**: CWE-476
- **Rule**: `kryon-rules.kryon.cwe-476.null-assign-deref`
- **Hunter**: semgrep-kryon
- **Severity**: ERROR
- **Message**: Pointer explicitly assigned NULL then dereferenced. CWE-476. 

Code context:
```c
      950   * read, meaning that items listed later in the date file can be printed over
      951   * top of items that appear earlier in the file.
      952   */
      953  static GSList *
      954  format_read_item_placement(const gchar *file,
      955                             GKeyFile *key_file, check_format_t *format)
      956  {
      957      check_item_t *data = NULL;
>>>   958      GError *error = NULL;
      959      GSList *list = NULL;
      960      gchar *key, *value, *name;
      961      int item_num;
      962      gboolean bval;
      963      gdouble *dd;
      964      gsize dd_len;
      965  
      966      /* Read until failure. */
```

**Label**: [ ] TP  [ ] FP  [ ] UNK

**Rationale**:

---

### CWE-476-07 — idx=26 

- **File**: `gnucash/gnome-utils/gnc-tree-view-account.c`
- **Line**: 2568-2646
- **CWE**: CWE-476
- **Rule**: `kryon-rules.kryon.cwe-476.null-assign-deref`
- **Hunter**: semgrep-kryon
- **Severity**: ERROR
- **Message**: Pointer explicitly assigned NULL then dereferenced. CWE-476. 

Code context:
```c
     2560          gnc_tree_view_account_set_selected_account(view, account);
     2561  }
     2562  
     2563  void
     2564  gnc_tree_view_account_restore(GncTreeViewAccount *view,
     2565                                AccountFilterDialog *fd,
     2566                                GKeyFile *key_file, const gchar *group_name)
     2567  {
>>>  2568      GError *error = NULL;
     2569      gchar *key, *value;
     2570      gint i, count;
     2571      gboolean show;
     2572  
     2573      /* Filter information. Ignore missing keys. */
     2574      show = g_key_file_get_boolean(key_file, group_name, SHOW_HIDDEN, &error);
     2575      if (error)
     2576      {
```

**Label**: [ ] TP  [ ] FP  [ ] UNK

**Rationale**:

---

### CWE-476-08 — idx=22 

- **File**: `gnucash/gnome-utils/gnc-tree-view-account.c`
- **Line**: 2568-2582
- **CWE**: CWE-476
- **Rule**: `kryon-rules.kryon.cwe-476.null-assign-deref`
- **Hunter**: semgrep-kryon
- **Severity**: ERROR
- **Message**: Pointer explicitly assigned NULL then dereferenced. CWE-476. 

Code context:
```c
     2560          gnc_tree_view_account_set_selected_account(view, account);
     2561  }
     2562  
     2563  void
     2564  gnc_tree_view_account_restore(GncTreeViewAccount *view,
     2565                                AccountFilterDialog *fd,
     2566                                GKeyFile *key_file, const gchar *group_name)
     2567  {
>>>  2568      GError *error = NULL;
     2569      gchar *key, *value;
     2570      gint i, count;
     2571      gboolean show;
     2572  
     2573      /* Filter information. Ignore missing keys. */
     2574      show = g_key_file_get_boolean(key_file, group_name, SHOW_HIDDEN, &error);
     2575      if (error)
     2576      {
```

**Label**: [ ] TP  [ ] FP  [ ] UNK

**Rationale**:

---

### CWE-476-09 — idx=109 [TEST-FILE]

- **File**: `gnucash/register/ledger-core/test/utest-split-register-copy-ops.c`
- **Line**: 533-545
- **CWE**: CWE-476
- **Rule**: `kryon-rules.kryon.cwe-476.null-assign-deref`
- **Hunter**: semgrep-kryon
- **Severity**: ERROR
- **Message**: Pointer explicitly assigned NULL then dereferenced. CWE-476. 

Code context:
```c
      525  {
      526  }*/
      527  /* gnc_txn_to_float_txn
      528  FloatingTxn *gnc_txn_to_float_txn (Transaction *txn, gboolean use_cut_semantics)// C: 3 in 1  Local: 0:0:0
      529  */
      530  static void
      531  test_gnc_txn_to_float_txn (Fixture *fixture, gconstpointer pData)
      532  {
>>>   533      FloatingTxn *ft = NULL;
      534      SplitList *sl = xaccTransGetSplitList(fixture->txn), *siter;
      535      SplitList *fsiter;
      536      FloatingSplit *fs;
      537      Split *s;
      538  
      539      ft = gnc_txn_to_float_txn (fixture->txn, FALSE, FALSE);
      540  
      541      /* Check transaction fields */
```

**Label**: [ ] TP  [ ] FP  [ ] UNK

**Rationale**:

---

### CWE-476-10 — idx=8 

- **File**: `gnucash/gnome-utils/gnc-main-window.cpp`
- **Line**: 557-576
- **CWE**: CWE-476
- **Rule**: `kryon-rules.kryon.cwe-476.null-assign-deref`
- **Hunter**: semgrep-kryon
- **Severity**: ERROR
- **Message**: Pointer explicitly assigned NULL then dereferenced. CWE-476. 

Code context:
```c
      549  
      550      return false;
      551  }
      552  
      553  static void
      554  set_window_geometry(GncMainWindow *window, GncMainWindowSaveData *data, gchar *window_group)
      555  {
      556      gsize length;
>>>   557      GError *error = nullptr;
      558      gint *geom = g_key_file_get_integer_list(data->key_file, window_group,
      559                                         WINDOW_GEOMETRY, &length, &error);
      560      if (error)
      561      {
      562          g_warning("error reading group %s key %s: %s",
      563                    window_group, WINDOW_GEOMETRY, error->message);
      564          g_error_free(error);
      565          error = nullptr;
```

**Label**: [ ] TP  [ ] FP  [ ] UNK

**Rationale**:

---

### CWE-476-11 — idx=7 

- **File**: `gnucash/gnome-utils/gnc-main-window.cpp`
- **Line**: 456-517
- **CWE**: CWE-476
- **Rule**: `kryon-rules.kryon.cwe-476.null-assign-deref`
- **Hunter**: semgrep-kryon
- **Severity**: ERROR
- **Message**: Pointer explicitly assigned NULL then dereferenced. CWE-476. 

Code context:
```c
      448  static gboolean
      449  gnc_main_window_restore_page (GncMainWindow *window,
      450                                GncMainWindowSaveData *data)
      451  {
      452      GncMainWindowPrivate *priv;
      453      GncPluginPage *page = nullptr;
      454      gchar *page_group, *page_type = nullptr, *name = nullptr;
      455      const gchar *class_type;
>>>   456      GError *error = nullptr;
      457  
      458      ENTER("window %p, data %p (key file %p, window %d, page start %d, page num %d)",
      459            window, data, data->key_file, data->window_num, data->page_offset,
      460            data->page_num);
      461  
      462      priv = GNC_MAIN_WINDOW_GET_PRIVATE(window);
      463      page_group = g_strdup_printf(PAGE_STRING,
      464                                   data->page_offset + data->page_num);
```

**Label**: [ ] TP  [ ] FP  [ ] UNK

**Rationale**:

---

### CWE-476-12 — idx=23 

- **File**: `gnucash/gnome-utils/gnc-tree-view-account.c`
- **Line**: 2568-2593
- **CWE**: CWE-476
- **Rule**: `kryon-rules.kryon.cwe-476.null-assign-deref`
- **Hunter**: semgrep-kryon
- **Severity**: ERROR
- **Message**: Pointer explicitly assigned NULL then dereferenced. CWE-476. 

Code context:
```c
     2560          gnc_tree_view_account_set_selected_account(view, account);
     2561  }
     2562  
     2563  void
     2564  gnc_tree_view_account_restore(GncTreeViewAccount *view,
     2565                                AccountFilterDialog *fd,
     2566                                GKeyFile *key_file, const gchar *group_name)
     2567  {
>>>  2568      GError *error = NULL;
     2569      gchar *key, *value;
     2570      gint i, count;
     2571      gboolean show;
     2572  
     2573      /* Filter information. Ignore missing keys. */
     2574      show = g_key_file_get_boolean(key_file, group_name, SHOW_HIDDEN, &error);
     2575      if (error)
     2576      {
```

**Label**: [ ] TP  [ ] FP  [ ] UNK

**Rationale**:

---

### CWE-476-13 — idx=55 

- **File**: `gnucash/gnome/gnc-plugin-page-account-tree.cpp`
- **Line**: 463-489
- **CWE**: CWE-476
- **Rule**: `kryon-rules.kryon.cwe-476.null-assign-deref`
- **Hunter**: semgrep-kryon
- **Severity**: ERROR
- **Message**: Pointer explicitly assigned NULL then dereferenced. CWE-476. 

Code context:
```c
      455      LEAVE(" ");
      456  }
      457  
      458  void
      459  gnc_plugin_page_account_tree_open (Account *account, GtkWindow *win)
      460  {
      461      GncPluginPageAccountTreePrivate *priv;
      462      GncPluginPageAccountTree *page;
>>>   463      GncPluginPage *plugin_page = NULL;
      464      const GList *page_list;
      465      GtkWidget   *window;
      466  
      467      /* Find Accounts page */
      468      page_list = gnc_gobject_tracking_get_list(GNC_PLUGIN_PAGE_ACCOUNT_TREE_NAME);
      469  
      470      // If we have a window, look for account page in that window
      471      if (gnc_list_length_cmp (page_list, 0))
```

**Label**: [ ] TP  [ ] FP  [ ] UNK

**Rationale**:

---

### CWE-476-14 — idx=59 

- **File**: `gnucash/gnome/gnc-plugin-page-report.cpp`
- **Line**: 1421-1431
- **CWE**: CWE-476
- **Rule**: `kryon-rules.kryon.cwe-476.null-assign-deref`
- **Hunter**: semgrep-kryon
- **Severity**: ERROR
- **Message**: Pointer explicitly assigned NULL then dereferenced. CWE-476. 

Code context:
```c
     1413  
     1414  static void
     1415  gnc_plugin_page_report_forw_cb (GSimpleAction *simple,
     1416                                  GVariant *parameter,
     1417                                  gpointer user_data)
     1418  {
     1419      GncPluginPageReport *report = (GncPluginPageReport*)user_data;
     1420      GncPluginPageReportPrivate *priv;
>>>  1421      gnc_html_history_node * node = nullptr;
     1422  
     1423      DEBUG( "forw" );
     1424      priv = GNC_PLUGIN_PAGE_REPORT_GET_PRIVATE(report);
     1425      gnc_html_history_forward(gnc_html_get_history(priv->html));
     1426      node = gnc_html_history_get_current(gnc_html_get_history(priv->html));
     1427      if (node)
     1428      {
     1429          gnc_html_show_url(priv->html, node->type, node->location,
```

**Label**: [ ] TP  [ ] FP  [ ] UNK

**Rationale**:

---

### CWE-476-15 — idx=145 

- **File**: `libgnucash/engine/gnc-pricedb.cpp`
- **Line**: 2337-2364
- **CWE**: CWE-476
- **Rule**: `kryon-rules.kryon.cwe-476.null-assign-deref`
- **Hunter**: semgrep-kryon
- **Severity**: ERROR
- **Message**: Pointer explicitly assigned NULL then dereferenced. CWE-476. 

Code context:
```c
     2329      GNCPrice *to;
     2330  } PriceTuple;
     2331  
     2332  static PriceTuple
     2333  extract_common_prices (PriceList *from_prices, PriceList *to_prices,
     2334                         const gnc_commodity *from, const gnc_commodity *to)
     2335  {
     2336      PriceTuple retval = {nullptr, nullptr};
>>>  2337      GList *from_node = nullptr, *to_node = nullptr;
     2338      GNCPrice *from_price = nullptr, *to_price = nullptr;
     2339  
     2340      for (from_node = from_prices; from_node != nullptr;
     2341           from_node = g_list_next(from_node))
     2342      {
     2343          for (to_node = to_prices; to_node != nullptr;
     2344               to_node = g_list_next(to_node))
     2345          {
```

**Label**: [ ] TP  [ ] FP  [ ] UNK

**Rationale**:

---

### CWE-476-16 — idx=50 

- **File**: `gnucash/gnome/dialog-report-style-sheet.cpp`
- **Line**: 47-560
- **CWE**: CWE-476
- **Rule**: `kryon-rules.kryon.cwe-476.null-assign-deref`
- **Hunter**: semgrep-kryon
- **Severity**: ERROR
- **Message**: Pointer explicitly assigned NULL then dereferenced. CWE-476. 

Code context:
```c
       39  #include "gnc-guile-utils.h"
       40  #include "gnc-ui.h"
       41  #include <guile-mappings.h>
       42  #include "gnc-report.h"
       43  
       44  #define DIALOG_STYLE_SHEETS_CM_CLASS "style-sheets-dialog"
       45  #define GNC_PREFS_GROUP              "dialogs.style-sheet"
       46  
>>>    47  StyleSheetDialog * gnc_style_sheet_dialog = NULL;
       48  
       49  struct _stylesheetdialog
       50  {
       51      GtkWidget     * toplevel;
       52      GtkTreeView   * list_view;
       53      GtkListStore  * list_store;
       54      GtkWidget     * options_frame;
       55      gint            component_id;
```

**Label**: [ ] TP  [ ] FP  [ ] UNK

**Rationale**:

---

### CWE-476-17 — idx=92 

- **File**: `gnucash/import-export/csv-imp/gnc-import-price.cpp`
- **Line**: 559-600
- **CWE**: CWE-476
- **Rule**: `kryon-rules.kryon.cwe-476.null-assign-deref`
- **Hunter**: semgrep-kryon
- **Severity**: ERROR
- **Message**: Pointer explicitly assigned NULL then dereferenced. CWE-476. 

Code context:
```c
      551      if (!error_message.empty())
      552          throw std::invalid_argument(error_message);
      553  }
      554  
      555  void GncPriceImport::create_price (std::vector<parse_line_t>::iterator& parsed_line)
      556  {
      557      StrVec line;
      558      std::string error_message;
>>>   559      std::shared_ptr<GncImportPrice> price_props = nullptr;
      560      bool skip_line = false;
      561      std::tie(line, error_message, price_props, skip_line) = *parsed_line;
      562  
      563      if (skip_line)
      564          return;
      565  
      566      error_message.clear();
      567  
```

**Label**: [ ] TP  [ ] FP  [ ] UNK

**Rationale**:

---

### CWE-476-18 — idx=84 

- **File**: `gnucash/import-export/csv-imp/assistant-csv-trans-import.cpp`
- **Line**: 849-856
- **CWE**: CWE-476
- **Rule**: `kryon-rules.kryon.cwe-476.null-assign-deref`
- **Hunter**: semgrep-kryon
- **Severity**: ERROR
- **Message**: Pointer explicitly assigned NULL then dereferenced. CWE-476. 

Code context:
```c
      841  void
      842  CsvImpTransAssist::preview_settings_load ()
      843  {
      844      // Get the Active Selection
      845      GtkTreeIter iter;
      846      if (!gtk_combo_box_get_active_iter (settings_combo, &iter))
      847          return;
      848  
>>>   849      CsvTransImpSettings *preset = nullptr;
      850      auto model = gtk_combo_box_get_model (settings_combo);
      851      gtk_tree_model_get (model, &iter, SET_GROUP, &preset, -1);
      852  
      853      if (!preset)
      854          return;
      855  
      856      tx_imp->settings (*preset);
      857      if (preset->m_load_error)
```

**Label**: [ ] TP  [ ] FP  [ ] UNK

**Rationale**:

---

### CWE-476-19 — idx=90 

- **File**: `gnucash/import-export/csv-imp/gnc-import-price.cpp`
- **Line**: 559-583
- **CWE**: CWE-476
- **Rule**: `kryon-rules.kryon.cwe-476.null-assign-deref`
- **Hunter**: semgrep-kryon
- **Severity**: ERROR
- **Message**: Pointer explicitly assigned NULL then dereferenced. CWE-476. 

Code context:
```c
      551      if (!error_message.empty())
      552          throw std::invalid_argument(error_message);
      553  }
      554  
      555  void GncPriceImport::create_price (std::vector<parse_line_t>::iterator& parsed_line)
      556  {
      557      StrVec line;
      558      std::string error_message;
>>>   559      std::shared_ptr<GncImportPrice> price_props = nullptr;
      560      bool skip_line = false;
      561      std::tie(line, error_message, price_props, skip_line) = *parsed_line;
      562  
      563      if (skip_line)
      564          return;
      565  
      566      error_message.clear();
      567  
```

**Label**: [ ] TP  [ ] FP  [ ] UNK

**Rationale**:

---

### CWE-476-20 — idx=70 

- **File**: `gnucash/import-export/aqb/gnc-gwen-gui.c`
- **Line**: 65-341
- **CWE**: CWE-476
- **Rule**: `kryon-rules.kryon.cwe-476.null-assign-deref`
- **Hunter**: semgrep-kryon
- **Severity**: ERROR
- **Message**: Pointer explicitly assigned NULL then dereferenced. CWE-476. 

Code context:
```c
       57  #define GNC_PREF_REMEMBER_PIN      "remember-pin"
       58  
       59  # include <gwen-gui-gtk3/gtk3_gui.h>
       60  
       61  /* This static indicates the debugging module that this .o belongs to.  */
       62  static QofLogModule log_module = G_LOG_DOMAIN;
       63  
       64  /* A unique full-blown GUI, featuring  */
>>>    65  static GncGWENGui *full_gui = NULL;
       66  
       67  /* A unique Gwenhywfar GUI for hooking our logging into the gwenhywfar logging
       68   * framework */
       69  static GWEN_GUI *log_gwen_gui = NULL;
       70  
       71  /* A mapping from gwenhywfar log levels to glib ones */
       72  static GLogLevelFlags log_levels[] =
       73  {
```

**Label**: [ ] TP  [ ] FP  [ ] UNK

**Rationale**:

---

### CWE-476-21 — idx=53 

- **File**: `gnucash/gnome/dialog-tax-info.c`
- **Line**: 1177-1218
- **CWE**: CWE-476
- **Rule**: `kryon-rules.kryon.cwe-476.null-assign-deref`
- **Hunter**: semgrep-kryon
- **Severity**: ERROR
- **Message**: Pointer explicitly assigned NULL then dereferenced. CWE-476. 

Code context:
```c
     1169  {
     1170      TaxInfoDialog *ti_dialog = user_data;
     1171      GtkWidget *dialog;
     1172      GtkWidget *content_area;
     1173      GtkWidget *name_entry;
     1174      GtkWidget *label;
     1175      GtkWidget *table;
     1176      GtkListStore *store;
>>>  1177      GList *types = NULL;
     1178      GtkTreeIter iter;
     1179      gint current_item = -1;
     1180      gint item = 0;
     1181      GtkCellRenderer *renderer;
     1182      GtkWidget *type_combo;
     1183  
     1184      dialog = gtk_dialog_new_with_buttons (_("Income Tax Identity"),
     1185                                            (GtkWindow *)ti_dialog->dialog,
```

**Label**: [ ] TP  [ ] FP  [ ] UNK

**Rationale**:

---

### CWE-476-22 — idx=146 

- **File**: `libgnucash/gnc-module/gnc-module.c`
- **Line**: 445-470
- **CWE**: CWE-476
- **Rule**: `kryon-rules.kryon.cwe-476.null-assign-deref`
- **Hunter**: semgrep-kryon
- **Severity**: ERROR
- **Message**: Pointer explicitly assigned NULL then dereferenced. CWE-476. 

Code context:
```c
      437      *l = g_list_prepend(*l, v);
      438  }
      439  
      440  static GNCLoadedModule *
      441  gnc_module_check_loaded(const char * module_name, gint iface)
      442  {
      443      GNCModuleInfo * modinfo = gnc_module_locate(module_name, iface);
      444      GList * modules = NULL;
>>>   445      GList * p = NULL;
      446      GNCLoadedModule * rv = NULL;
      447  
      448      if (modinfo == NULL)
      449      {
      450          return NULL;
      451      }
      452  
      453      if (!loaded_modules)
```

**Label**: [ ] TP  [ ] FP  [ ] UNK

**Rationale**:

---

### CWE-476-23 — idx=142 

- **File**: `libgnucash/engine/Scrub.cpp`
- **Line**: 1059-1106
- **CWE**: CWE-476
- **Rule**: `kryon-rules.kryon.cwe-476.null-assign-deref`
- **Hunter**: semgrep-kryon
- **Severity**: ERROR
- **Message**: Pointer explicitly assigned NULL then dereferenced. CWE-476. 

Code context:
```c
     1051   * slightly more sense for the transaction commodity to be the
     1052   * currency -- to the extent that it makes sense for a transaction to
     1053   * have a currency at all. jralls, 2010-11-02 */
     1054  
     1055  static gnc_commodity *
     1056  xaccTransFindCommonCurrency (Transaction *trans, QofBook *book)
     1057  {
     1058      gnc_commodity *com_scratch;
>>>  1059      GList *node = nullptr;
     1060      GSList *comlist = nullptr, *found = nullptr;
     1061  
     1062      if (!trans) return nullptr;
     1063  
     1064      if (trans->splits == nullptr) return nullptr;
     1065  
     1066      g_return_val_if_fail (book, nullptr);
     1067  
```

**Label**: [ ] TP  [ ] FP  [ ] UNK

**Rationale**:

---

### CWE-476-24 — idx=76 

- **File**: `gnucash/import-export/aqb/gnc-gwen-gui.c`
- **Line**: 918-968
- **CWE**: CWE-476
- **Rule**: `kryon-rules.kryon.cwe-476.null-assign-deref`
- **Hunter**: semgrep-kryon
- **Severity**: ERROR
- **Message**: Pointer explicitly assigned NULL then dereferenced. CWE-476. 

Code context:
```c
      910      GtkWidget *dialog;
      911      GtkWidget *heading_label;
      912      GtkWidget *input_entry;
      913      GtkWidget *confirm_entry;
      914      GtkWidget *confirm_label;
      915      GtkWidget *remember_pin_checkbutton;
      916      GtkImage *optical_challenge;
      917  
>>>   918      static GncFlickerGui *flickergui = NULL;
      919  
      920      const gchar *internal_input, *internal_confirmed;
      921      gboolean confirm = (flags & GWEN_GUI_INPUT_FLAGS_CONFIRM) != 0;
      922      gboolean is_tan = (flags & GWEN_GUI_INPUT_FLAGS_TAN) != 0;
      923  
      924      g_return_if_fail(input);
      925      g_return_if_fail(max_len >= min_len && max_len > 0);
      926  
```

**Label**: [ ] TP  [ ] FP  [ ] UNK

**Rationale**:

---

### CWE-476-25 — idx=141 

- **File**: `libgnucash/engine/Scrub.cpp`
- **Line**: 793-833
- **CWE**: CWE-476
- **Rule**: `kryon-rules.kryon.cwe-476.null-assign-deref`
- **Hunter**: semgrep-kryon
- **Severity**: ERROR
- **Message**: Pointer explicitly assigned NULL then dereferenced. CWE-476. 

Code context:
```c
      785   * ordinarily be necessary.
      786   * @param trans the transaction to balance
      787   * @param root the root account
      788   */
      789  static void
      790  gnc_transaction_balance_trading_more_splits (Transaction *trans, Account *root)
      791  {
      792      /* Copy the split list so we don't see the splits we're adding */
>>>   793      GList *splits_dup = g_list_copy(trans->splits), *splits = nullptr;
      794      const gnc_commodity  *txn_curr = xaccTransGetCurrency (trans);
      795      for (splits = splits_dup; splits; splits = splits->next)
      796      {
      797          Split *split = GNC_SPLIT(splits->data);
      798          if (! xaccTransStillHasSplit(trans, split)) continue;
      799          if (!gnc_numeric_zero_p(xaccSplitGetValue(split)) &&
      800              gnc_numeric_zero_p(xaccSplitGetAmount(split)))
      801          {
```

**Label**: [ ] TP  [ ] FP  [ ] UNK

**Rationale**:

---

### CWE-476-26 — idx=104 [TEST-FILE]

- **File**: `gnucash/register/ledger-core/test/utest-split-register-copy-ops.c`
- **Line**: 435-446
- **CWE**: CWE-476
- **Rule**: `kryon-rules.kryon.cwe-476.null-assign-deref`
- **Hunter**: semgrep-kryon
- **Severity**: ERROR
- **Message**: Pointer explicitly assigned NULL then dereferenced. CWE-476. 

Code context:
```c
      427  {
      428  }*/
      429  /* gnc_split_to_float_split
      430  FloatingSplit *gnc_split_to_float_split (Split *split)// C: 3 in 1  Local: 1:0:0
      431  */
      432  static void
      433  test_gnc_split_to_float_split (Fixture *fixture, gconstpointer pData)
      434  {
>>>   435      FloatingSplit *fs = NULL;
      436      Split *s = xaccTransFindSplitByAccount (fixture->txn, fixture->acc1);
      437  
      438      g_assert_nonnull (s);
      439  
      440      fs = gnc_split_to_float_split (s, FALSE);
      441      g_assert_true (fs->m_split == s);
      442      g_assert_true (fs->m_account == xaccSplitGetAccount (s));
      443      g_assert_true (fs->m_transaction == xaccSplitGetParent (s));
```

**Label**: [ ] TP  [ ] FP  [ ] UNK

**Rationale**:

---

### CWE-476-27 — idx=112 [TEST-FILE]

- **File**: `gnucash/register/ledger-core/test/utest-split-register-copy-ops.c`
- **Line**: 533-548
- **CWE**: CWE-476
- **Rule**: `kryon-rules.kryon.cwe-476.null-assign-deref`
- **Hunter**: semgrep-kryon
- **Severity**: ERROR
- **Message**: Pointer explicitly assigned NULL then dereferenced. CWE-476. 

Code context:
```c
      525  {
      526  }*/
      527  /* gnc_txn_to_float_txn
      528  FloatingTxn *gnc_txn_to_float_txn (Transaction *txn, gboolean use_cut_semantics)// C: 3 in 1  Local: 0:0:0
      529  */
      530  static void
      531  test_gnc_txn_to_float_txn (Fixture *fixture, gconstpointer pData)
      532  {
>>>   533      FloatingTxn *ft = NULL;
      534      SplitList *sl = xaccTransGetSplitList(fixture->txn), *siter;
      535      SplitList *fsiter;
      536      FloatingSplit *fs;
      537      Split *s;
      538  
      539      ft = gnc_txn_to_float_txn (fixture->txn, FALSE, FALSE);
      540  
      541      /* Check transaction fields */
```

**Label**: [ ] TP  [ ] FP  [ ] UNK

**Rationale**:

---

### CWE-476-28 — idx=0 

- **File**: `bindings/guile/gnc-engine-guile.cpp`
- **Line**: 415-422
- **CWE**: CWE-476
- **Rule**: `kryon-rules.kryon.cwe-476.null-assign-deref`
- **Hunter**: semgrep-kryon
- **Severity**: ERROR
- **Message**: Pointer explicitly assigned NULL then dereferenced. CWE-476. 

Code context:
```c
      407      g_slist_free_full (path, (GDestroyNotify)qof_string_cache_remove);
      408  }
      409  
      410  
      411  static SCM
      412  gnc_queryterm2scm (const QofQueryTerm *qt)
      413  {
      414      SCM qt_scm = SCM_EOL;
>>>   415      QofQueryPredData *pd = nullptr;
      416  
      417      qt_scm = scm_cons (gnc_query_path2scm (qof_query_term_get_param_path (qt)),
      418                         qt_scm);
      419      qt_scm = scm_cons (SCM_BOOL (qof_query_term_is_inverted (qt)), qt_scm);
      420  
      421      pd = qof_query_term_get_pred_data (qt);
      422      qt_scm = scm_cons (scm_from_locale_symbol (pd->type_name), qt_scm);
      423      qt_scm = scm_cons (scm_from_long  (pd->how), qt_scm);
```

**Label**: [ ] TP  [ ] FP  [ ] UNK

**Rationale**:

---

### CWE-476-29 — idx=98 

- **File**: `gnucash/import-export/import-backend.cpp`
- **Line**: 403-422
- **CWE**: CWE-476
- **Rule**: `kryon-rules.kryon.cwe-476.null-assign-deref`
- **Hunter**: semgrep-kryon
- **Severity**: ERROR
- **Message**: Pointer explicitly assigned NULL then dereferenced. CWE-476. 

Code context:
```c
      395              else if (j <= add_threshold)
      396                  strcat(xpm[num_colors+1+i], "brrrrb ");
      397              else if (j >= clear_threshold)
      398                  strcat(xpm[num_colors+1+i], "bggggb ");
      399              else
      400                  strcat(xpm[num_colors+1+i], "byyyyb ");
      401          }
      402      }
>>>   403      GError *err = nullptr;
      404      std::string xpm_str = "/* XPM */\nstatic char * XFACE[] = {\n";
      405  
      406      for (auto i = 0UL; i < xpm_size - 1; i++)
      407      {
      408         xpm_str += "\"";
      409          xpm_str += xpm[i];
      410          xpm_str += "\",\n";
      411          g_free(xpm[i]);
```

**Label**: [ ] TP  [ ] FP  [ ] UNK

**Rationale**:

---

### CWE-476-30 — idx=118 [TEST-FILE]

- **File**: `gnucash/register/ledger-core/test/utest-split-register-copy-ops.c`
- **Line**: 590-602
- **CWE**: CWE-476
- **Rule**: `kryon-rules.kryon.cwe-476.null-assign-deref`
- **Hunter**: semgrep-kryon
- **Severity**: ERROR
- **Message**: Pointer explicitly assigned NULL then dereferenced. CWE-476. 

Code context:
```c
      582  
      583      g_assert_null (fsiter->next);
      584  
      585      gnc_float_txn_free (ft);
      586  }
      587  static void
      588  test_gnc_txn_to_float_txn_cut_semantics (Fixture *fixture, gconstpointer pData)
      589  {
>>>   590      FloatingTxn *ft = NULL;
      591      SplitList *sl = xaccTransGetSplitList(fixture->txn), *siter;
      592      SplitList *fsiter;
      593      FloatingSplit *fs;
      594      Split *s;
      595  
      596      ft = gnc_txn_to_float_txn (fixture->txn, TRUE, FALSE);
      597  
      598      /* Check transaction fields */
```

**Label**: [ ] TP  [ ] FP  [ ] UNK

**Rationale**:

---

## Category: CWE-121

### CWE-121-01 — idx=62 

- **File**: `gnucash/gnome/gnc-split-reg.c`
- **Line**: 548-575
- **CWE**: CWE-121
- **Rule**: `kryon-rules.kryon.cwe-121.unsafe-strcat`
- **Hunter**: semgrep-kryon
- **Severity**: ERROR
- **Message**: strcat into fixed-size stack buffer without bounds check. CWE-121. 

Code context:
```c
      540                            xaccGetBalanceFn getter,
      541                            Account *leader,
      542                            GNCPrintAmountInfo print_info,
      543                            gnc_commodity *cmdty,
      544                            gboolean reverse,
      545                            gboolean euroFlag )
      546  {
      547      gnc_numeric amount;
>>>   548      char string[256];
      549      const gchar *label_str = NULL;
      550      GtkWidget *text_label, *hbox;
      551      gchar *bidi_string;
      552  
      553      if ( label == NULL )
      554          return;
      555  
      556      hbox = g_object_get_data (G_OBJECT(label), "text_box");
```

**Label**: [ ] TP  [ ] FP  [ ] UNK

**Rationale**:

---

### CWE-121-02 — idx=147 

- **File**: `libgnucash/engine/Account.cpp`
- **Line**: 226-226
- **CWE**: CWE-121
- **Rule**: `heuristic.cwe-121`
- **Hunter**: heuristic
- **Severity**: WARNING
- **Message**: CWE-121 pattern match: strcpy(account_separator, ":")

Code context:
```c
      218  {
      219      gunichar uc;
      220      gint count;
      221  
      222      uc = g_utf8_get_char_validated(separator, -1);
      223      if ((uc == (gunichar) - 2) || (uc == (gunichar) - 1) || g_unichar_isalnum(uc))
      224      {
      225          account_uc_separator = ':';
>>>   226          strcpy(account_separator, ":");
      227          return;
      228      }
      229  
      230      account_uc_separator = uc;
      231      count = g_unichar_to_utf8(uc, account_separator);
      232      account_separator[count] = '\0';
      233  }
      234  
```

**Label**: [ ] TP  [ ] FP  [ ] UNK

**Rationale**:

---

### CWE-121-03 — idx=148 

- **File**: `gnucash/import-export/bi-import/dialog-bi-import.c`
- **Line**: 518-518
- **CWE**: CWE-121
- **Rule**: `heuristic.cwe-121`
- **Hunter**: heuristic
- **Severity**: WARNING
- **Message**: CWE-121 pattern match: strcpy( id, running_id->str)

Code context:
```c
      510          // Get the next row and its id.
      511          valid = gtk_tree_model_iter_next (GTK_TREE_MODEL (store), &iter);
      512          if (valid) gtk_tree_model_get (GTK_TREE_MODEL (store), &iter, ID, &id, -1);
      513  
      514  
      515          // If the id of the next row is blank, it takes the id of the previous row.
      516          if (valid && strlen(id) == 0)
      517          {
>>>   518              strcpy( id, running_id->str);
      519              gtk_list_store_set (store, &iter, ID, id, -1);
      520          }
      521  
      522          // If this row was the last row of the invoice...
      523          if (!valid || (valid && g_strcmp0 (id, running_id->str) != 0))
      524          {
      525              // If invoice should be ignored, remove all rows of this invoice.
      526              if (ignore_invoice)
```

**Label**: [ ] TP  [ ] FP  [ ] UNK

**Rationale**:

---

### CWE-121-04 — idx=149 

- **File**: `libgnucash/backend/xml/io-gncxml-v2.cpp`
- **Line**: 1749-1749
- **CWE**: CWE-121
- **Rule**: `heuristic.cwe-121`
- **Hunter**: heuristic
- **Severity**: WARNING
- **Message**: CWE-121 pattern match: strcpy (cursor, tail)

Code context:
```c
     1741  
     1742              /* overwrite '&' with the specified character */
     1743              *cursor = (gchar) number;
     1744              cursor++;
     1745              if (* (semicolon + 1))
     1746              {
     1747                  /* move text after semicolon the the left */
     1748                  tail = g_strdup (semicolon + 1);
>>>  1749                  strcpy (cursor, tail);
     1750                  g_free (tail);
     1751              }
     1752              else
     1753              {
     1754                  /* cut here */
     1755                  *cursor = '\0';
     1756              }
     1757  
```

**Label**: [ ] TP  [ ] FP  [ ] UNK

**Rationale**:

---

### CWE-121-05 — idx=150 

- **File**: `gnucash/import-export/import-backend.cpp`
- **Line**: 392-392
- **CWE**: CWE-121
- **Rule**: `heuristic.cwe-121`
- **Hunter**: heuristic
- **Severity**: WARNING
- **Message**: CWE-121 pattern match: strcat(xpm[num_colors+1+i], "b")

Code context:
```c
      384      auto add_threshold = gnc_import_Settings_get_add_threshold(settings);
      385      auto clear_threshold = gnc_import_Settings_get_clear_threshold(settings);
      386      for (int i = 0; i < height; i++)
      387      {
      388          xpm[num_colors+1+i] = g_new0(char, (width_each_bar * score) + width_first_bar + 1);
      389          for (int j = 0; j <= score; j++)
      390          {
      391              if (j == 0)
>>>   392                  strcat(xpm[num_colors+1+i], "b");
      393              else if (i == 0 || i == height - 1)
      394                  strcat(xpm[num_colors+1+i], "bbbbbb ");
      395              else if (j <= add_threshold)
      396                  strcat(xpm[num_colors+1+i], "brrrrb ");
      397              else if (j >= clear_threshold)
      398                  strcat(xpm[num_colors+1+i], "bggggb ");
      399              else
      400                  strcat(xpm[num_colors+1+i], "byyyyb ");
```

**Label**: [ ] TP  [ ] FP  [ ] UNK

**Rationale**:

---

### CWE-121-06 — idx=151 

- **File**: `gnucash/import-export/import-backend.cpp`
- **Line**: 394-394
- **CWE**: CWE-121
- **Rule**: `heuristic.cwe-121`
- **Hunter**: heuristic
- **Severity**: WARNING
- **Message**: CWE-121 pattern match: strcat(xpm[num_colors+1+i], "bbbbbb ")

Code context:
```c
      386      for (int i = 0; i < height; i++)
      387      {
      388          xpm[num_colors+1+i] = g_new0(char, (width_each_bar * score) + width_first_bar + 1);
      389          for (int j = 0; j <= score; j++)
      390          {
      391              if (j == 0)
      392                  strcat(xpm[num_colors+1+i], "b");
      393              else if (i == 0 || i == height - 1)
>>>   394                  strcat(xpm[num_colors+1+i], "bbbbbb ");
      395              else if (j <= add_threshold)
      396                  strcat(xpm[num_colors+1+i], "brrrrb ");
      397              else if (j >= clear_threshold)
      398                  strcat(xpm[num_colors+1+i], "bggggb ");
      399              else
      400                  strcat(xpm[num_colors+1+i], "byyyyb ");
      401          }
      402      }
```

**Label**: [ ] TP  [ ] FP  [ ] UNK

**Rationale**:

---

### CWE-121-07 — idx=152 

- **File**: `gnucash/import-export/import-backend.cpp`
- **Line**: 396-396
- **CWE**: CWE-121
- **Rule**: `heuristic.cwe-121`
- **Hunter**: heuristic
- **Severity**: WARNING
- **Message**: CWE-121 pattern match: strcat(xpm[num_colors+1+i], "brrrrb ")

Code context:
```c
      388          xpm[num_colors+1+i] = g_new0(char, (width_each_bar * score) + width_first_bar + 1);
      389          for (int j = 0; j <= score; j++)
      390          {
      391              if (j == 0)
      392                  strcat(xpm[num_colors+1+i], "b");
      393              else if (i == 0 || i == height - 1)
      394                  strcat(xpm[num_colors+1+i], "bbbbbb ");
      395              else if (j <= add_threshold)
>>>   396                  strcat(xpm[num_colors+1+i], "brrrrb ");
      397              else if (j >= clear_threshold)
      398                  strcat(xpm[num_colors+1+i], "bggggb ");
      399              else
      400                  strcat(xpm[num_colors+1+i], "byyyyb ");
      401          }
      402      }
      403      GError *err = nullptr;
      404      std::string xpm_str = "/* XPM */\nstatic char * XFACE[] = {\n";
```

**Label**: [ ] TP  [ ] FP  [ ] UNK

**Rationale**:

---

### CWE-121-08 — idx=153 

- **File**: `gnucash/import-export/import-backend.cpp`
- **Line**: 398-398
- **CWE**: CWE-121
- **Rule**: `heuristic.cwe-121`
- **Hunter**: heuristic
- **Severity**: WARNING
- **Message**: CWE-121 pattern match: strcat(xpm[num_colors+1+i], "bggggb ")

Code context:
```c
      390          {
      391              if (j == 0)
      392                  strcat(xpm[num_colors+1+i], "b");
      393              else if (i == 0 || i == height - 1)
      394                  strcat(xpm[num_colors+1+i], "bbbbbb ");
      395              else if (j <= add_threshold)
      396                  strcat(xpm[num_colors+1+i], "brrrrb ");
      397              else if (j >= clear_threshold)
>>>   398                  strcat(xpm[num_colors+1+i], "bggggb ");
      399              else
      400                  strcat(xpm[num_colors+1+i], "byyyyb ");
      401          }
      402      }
      403      GError *err = nullptr;
      404      std::string xpm_str = "/* XPM */\nstatic char * XFACE[] = {\n";
      405  
      406      for (auto i = 0UL; i < xpm_size - 1; i++)
```

**Label**: [ ] TP  [ ] FP  [ ] UNK

**Rationale**:

---

### CWE-121-09 — idx=154 

- **File**: `gnucash/import-export/import-backend.cpp`
- **Line**: 400-400
- **CWE**: CWE-121
- **Rule**: `heuristic.cwe-121`
- **Hunter**: heuristic
- **Severity**: WARNING
- **Message**: CWE-121 pattern match: strcat(xpm[num_colors+1+i], "byyyyb ")

Code context:
```c
      392                  strcat(xpm[num_colors+1+i], "b");
      393              else if (i == 0 || i == height - 1)
      394                  strcat(xpm[num_colors+1+i], "bbbbbb ");
      395              else if (j <= add_threshold)
      396                  strcat(xpm[num_colors+1+i], "brrrrb ");
      397              else if (j >= clear_threshold)
      398                  strcat(xpm[num_colors+1+i], "bggggb ");
      399              else
>>>   400                  strcat(xpm[num_colors+1+i], "byyyyb ");
      401          }
      402      }
      403      GError *err = nullptr;
      404      std::string xpm_str = "/* XPM */\nstatic char * XFACE[] = {\n";
      405  
      406      for (auto i = 0UL; i < xpm_size - 1; i++)
      407      {
      408         xpm_str += "\"";
```

**Label**: [ ] TP  [ ] FP  [ ] UNK

**Rationale**:

---

### CWE-121-10 — idx=155 

- **File**: `gnucash/gnome/gnc-split-reg.c`
- **Line**: 571-571
- **CWE**: CWE-121
- **Rule**: `heuristic.cwe-121`
- **Hunter**: heuristic
- **Severity**: WARNING
- **Message**: CWE-121 pattern match: strcat( string, " / " )

Code context:
```c
      563      {
      564          amount = gnc_numeric_neg( amount );
      565      }
      566  
      567      xaccSPrintAmount( string, amount, print_info );
      568  
      569      if ( euroFlag )
      570      {
>>>   571          strcat( string, " / " );
      572          xaccSPrintAmount( string + strlen( string ),
      573                            gnc_convert_to_euro( cmdty, amount ),
      574                            gnc_commodity_print_info( gnc_get_euro(), TRUE ) );
      575      }
      576  
      577      gnc_set_label_color( label, amount );
      578      bidi_string = gnc_wrap_text_with_bidi_ltr_isolate (string);
      579      gtk_label_set_text( GTK_LABEL(label), bidi_string );
```

**Label**: [ ] TP  [ ] FP  [ ] UNK

**Rationale**:

---

### CWE-121-11 — idx=156 

- **File**: `libgnucash/app-utils/gnc-ui-util.cpp`
- **Line**: 1162-1162
- **CWE**: CWE-121
- **Rule**: `heuristic.cwe-121`
- **Hunter**: heuristic
- **Severity**: WARNING
- **Message**: CWE-121 pattern match: strcpy (buf, temp_buf)

Code context:
```c
     1154  
     1155      // Value may now be decimal, for example if the factional part is zero
     1156      value_is_decimal = gnc_numeric_to_decimal(&val, nullptr);
     1157      /* print the integer part without separators */
     1158      snprintf(temp_buf, buf_size, "%" G_GINT64_FORMAT, whole.num);
     1159      auto num_whole_digits = strlen (temp_buf);
     1160  
     1161      if (!info->use_separators)
>>>  1162          strcpy (buf, temp_buf);
     1163      else
     1164      {
     1165          char* separator;
     1166          char* group;
     1167  
     1168          if (info->monetary)
     1169          {
     1170              separator = lc->mon_thousands_sep;
```

**Label**: [ ] TP  [ ] FP  [ ] UNK

**Rationale**:

---

### CWE-121-12 — idx=157 

- **File**: `libgnucash/app-utils/gnc-ui-util.cpp`
- **Line**: 1219-1219
- **CWE**: CWE-121
- **Rule**: `heuristic.cwe-121`
- **Hunter**: heuristic
- **Severity**: WARNING
- **Message**: CWE-121 pattern match: strcpy (buf, rev_buf)

Code context:
```c
     1211                  }
     1212              }
     1213          }
     1214  
     1215          /* We built the string backwards, now reverse */
     1216          *buf_ptr++ = *temp_ptr;
     1217          *buf_ptr = '\0';
     1218          auto rev_buf = g_utf8_strreverse(buf, -1);
>>>  1219          strcpy (buf, rev_buf);
     1220          g_free(rev_buf);
     1221      } /* endif */
     1222  
     1223      /* at this point, buf contains the whole part of the number */
     1224  
     1225      /* If it's not decimal, print the fraction as an expression. */
     1226      if (!value_is_decimal)
     1227      {
```

**Label**: [ ] TP  [ ] FP  [ ] UNK

**Rationale**:

---

### CWE-121-13 — idx=158 

- **File**: `libgnucash/app-utils/gnc-ui-util.cpp`
- **Line**: 1240-1240
- **CWE**: CWE-121
- **Rule**: `heuristic.cwe-121`
- **Hunter**: heuristic
- **Severity**: WARNING
- **Message**: CWE-121 pattern match: strcat(buf, " - ")

Code context:
```c
     1232                       val.num, val.denom);
     1233          else
     1234              snprintf (temp_buf, buf_size, "%" G_GINT64_FORMAT " * %" G_GINT64_FORMAT,
     1235                       val.num, -val.denom);
     1236  
     1237          if (whole.num == 0)
     1238              *buf = '\0';
     1239          else if (value_is_negative)
>>>  1240              strcat(buf, " - ");
     1241          else
     1242              strcat(buf, " + ");
     1243  
     1244          strcat (buf, temp_buf);
     1245      }
     1246      else
     1247      {
     1248          guint8 num_decimal_places = 0;
```

**Label**: [ ] TP  [ ] FP  [ ] UNK

**Rationale**:

---

### CWE-121-14 — idx=159 

- **File**: `libgnucash/app-utils/gnc-ui-util.cpp`
- **Line**: 1242-1242
- **CWE**: CWE-121
- **Rule**: `heuristic.cwe-121`
- **Hunter**: heuristic
- **Severity**: WARNING
- **Message**: CWE-121 pattern match: strcat(buf, " + ")

Code context:
```c
     1234              snprintf (temp_buf, buf_size, "%" G_GINT64_FORMAT " * %" G_GINT64_FORMAT,
     1235                       val.num, -val.denom);
     1236  
     1237          if (whole.num == 0)
     1238              *buf = '\0';
     1239          else if (value_is_negative)
     1240              strcat(buf, " - ");
     1241          else
>>>  1242              strcat(buf, " + ");
     1243  
     1244          strcat (buf, temp_buf);
     1245      }
     1246      else
     1247      {
     1248          guint8 num_decimal_places = 0;
     1249          char* temp_ptr = temp_buf;
     1250  
```

**Label**: [ ] TP  [ ] FP  [ ] UNK

**Rationale**:

---

### CWE-121-15 — idx=160 

- **File**: `libgnucash/app-utils/gnc-ui-util.cpp`
- **Line**: 1244-1244
- **CWE**: CWE-121
- **Rule**: `heuristic.cwe-121`
- **Hunter**: heuristic
- **Severity**: WARNING
- **Message**: CWE-121 pattern match: strcat (buf, temp_buf)

Code context:
```c
     1236  
     1237          if (whole.num == 0)
     1238              *buf = '\0';
     1239          else if (value_is_negative)
     1240              strcat(buf, " - ");
     1241          else
     1242              strcat(buf, " + ");
     1243  
>>>  1244          strcat (buf, temp_buf);
     1245      }
     1246      else
     1247      {
     1248          guint8 num_decimal_places = 0;
     1249          char* temp_ptr = temp_buf;
     1250  
     1251          auto decimal_point = info->monetary
     1252                               ? lc->mon_decimal_point
```

**Label**: [ ] TP  [ ] FP  [ ] UNK

**Rationale**:

---

### CWE-121-16 — idx=161 

- **File**: `libgnucash/app-utils/gnc-ui-util.cpp`
- **Line**: 1295-1295
- **CWE**: CWE-121
- **Rule**: `heuristic.cwe-121`
- **Hunter**: heuristic
- **Severity**: WARNING
- **Message**: CWE-121 pattern match: strcat (buf, temp_buf)

Code context:
```c
     1287          }
     1288  
     1289          if (num_decimal_places > max_dp)
     1290          {
     1291              PWARN ("max_decimal_places too small; limit %d, value %s%s",
     1292                     info->max_decimal_places, buf, temp_buf);
     1293          }
     1294  
>>>  1295          strcat (buf, temp_buf);
     1296      }
     1297  
     1298      return strlen(buf);
     1299  }
     1300  
     1301  /**
     1302   * @param bufp Should be at least 64 chars.
     1303   **/
```

**Label**: [ ] TP  [ ] FP  [ ] UNK

**Rationale**:

---

### CWE-121-17 — idx=162 

- **File**: `gnucash/gnome/gnc-budget-view.c`
- **Line**: 1137-1137
- **CWE**: CWE-121
- **Rule**: `heuristic.cwe-121`
- **Hunter**: heuristic
- **Severity**: WARNING
- **Message**: CWE-121 pattern match: strcpy (amtbuff, "error")

Code context:
```c
     1129                                NULL);
     1130          }
     1131      }
     1132      else
     1133      {
     1134          numeric = gnc_budget_get_account_period_value (priv->budget, account,
     1135                                                         period_num);
     1136          if (gnc_numeric_check (numeric))
>>>  1137              strcpy (amtbuff, "error");
     1138          else
     1139          {
     1140              if (gnc_reverse_balance (account))
     1141                  numeric = gnc_numeric_neg (numeric);
     1142  
     1143              xaccSPrintAmount (amtbuff, numeric,
     1144                                gnc_account_print_info (account, FALSE));
     1145  
```

**Label**: [ ] TP  [ ] FP  [ ] UNK

**Rationale**:

---

## Category: CWE-190

### CWE-190-01 — idx=132 

- **File**: `libgnucash/app-utils/gnc-ui-util.cpp`
- **Line**: 1565-1565
- **CWE**: CWE-190
- **Rule**: `kryon-rules.kryon.cwe-190.typed-arithmetic-overflow`
- **Hunter**: semgrep-kryon
- **Severity**: ERROR
- **Message**: Typed integer assignment with arithmetic operation. Risk of overflow if operands are unbounded. CWE-190. 

Code context:
```c
     1557          return g_strdup("zero");
     1558      if (val < 0)
     1559          val = -val;
     1560  
     1561      auto result = g_string_sized_new(100);
     1562  
     1563      while (val >= 1000)
     1564      {
>>>  1565          int log_val = log10(val) / 3 + FUDGE;
     1566          int pow_val = exp(log_val * 3 * G_LN10) + FUDGE;
     1567          int this_part = val / pow_val;
     1568          val -= this_part * pow_val;
     1569          auto tmp = integer_to_words(this_part);
     1570          g_string_append_printf(result, "%s %s ", tmp, gettext(big_numbers[log_val]));
     1571          g_free(tmp);
     1572      }
     1573  
```

**Label**: [ ] TP  [ ] FP  [ ] UNK

**Rationale**:

---

### CWE-190-02 — idx=133 

- **File**: `libgnucash/app-utils/gnc-ui-util.cpp`
- **Line**: 1566-1566
- **CWE**: CWE-190
- **Rule**: `kryon-rules.kryon.cwe-190.typed-arithmetic-overflow`
- **Hunter**: semgrep-kryon
- **Severity**: ERROR
- **Message**: Typed integer assignment with arithmetic operation. Risk of overflow if operands are unbounded. CWE-190. 

Code context:
```c
     1558      if (val < 0)
     1559          val = -val;
     1560  
     1561      auto result = g_string_sized_new(100);
     1562  
     1563      while (val >= 1000)
     1564      {
     1565          int log_val = log10(val) / 3 + FUDGE;
>>>  1566          int pow_val = exp(log_val * 3 * G_LN10) + FUDGE;
     1567          int this_part = val / pow_val;
     1568          val -= this_part * pow_val;
     1569          auto tmp = integer_to_words(this_part);
     1570          g_string_append_printf(result, "%s %s ", tmp, gettext(big_numbers[log_val]));
     1571          g_free(tmp);
     1572      }
     1573  
     1574      if (val >= 100)
```

**Label**: [ ] TP  [ ] FP  [ ] UNK

**Rationale**:

---

### CWE-190-03 — idx=135 

- **File**: `libgnucash/backend/sql/gnc-sql-column-table-entry.cpp`
- **Line**: 368-368
- **CWE**: CWE-190
- **Rule**: `kryon-rules.kryon.cwe-190.typed-arithmetic-overflow`
- **Hunter**: semgrep-kryon
- **Severity**: ERROR
- **Message**: Typed integer assignment with arithmetic operation. Risk of overflow if operands are unbounded. CWE-190. 

Code context:
```c
      360          vec.emplace_back (std::make_pair (std::string{m_col_name}, quote_string(guid_s)));
      361          g_free(guid_s);
      362          return;
      363      }
      364  }
      365  /* ----------------------------------------------------------------- */
      366  typedef time64 (*Time64AccessFunc) (const gpointer);
      367  typedef void (*Time64SetterFunc) (const gpointer, time64);
>>>   368  constexpr int TIME_COL_SIZE = 4 + 3 + 3 + 3 + 3 + 3;
      369  
      370  template<> void
      371  GncSqlColumnTableEntryImpl<CT_TIME>::load (const GncSqlBackend* sql_be,
      372                                              GncSqlRow& row,
      373                                              QofIdTypeConst obj_name,
      374                                              gpointer pObject)
      375      const noexcept
      376  {
```

**Label**: [ ] TP  [ ] FP  [ ] UNK

**Rationale**:

---

## Category: heuristic-other
