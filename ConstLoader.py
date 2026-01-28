import idaapi
import ida_bytes
import ida_hexrays
import ida_kernwin
import collections
import ida_xref
import idautils

DEBUG_MODE = True
hooks = None
opt_handler = None
TARGET_MATURITY = ida_hexrays.MMAT_GENERATED
SKIP_READONLY_CHECK = False

def _log(msg):
    if DEBUG_MODE:
        print("[ConstLoader] " + msg)

def _read_value(ea, size):
    if ea == idaapi.BADADDR:
        return None
    if not ida_bytes.is_loaded(ea):
        return None
    if size == 1:
        return ida_bytes.get_byte(ea)
    if size == 2:
        return ida_bytes.get_word(ea)
    if size == 4:
        return ida_bytes.get_dword(ea)
    if size == 8:
        return ida_bytes.get_qword(ea)
    data = ida_bytes.get_bytes(ea, size)
    if not data:
        return None
    return int.from_bytes(data, byteorder="little", signed=False)

def _mask_value(val, size):
    if size <= 0:
        return val
    mask = (1 << (size * 8)) - 1
    return val & mask

def _is_read_only_data_ea(ea):
    if SKIP_READONLY_CHECK:
        return True
    seg = idaapi.getseg(ea)
    if not seg:
        return False
    for xref in idautils.XrefsTo(ea, 0):
        if xref.iscode:
            continue
        if xref.type in (ida_xref.dr_W, ida_xref.dr_O):
            return False
    # Allow writable segments if no write/offset xrefs are found.
    return True

def _all_xrefs_in_func(ea, func):
    if func is None:
        return False
    for xref in idautils.XrefsTo(ea, 0):
        if not xref.iscode:
            continue
        xfunc = idaapi.get_func(xref.frm)
        if xfunc is None or xfunc.start_ea != func.start_ea:
            return False
    return True

def _eval_const_addr(mop):
    if mop is None:
        return None
    if mop.t == ida_hexrays.mop_n:
        return mop.nnn.value
    if mop.t == ida_hexrays.mop_a:
        if mop.a.t == ida_hexrays.mop_v:
            return mop.a.g
        if mop.a.t == ida_hexrays.mop_S:
            return mop.a.s.off
        if mop.a.t == ida_hexrays.mop_n:
            return mop.a.nnn.value
    if mop.t == ida_hexrays.mop_v:
        return mop.g
    if mop.t == ida_hexrays.mop_d:
        op = mop.d.opcode
        if op in (ida_hexrays.m_xdu, ida_hexrays.m_xds, ida_hexrays.m_low, ida_hexrays.m_high):
            return _eval_const_addr(mop.d.l)
        if op == ida_hexrays.m_mov:
            return _eval_const_addr(mop.d.l)
        if op == ida_hexrays.m_add:
            l = _eval_const_addr(mop.d.l)
            r = _eval_const_addr(mop.d.r)
            if l is not None and r is not None:
                return l + r
        if op == ida_hexrays.m_sub:
            l = _eval_const_addr(mop.d.l)
            r = _eval_const_addr(mop.d.r)
            if l is not None and r is not None:
                return l - r
    return None

def _same_reg(a, b):
    return a is not None and b is not None and a.t == ida_hexrays.mop_r and b.t == ida_hexrays.mop_r and a.r == b.r

def _eval_const_expr(ins):
    if ins is None:
        return None
    op = ins.opcode
    if op in (ida_hexrays.m_xdu, ida_hexrays.m_xds, ida_hexrays.m_low, ida_hexrays.m_high):
        return _eval_const_mop(ins.l, ins)
    if op == ida_hexrays.m_mov:
        return _eval_const_mop(ins.l, ins)
    if op == ida_hexrays.m_add:
        l = _eval_const_mop(ins.l, ins)
        r = _eval_const_mop(ins.r, ins)
        if l is not None and r is not None:
            return l + r
    if op == ida_hexrays.m_sub:
        l = _eval_const_mop(ins.l, ins)
        r = _eval_const_mop(ins.r, ins)
        if l is not None and r is not None:
            return l - r
    return None

def _resolve_reg_const(ins, reg_mop):
    cur = ins.prev
    while cur is not None:
        if cur.d is not None and _same_reg(cur.d, reg_mop):
            return _eval_const_expr(cur)
        cur = cur.prev
    return None

def _eval_const_mop(mop, ins_ctx):
    if mop is None:
        return None
    if mop.t == ida_hexrays.mop_r:
        return _resolve_reg_const(ins_ctx, mop)
    if mop.t == ida_hexrays.mop_d:
        return _eval_const_expr(mop.d)
    return _eval_const_addr(mop)

def _get_store_addr_and_value(ins):
    if ins is None:
        return None, None
    if ins.opcode == ida_hexrays.m_stx:
        addr = _eval_const_mop(ins.r, ins)
        return addr, ins.d
    if ins.opcode == ida_hexrays.m_mov and ins.d is not None:
        if ins.d.t in (ida_hexrays.mop_v, ida_hexrays.mop_a):
            addr = _eval_const_addr(ins.d)
            return addr, ins.l
    return None, None

def _find_last_store_value_before(ins, addr):
    cur = ins.prev
    while cur is not None:
        saddr, sval_mop = _get_store_addr_and_value(cur)
        if saddr is not None and saddr == addr:
            val = _eval_const_mop(sval_mop, cur)
            return True, val
        cur = cur.prev
    return False, None

def _resolve_value_for_addr(addr, size, ins, func):
    if _is_read_only_data_ea(addr):
        return _read_value(addr, size)
    if not _all_xrefs_in_func(addr, func):
        return None
    found_write, val = _find_last_store_value_before(ins, addr)
    if not found_write:
        # Allowed: write occurs after read in same function
        return _read_value(addr, size)
    return val

def _fold_ldx_mop(mop):
    if mop is None or mop.t != ida_hexrays.mop_d:
        return False
    if mop.d.opcode != ida_hexrays.m_ldx:
        return False

    addr = _eval_const_mop(mop.d.r, mop.d)
    if addr is None:
        return False
    size = mop.size if mop.size else (mop.d.d.size if mop.d.d is not None else 0)
    if size <= 0:
        return False
    func = None
    try:
        func = idaapi.get_func(mop.d.ea)
    except Exception:
        func = None
    val = _resolve_value_for_addr(addr, size, mop.d, func)
    if val is None:
        return False
    val = _mask_value(val, size)
    _log("fold mop ldx @ 0x%x -> 0x%x" % (mop.d.ea, val))
    mop.make_number(val, size, mop.d.ea)
    return True

def _fold_mem_mop(mop, ins_ea, ins_ctx=None, func=None):
    if mop is None:
        return False
    if mop.t == ida_hexrays.mop_v:
        addr = mop.g
    elif mop.t == ida_hexrays.mop_a:
        addr = _eval_const_addr(mop)
    else:
        return False
    if addr is None:
        return False
    size = mop.size
    if size <= 0:
        return False
    val = _resolve_value_for_addr(addr, size, ins_ctx, func)
    if val is None:
        return False
    val = _mask_value(val, size)
    _log("fold mem @ 0x%x (0x%x) -> 0x%x" % (ins_ea, addr, val))
    mop.make_number(val, size, ins_ea)
    return True

def _fold_mop_recursive(mop, ins_ctx=None, func=None):
    if mop is None:
        return False
    changed = _fold_ldx_mop(mop)
    if _fold_mem_mop(mop, mop.ea if hasattr(mop, "ea") else idaapi.BADADDR, ins_ctx, func):
        changed = True
    if mop.t == ida_hexrays.mop_d:
        if _fold_mop_recursive(mop.d.l, ins_ctx, func):
            changed = True
        if _fold_mop_recursive(mop.d.r, ins_ctx, func):
            changed = True
        if _fold_mop_recursive(mop.d.d, ins_ctx, func):
            changed = True
    elif mop.t == ida_hexrays.mop_a:
        if _fold_mop_recursive(mop.a, ins_ctx, func):
            changed = True
    return changed

class InsnVisitor(ida_hexrays.minsn_visitor_t):
    def __init__(self, *args):
        super().__init__(*args)
        self.changed = False

    def visit_minsn(self, *args) -> "int":
        ins = self.curins
        if ins is None:
            return 0
        changed = False
        func = idaapi.get_func(ins.ea)
        if ins.opcode == ida_hexrays.m_ldx:
            addr = _eval_const_mop(ins.r, ins)
            if addr is not None:
                val = _resolve_value_for_addr(addr, ins.d.size, ins, func)
                if val is not None:
                    val = _mask_value(val, ins.d.size)
                    _log("fold ldx @ 0x%x -> 0x%x" % (ins.ea, val))
                    ins.opcode = ida_hexrays.m_mov
                    ins.l.make_number(val, ins.d.size, ins.ea)
                    ins.r.erase()
                    changed = True

        if _fold_mop_recursive(ins.l, ins, func):
            changed = True
        if _fold_mop_recursive(ins.r, ins, func):
            changed = True

        if changed:
            ins_text = ins.dstr()
            if ins_text:
                ins_text = "".join([c if 0x20 <= ord(c) <= 0x7e else "" for c in ins_text])
            _log("changed ins @ 0x%x: %s" % (ins.ea, ins_text))
            self.changed = True
        return 0

class ConstLoaderOpt(ida_hexrays.optinsn_t):
    def __init__(self):
        super().__init__()
        self._last_maturity = None

    def func(self, blk: ida_hexrays.mblock_t, ins: ida_hexrays.minsn_t, optflags: int) -> int:
        if blk is None or ins is None or blk.mba is None:
            return 0
        if blk.mba.maturity < ida_hexrays.MMAT_GENERATED:
            return 0
        if TARGET_MATURITY is not None and blk.mba.maturity != TARGET_MATURITY:
            return 0
        if self._last_maturity != blk.mba.maturity:
            self._last_maturity = blk.mba.maturity
            _log("optinsn maturity: %d" % blk.mba.maturity)

        visitor = InsnVisitor()
        visitor.blk = blk
        visitor.curins = ins
        visitor.topins = ins
        visitor.visit_minsn()

        if visitor.changed:
            ins.optimize_solo()
            blk.mark_lists_dirty()
            blk.mba.verify(True)
            return 1
        return 0

MenuItem = collections.namedtuple("MenuItem", ["action", "handler", "title", "tooltip", "shortcut", "popup"])

class MenuActionHandler(idaapi.action_handler_t):
    def __init__(self, callback):
        super().__init__()
        self._callback = callback

    def activate(self, ctx):
        try:
            self._callback()
        except Exception as e:
            print("[ConstLoader] menu action error: %s" % e)
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

class ConstLoaderPlugin(idaapi.plugin_t, ida_kernwin.UI_Hooks):
    flags = idaapi.PLUGIN_PROC
    comment = "Fold constant loads from read-only data into microcode."
    help = "Toggle microcode constant-load folding."
    wanted_name = "Const Loader"
    wanted_hotkey = ""

    def init(self):
        self.MENU_ITEMS = []
        self._menu_ready = False
        self.hook()
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        toggle_constloader()
        if opt_handler:
            _refresh_views()

    def term(self):
        global opt_handler
        if opt_handler:
            opt_handler.remove()
            opt_handler = None
        self.unhook()
        if self._menu_ready:
            self._detach_main_menu_actions()
            self._unregister_menu_actions()
            self._menu_ready = False

    def _register_new_action(self, act_name, act_text, act_handler, shortcut, tooltip, icon):
        act = idaapi.action_desc_t(act_name, act_text, act_handler, shortcut, tooltip, icon)
        if not idaapi.register_action(act):
            idaapi.unregister_action(act_name)
            return idaapi.register_action(act)
        return True

    def _register_menu_actions(self):
        self.MENU_ITEMS = []
        self.MENU_ITEMS.append(MenuItem("ConstLoader:toggle", MenuActionHandler(toggle_constloader), "Enable", "Enable/Disable plugin", None, True))
        self.MENU_ITEMS.append(MenuItem("ConstLoader:debug", MenuActionHandler(toggle_debug), "Enable Debug", "Enable/Disable debug logging", None, True))
        self.MENU_ITEMS.append(MenuItem("ConstLoader:skip_ro", MenuActionHandler(toggle_skip_readonly), "Skip ReadOnly Check", "Skip read-only data check", None, True))
        self.MENU_ITEMS.append(MenuItem("-", None, "", None, None, True))
        self.MENU_ITEMS.append(MenuItem("ConstLoader:mat_gen", MenuActionHandler(lambda: set_maturity(ida_hexrays.MMAT_GENERATED)), "MMAT_GENERATED", "", None, True))
        self.MENU_ITEMS.append(MenuItem("ConstLoader:mat_pre", MenuActionHandler(lambda: set_maturity(ida_hexrays.MMAT_PREOPTIMIZED)), "MMAT_PREOPTIMIZED", "", None, True))
        self.MENU_ITEMS.append(MenuItem("ConstLoader:mat_loc", MenuActionHandler(lambda: set_maturity(ida_hexrays.MMAT_LOCOPT)), "MMAT_LOCOPT", "", None, True))
        self.MENU_ITEMS.append(MenuItem("ConstLoader:mat_calls", MenuActionHandler(lambda: set_maturity(ida_hexrays.MMAT_CALLS)), "MMAT_CALLS", "", None, True))
        self.MENU_ITEMS.append(MenuItem("ConstLoader:mat_glb1", MenuActionHandler(lambda: set_maturity(ida_hexrays.MMAT_GLBOPT1)), "MMAT_GLBOPT1", "", None, True))

        for item in self.MENU_ITEMS:
            if item.action == "-":
                continue
            ok = self._register_new_action(item.action, item.title, item.handler, item.shortcut, item.tooltip, -1)
            if not ok:
                print("[ConstLoader] register_action failed: %s" % item.action)
        _update_toggle_label()
        _update_debug_label()
        _update_skip_ro_label()

    def _unregister_menu_actions(self):
        for item in self.MENU_ITEMS:
            if item.action == "-":
                continue
            idaapi.unregister_action(item.action)

    def _attach_main_menu_actions(self):
        menu_root = "Edit/Plugins/" + self.wanted_name + "/"
        for item in self.MENU_ITEMS:
            if item.action == "-":
                continue
            if item.action.startswith("ConstLoader:mat_"):
                path = menu_root + "Maturity/" + item.title
            else:
                path = menu_root + item.title
            ok = idaapi.attach_action_to_menu(path, item.action, idaapi.SETMENU_APP)
            if not ok:
                print("[ConstLoader] attach_action_to_menu failed: %s" % item.title)

    def _detach_main_menu_actions(self):
        menu_root = "Edit/Plugins/" + self.wanted_name + "/"
        for item in self.MENU_ITEMS:
            if item.action == "-":
                continue
            if item.action.startswith("ConstLoader:mat_"):
                path = menu_root + "Maturity/" + item.title
            else:
                path = menu_root + item.title
            idaapi.detach_action_from_menu(path, item.action)

    def finish_populating_widget_popup(self, widget, popup_handle):
        if ida_kernwin.get_widget_type(widget) in (ida_kernwin.BWN_DISASM, ida_kernwin.BWN_PSEUDOCODE):
            for item in self.MENU_ITEMS:
                if item.popup and item.action != "-":
                    if item.action.startswith("ConstLoader:mat_"):
                        path = "ConstLoader/Maturity/"
                    else:
                        path = "ConstLoader/"
                    idaapi.attach_action_to_popup(widget, popup_handle, item.action, path)

    def ready_to_run(self):
        if not self._menu_ready:
            self._register_menu_actions()
            self._attach_main_menu_actions()
            self._menu_ready = True

def PLUGIN_ENTRY():
    return ConstLoaderPlugin()

def _refresh_views():
    ida_kernwin.refresh_idaview_anyway()
    w = ida_kernwin.get_current_widget()
    if w and ida_kernwin.get_widget_type(w) == ida_kernwin.BWN_PSEUDOCODE:
        vu = ida_hexrays.get_widget_vdui(w)
        if vu:
            vu.refresh_ctext()

def toggle_constloader():
    global opt_handler
    if opt_handler:
        opt_handler.remove()
        opt_handler = None
        print("ConstLoader: optinsn removed.")
    else:
        if ida_hexrays.init_hexrays_plugin():
            opt_handler = ConstLoaderOpt()
            opt_handler.install()
            print("ConstLoader: optinsn installed.")
        else:
            print("ConstLoader: Hex-Rays not available.")
    _update_toggle_label()

def toggle_debug():
    global DEBUG_MODE
    DEBUG_MODE = not DEBUG_MODE
    print("ConstLoader: DEBUG_MODE = %s" % DEBUG_MODE)
    _update_debug_label()

def set_maturity(maturity):
    global TARGET_MATURITY
    TARGET_MATURITY = maturity
    print("ConstLoader: TARGET_MATURITY = %d" % TARGET_MATURITY)

def _update_toggle_label():
    label = "Disable" if opt_handler else "Enable"
    try:
        idaapi.update_action_label("ConstLoader:toggle", label)
    except Exception:
        pass

def _update_debug_label():
    label = "Disable Debug" if DEBUG_MODE else "Enable Debug"
    try:
        idaapi.update_action_label("ConstLoader:debug", label)
    except Exception:
        pass

def toggle_skip_readonly():
    global SKIP_READONLY_CHECK
    SKIP_READONLY_CHECK = not SKIP_READONLY_CHECK
    print("ConstLoader: SKIP_READONLY_CHECK = %s" % SKIP_READONLY_CHECK)
    _update_skip_ro_label()

def _update_skip_ro_label():
    label = "Disable Skip ReadOnly Check" if SKIP_READONLY_CHECK else "Enable Skip ReadOnly Check"
    try:
        idaapi.update_action_label("ConstLoader:skip_ro", label)
    except Exception:
        pass