from idaapi import *

"""
This plugin for IDA synchronizes Hexrays decompiler views and disassembly views (from
decompiled code to disassembly by default - use the TAB key for synchronizing from
disassembly to decompiled code).

It also highlights all addresses (code and data definitions) involved. Pressing the
hotkey Ctrl-Shift-S switches synchronization on and off. Hovering over pseudocode
items will display corresponding disassembled code in a hint window. The item that
belongs to the item that is located under the cursor will be highlighted and pointed
to by an arrow.

The plugin requires IDA 7.3.
"""

__author__ = 'https://github.com/patois'

HL_COLOR = 0xAD8044

# -----------------------------------------------------------------------
class idb_hook_t(IDB_Hooks):
    def __init__(self, hxehook):
        self.hxehook = hxehook
        IDB_Hooks.__init__(self)

    def savebase(self):
        self.hxehook._reset_all_colors()
        return 0

# -----------------------------------------------------------------------
class hxe_hook_t(Hexrays_Hooks):
    def __init__(self):
        Hexrays_Hooks.__init__(self)
        self.idbhook = idb_hook_t(self)
        self.idbhook.hook()
        self.pseudocode_instances = {}
        self.n_spaces = 40

    def close_pseudocode(self, vd):
        self._reset_colors(vd.view_idx, ignore_vd=True)
        refresh_idaview_anyway()
        return 0

    def create_hint(self, vd):
        result = self._get_vd_context(vd)
        if result:
            _, _, _, item_ea_list = result

            if len(item_ea_list):
                if vd.get_current_item(USE_MOUSE):
                    cur_item_ea = vd.item.it.ea
                else:
                    cur_item_ea = BADADDR

                lines = []
                for ea in item_ea_list:
                    disasm_line = generate_disasm_line(ea, 0)
                    if disasm_line:
                        addr = "0x%x: " % ea
                        
                        if cur_item_ea == ea:
                            prefix = COLSTR("==> %s" % addr, SCOLOR_INSN)
                        else:
                            prefix = "    " + addr

                        lines.append(prefix+disasm_line)

                lines.append("")
                lines.append(self.n_spaces * "-")
                lines.append("")
                custom_hints = "\n".join(lines)
                # ask decompiler to append default hints
                return (2, custom_hints, len(lines))
        return 0

    def curpos(self, vd):
        self._reset_all_colors()
        self._apply_colors(vd)
        refresh_idaview_anyway()
        return 0

    def refresh_pseudocode(self, vd):
        self._reset_all_colors(ignore_vd=True)
        return 0

    def cleanup(self):
        self._reset_all_colors()
        refresh_idaview_anyway()

        if self.idbhook:
            self.idbhook.unhook()
            self.idbhook = None
        return
 
    def _reset_colors(self, idx, ignore_vd=False):
        v = self.pseudocode_instances[idx]
        if v:
            pseudocode, lineno, color, disasm_lines = v
            if not ignore_vd and pseudocode:
                try:
                    pseudocode[lineno].bgcolor = color
                except: # wtf
                    pass
            for ea, color in disasm_lines:
                set_item_color(ea, color)
        self.pseudocode_instances.pop(idx)
        return

    def _reset_all_colors(self, ignore_vd=False):
        # restore colors
        if self.pseudocode_instances:
            pi = list(self.pseudocode_instances)
            for k in pi:
                self._reset_colors(k, ignore_vd)
            self.pseudocode_instances = {}
        return

    def _apply_colors(self, vd):
        result = self._get_vd_context(vd)
        if result:
            pseudocode, lineno, col, item_ea_list = result
            disasm_lines = [(ea, get_item_color(ea)) for ea in item_ea_list]
            if len(item_ea_list):
                jumpto(item_ea_list[0], -1, UIJMP_IDAVIEW | UIJMP_DONTPUSH)
            self.pseudocode_instances[vd.view_idx] = (pseudocode, lineno, col, disasm_lines)

            if pseudocode:
                try:
                    pseudocode[lineno].bgcolor = HL_COLOR
                except: # wtf
                    pass
            for ea, _ in disasm_lines:
                set_item_color(ea, HL_COLOR)
        return

    def _get_item_indexes(self, line):
        indexes = []
        tag = COLOR_ON + chr(COLOR_ADDR)
        pos = line.find(tag)
        while pos != -1 and len(line[pos+len(tag):]) >= COLOR_ADDR_SIZE:
            addr = line[pos+len(tag):pos+len(tag)+COLOR_ADDR_SIZE]
            idx = int(addr, 16)
            a = ctree_anchor_t()
            a.value = idx
            if a.is_valid_anchor() and a.is_citem_anchor():
                """
                print "a.value %s %d lvar %s citem %s itp %s blkcmt %s" % (
                    a.is_valid_anchor(),
                    a.get_index(),
                    a.is_lvar_anchor(),
                    a.is_citem_anchor(),
                    a.is_itp_anchor(),
                    a.is_blkcmt_anchor())
                """
                indexes.append(a.get_index())
            pos = line.find(tag, pos+len(tag)+COLOR_ADDR_SIZE)
        return indexes

    def _get_vd_context(self, vd):
        if vd:
            lineno = vd.cpos.lnnum
            pseudocode = vd.cfunc.get_pseudocode()

            if pseudocode and lineno != -1:
                try:
                    color = pseudocode[lineno].bgcolor
                    line = pseudocode[lineno].line
                   
                    item_idxs = self._get_item_indexes(line)
                    ea_list = {}
                    for i in item_idxs:
                        try:
                            item = vd.cfunc.treeitems.at(i)
                            if item and item.ea != BADADDR:
                                ea_list[item.ea] = None
                        except:
                            pass
                    return (pseudocode, lineno, color, sorted(ea_list.keys()))
                except:
                    pass
        return None

# -----------------------------------------------------------------------
def is_ida_version(min_ver_required):
    return IDA_SDK_VERSION >= min_ver_required

# -----------------------------------------------------------------------
class Dsync(ida_idaapi.plugin_t):
    comment = ''
    help = ''
    flags = PLUGIN_MOD
    wanted_name = 'dsync'
    wanted_hotkey = 'Ctrl-Shift-S'
    hxehook = None

    def init(self):
        required_ver = 730
        if not is_ida_version(required_ver) or not init_hexrays_plugin():
            msg ("[!] '%s' is inactive (IDA v%d and decompiler required).\n" % (Dsync.wanted_name, required_ver))
            return PLUGIN_SKIP

        msg("[+] '%s' loaded. %s activates/deactivates synchronization.\n" % (Dsync.wanted_name, Dsync.wanted_hotkey))
        return PLUGIN_KEEP

    def run(self, arg):
        if not Dsync.hxehook:
            Dsync.hxehook = hxe_hook_t()
            Dsync.hxehook.hook()
        else:
            Dsync.hxehook.unhook()
            Dsync.hxehook.cleanup()
            Dsync.hxehook = None

        msg("[+] %s is %sabled now.\n" % (Dsync.wanted_name, "en" if Dsync.hxehook else "dis"))

    def term(self):
        msg("[+] %s unloaded.\n" % (Dsync.wanted_name))
        if Dsync.hxehook:
            Dsync.hxehook.unhook()
            Dsync.hxehook.cleanup()
            Dsync.hxehook = None

# -----------------------------------------------------------------------
def PLUGIN_ENTRY():   
    return Dsync()
