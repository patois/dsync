from idaapi import *

"""
This plugin for IDA synchronizes Hexrays decompiler views and disassembly views (from
decompiled code to disassembly by default - use the TAB key for synchronizing from
disassembly to decompiled code).

It also highlights all addresses (code and data definitions) involved. Pressing the
hotkey Ctrl-Shift-S switches synchronization on and off.

The plugin was developed for and tested with IDA 7.2.
"""

__author__ = 'Dennis Elser'

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

    def close_pseudocode(self, vd):
        self._reset_colors(vd.view_idx)
        refresh_idaview_anyway()
        return 0

    def create_hint(self, vd):
        ea_list = self._get_item_ea_list(vd)
        count = len(ea_list)
        if count:
            lines = ["0x%x: %s\n" % (ea, generate_disasm_line(ea, 0)) for ea in ea_list]
            postfix = "\n"+len(tag_remove(max(lines, key=len)))*"-"+"\n"
            custom_hints = "".join(lines) + postfix
            # ask decompiler to append default hints
            return (2, custom_hints, custom_hints.count("\n") + 1)

        return 0

    def curpos(self, vd):
        # workaround for a bug in IDA/Decompiler <= 7.2
        vd.refresh_cpos(USE_KEYBOARD)
        self._reset_all_colors()
        self._apply_colors(vd)
        refresh_idaview_anyway()
        return 0

    def cleanup(self):
        self._reset_all_colors()
        refresh_idaview_anyway()

        if self.idbhook:
            self.idbhook.unhook()
            self.idbhook = None
 
    def _reset_colors(self, idx):
        try:
            v = self.pseudocode_instances[idx]
            if len(v) == 2:
                pseudocode, lineno, color = v[0]
                pseudocode[lineno].bgcolor = color
                for ea, color in v[1]:
                    set_item_color(ea, color)
            self.pseudocode_instances.pop(idx)
        except:
            pass

    def _reset_all_colors(self):
        # restore colors
        for k in self.pseudocode_instances.keys():
            self._reset_colors(k)
        self.pseudocode_instances = {}

    def _apply_colors(self, vd):
        lineno = vd.cpos.lnnum
        pseudocode = vd.cfunc.get_pseudocode()
        decomp_line = (pseudocode, lineno, pseudocode[lineno].bgcolor)
        l = self._get_item_ea_list(vd)
        disasm_lines = [(ea, get_item_color(ea)) for ea in l]
        if len(l):
            jumpto(l[0], -1, UIJMP_IDAVIEW | UIJMP_DONTPUSH)
        self.pseudocode_instances[vd.view_idx] = (decomp_line, disasm_lines)

        pseudocode[lineno].bgcolor = HL_COLOR
        for ea, _ in disasm_lines:
            set_item_color(ea, HL_COLOR)

    def _get_item_indexes(self, line):
        indexes = []
        tag = COLOR_ON + chr(COLOR_ADDR)
        pos = line.find(tag)
        while pos != -1 and line[pos+len(tag):] >= COLOR_ADDR_SIZE:
            item_idx = line[pos+len(tag):pos+len(tag)+COLOR_ADDR_SIZE]
            indexes.append(int(item_idx, 16))
            pos = line.find(tag, pos+len(tag)+COLOR_ADDR_SIZE)
        return indexes

    def _get_item_ea_list(self, vd):
        lineno = vd.cpos.lnnum
        line = vd.cfunc.get_pseudocode()[lineno].line
       
        item_idxs = self._get_item_indexes(line)
        ea_list = {}
        for i in item_idxs:
            try:
                item = vd.cfunc.treeitems.at(i)
                if item and item.ea != BADADDR:
                    ea_list[item.ea] = None
            except:
                pass
        return sorted(ea_list.keys())

# -----------------------------------------------------------------------

class Dsync(ida_idaapi.plugin_t):
    flags = 0
    comment = ''
    help = ''
    flags = PLUGIN_MOD | PLUGIN_PROC
    wanted_name = 'Toggle Dsync'
    wanted_hotkey = 'Ctrl-Shift-S'
    hxehook = None

    def init(self):
        return PLUGIN_KEEP if init_hexrays_plugin() else PLUGIN_SKIP

    def run(self, arg):
        if not Dsync.hxehook:
            Dsync.hxehook = hxe_hook_t()
            Dsync.hxehook.hook()
        else:
            Dsync.hxehook.unhook()
            Dsync.hxehook.cleanup()
            Dsync.hxehook = None

    def term(self):
        if Dsync.hxehook:
            Dsync.hxehook.unhook()
            Dsync.hxehook.cleanup()
            Dsync.hxehook = None

# -----------------------------------------------------------------------
def PLUGIN_ENTRY():   
    return Dsync()
