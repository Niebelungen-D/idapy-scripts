'''
Author: Niebelungen
IDA Script: Rename Functions by Call Argument

Automatically renames functions based on the string value of a specified 
argument in their calls to a target function. Analyzes cross-references, 
extracts strings using multiple encodings (UTF-8/GBK/Latin-1), and handles 
name conflicts with numeric suffixes.

Parameters:
- target: Target function name (e.g., "sub_12345")
- idx: 0-based argument index (0=first param)

sub_xxx() {
    // ... some code
    sub_12345("[%s:%d] Failed to xxxxxx", "foo", 117);
}

rename sub_xxx() to foo/foo_i

'''

import idc
import idaapi
import idautils

def decode_string(addr):
    s = idc.get_strlit_contents(addr, -1, idc.STRTYPE_C)
    if not s:
        return None
    try:
        return s.decode('utf-8')
    except UnicodeDecodeError:
        try:
            return s.decode('gbk')
        except UnicodeDecodeError:
            return s.decode('latin-1', errors='replace')

class CallVisitor(idaapi.ctree_visitor_t):
    def __init__(self, target_addr, idx):
        idaapi.ctree_visitor_t.__init__(self, idaapi.CV_FAST)
        self.target_addr = target_addr
        self.new_name = []
        self.idx = idx

    def visit_expr(self, expr):
        if expr.op == idaapi.cot_call and expr.ea == self.target_addr:
            if len(expr.a) > self.idx:
                arg = expr.a[self.idx]
                if arg.op == idaapi.cot_obj:
                    addr = arg.obj_ea
                    s = decode_string(addr)
                    if s:
                        self.new_name.append(s)
        return 0

def find_and_rename(target, idx):
    target_ea = idc.get_name_ea_simple(target)
    if target_ea == idc.BADADDR:
        print(f"[RENAME] Target function '{target}' not found")
        return
    target_name = idc.get_name(target_ea)
    cfunc_cache = {}

    for ref in idautils.CodeRefsTo(target_ea, 0):
        caller_func = idaapi.get_func(ref)
        if not caller_func:
            continue
        caller_ea = caller_func.start_ea

        if caller_ea in cfunc_cache:
            cfunc = cfunc_cache[caller_ea]
        else:
            try:
                cfunc = idaapi.decompile(caller_func)
                cfunc_cache[caller_ea] = cfunc
            except Exception as e:
                print(f"[RENAME] Failed to decompile 0x{caller_ea:X}: {e}")
                continue
                
        visitor = CallVisitor(ref, idx)
        visitor.apply_to(cfunc.body, None)
        if len(visitor.new_name) == 1:
            original_name = visitor.new_name[0]
            new_name = original_name
            counter = 0
            while not idc.set_name(caller_ea, new_name, idc.SN_NOWARN):
                counter += 1
                new_name = f"{original_name}_{counter:x}"
            print(f"[RENAME] Renamed 0x{caller_ea:X} from {caller_func.name} to {new_name}")
        elif len(visitor.new_name) > 1:
            print(f"[RENAME] Multiple names found for 0x{caller_ea:X} in {caller_func.name}: {visitor.new_name}")
        else:
            print(f"[RENAME] Failed at 0x{ref:X} (func {caller_func.name}): "
                  f"Could not find {idx}th arg of {target_name}")

if __name__ == '__main__':
    function_name = "sub_25521A0"
    arg_idx = 1  # 0-based index
    find_and_rename(function_name, arg_idx)