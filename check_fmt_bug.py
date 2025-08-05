'''
Author: Niebelungen
IDA Script: A simple IDA script to detect unsafe format arguments in printf-family calls.

This script inspects the format (`fmt`) parameter of functions like printf, snprintf, etc.
A vulnerability exists if `fmt` originates from a variable rather than a compile-time constant.

Parameters:
- addr: Target function addr (e.g., "0x12345")
- idx: 0-based argument index (0=first param)

snprintf(s, 0x100, buf, "AAA"); // no

snprintf(s, 0x100, "%s", "AAA"); // yes

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
        self.risk = 0
        self.idx = idx

    def visit_expr(self, expr):
        if expr.op == idaapi.cot_call and expr.ea == self.target_addr:
            if len(expr.a) > self.idx:
                arg = expr.a[self.idx]
                # print(arg.op)
                if arg.op == idaapi.cot_obj:
                    # fmt arg is a obj 
                    pass
                elif arg.op == idaapi.cot_var:
                    # fmt arg is a var, you need to check it!
                    self.risk = 1
                
        return 0

def find_fmt_bug(target, idx):
    target_ea = target
    if target_ea == idc.BADADDR:
        print(f"[NNNNNNN] Target function '{target}' not found")
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
                print(f"[NNNNNNN] Failed to decompile 0x{caller_ea:X}: {e}")
                continue

        try:
            visitor = CallVisitor(ref, idx)
            visitor.apply_to(cfunc.body, None)
            if visitor.risk == 1:
                print(f"risk: {hex(ref)}")
        except Exception as e:
            continue


if __name__ == '__main__':
    addr = 0x2F1CB0
    arg_idx = 2  # 0-based index
    find_fmt_bug(addr, arg_idx)
    print("Done")