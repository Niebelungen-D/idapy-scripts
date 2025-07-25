# -*- coding: utf-8 -*-
import ida_funcs
import ida_name
import idautils
import ida_ua
import ida_segment
import ida_idaapi
import idc
import ida_allins  # <-- Import the module for instruction constants

def is_readonly_address(addr):
    """
    Checks if a given address is in a read-only segment.
    """
    seg = ida_segment.getseg(addr)
    if not seg:
        return False
    # A segment is considered writable if the SEGPERM_WRITE bit is set.
    is_writable = (seg.perm & ida_segment.SEGPERM_WRITE) != 0
    return not is_writable

def find_snprintf_format_from_variable():
    """
    Finds all calls to snprintf and identifies calls where the format 
    parameter originates from a variable rather than a read-only literal.
    """
    # Find the address of the snprintf function
    snprintf_addr = 0x2F1CB0

    if snprintf_addr == ida_idaapi.BADADDR:
        print("❌ Error: Could not find the 'snprintf' function in the database.")
        return

    print(f"✅ Found 'snprintf' function at: 0x{snprintf_addr:x}")
    print("--- Starting analysis ---")

    # Get all cross-references (calls) to snprintf
    for xref in idautils.XrefsTo(snprintf_addr, 0):
        call_addr = xref.frm
        func = ida_funcs.get_func(call_addr)
        if not func:
            continue

        #print(f"\n[+] Analyzing 'snprintf' call at 0x{call_addr:x}...")

        # For x64, the 3rd argument (format string) is in RDX (System V) or R8 (Microsoft)
        # We will trace back from the call instruction to find the origin of these registers.
        
        format_reg_found = False
        current_addr = call_addr
        
        # Look back a maximum of 20 instructions within the same function
        for _ in range(20):
            current_addr = idc.prev_head(current_addr, func.start_ea)
            
            if current_addr == ida_idaapi.BADADDR or current_addr < func.start_ea:
                break

            insn = ida_ua.insn_t()
            ida_ua.decode_insn(insn, current_addr)

            # This is the corrected line, using ida_allins
            if insn.itype in [ida_allins.NN_mov, ida_allins.NN_lea] and \
               insn.Op1.type == ida_ua.o_reg and (insn.Op1.reg == 2 or insn.Op1.reg == 8): # RDX=2, R8=8
                
                op2 = insn.Op2
                source_addr = -1

                # Case 1: LEA reg, [addr] or MOV reg, offset string
                if op2.type == ida_ua.o_mem or op2.type == ida_ua.o_imm:
                    source_addr = op2.addr if op2.type == ida_ua.o_mem else op2.value
                
                    # Now check if the resolved address is in a writable segment
                    if not is_readonly_address(source_addr):
                        print(f"  🚨 **HIGH RISK** call at 0x{call_addr:x}")
                        print(f"     Instruction: 0x{current_addr:x}: {idc.GetDisasm(current_addr)}")
                        print(f"     Reason: Format string loaded from writable address 0x{source_addr:x}.")
                        format_reg_found = True
                        break
                    else:
                        #print(f"  ✔️ Safe call at 0x{call_addr:x}")
                        #print(f"     Reason: Format string is a read-only literal from 0x{source_addr:x}.")
                        format_reg_found = True
                        break
                
                # Case 2: MOV rdx, rax (or another register)
                elif op2.type == ida_ua.o_reg:
                    print(f"  🤔 Unknown origin at 0x{call_addr:x}")
                    print(f"     Instruction: 0x{current_addr:x}: {idc.GetDisasm(current_addr)}")
                    print(f"     Reason: Format string comes from another register. Manual analysis required.")
                    format_reg_found = True
                    break

        if not format_reg_found:
            print(f"  ⚠️ Warning: Could not determine format string origin for call at 0x{call_addr:x}. Please review manually.")

    print("\n--- Analysis complete ---")

# --- To Run ---
if __name__ == "__main__":
    find_snprintf_format_from_variable()