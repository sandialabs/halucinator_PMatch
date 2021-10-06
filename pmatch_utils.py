# Copyright 2021 National Technology & Engineering Solutions of Sandia, LLC (NTESS). 
# Under the terms of Contract DE-NA0003525 with NTESS, the U.S. Government retains 
# certain rights in this software.

'''Utilities used for pmatch_make_db and pmatch_match_funcs'''
import signal
import sys
from contextlib import contextmanager

import ghidra
import ghidra.app.decompiler as decompiler
import ghidra.program.model.pcode.PcodeOp as PCODE_ENUMS
import java
import yaml
from __main__ import *

SEC_TO_TIMEOUT = 10

@contextmanager
def time_limit(seconds):
    def signal_handler(signum, frame):
        raise TimeoutException("Timed out!")
    signal.signal(signal.SIGALRM, signal_handler)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)


def read_yaml(filename):
    with open(filename, 'r') as stream:
        try:
            db = yaml.safe_load(stream)
            return db
        except yaml.YAMLError as exc:
            print(exc)
            sys.exit()


def get_func_end_addr(function, address_factory=None):
    if function is None:
        return None

    if address_factory is None:
        address_factory =  currentProgram.getAddressFactory()
    n_func = getFunctionAfter(function)
    end_addr = get_address(int(function.getEntryPoint().toString(), 16) +
                    function.getBody().getNumAddresses(), currentProgram)

    if n_func:
        poss_end = get_address( (int(n_func.getEntryPoint().toString(), 16) - 4), \
                    currentProgram)
        end_addr = end_addr if int(end_addr.toString(), 16) > \
                    int(poss_end.toString(),16) else poss_end
    return end_addr


def get_funcs(currentProgram, monitor):
    func_mgr = currentProgram.getFunctionManager()
    monitor.initialize(func_mgr.getFunctionCount())
    to_ret = []
    function = getFirstFunction()
    while function is not None:
        monitor.checkCanceled()
        monitor.incrementProgress(1)
        to_ret.append(function)
        function = getFunctionAfter(function)
    return to_ret


def get_address(address=None, program=None):
    """
    Take an integer/string address and turn it into a ghidra address
    If not address provided, get the current address
    """
    if address is None:
        if program is not None:
            if program != getState().getCurrentProgram():
                raise Exception(
                    "Using current address, but have specified not current program")
        return getState().getCurrentAddress()

    if isinstance(address, ghidra.program.model.address.GenericAddress):
        # already done, no need to fix
        return address

    if program is None:
        program = getState().getCurrentProgram()

    if not isinstance(address, str) and not isinstance(address, unicode):
        address = hex(address)
        if address.endswith("L"):
            address = address[:-1]

    return program.getAddressFactory().getAddress(address)


#############################################################################
################################PCODE STUFF##################################
#############################################################################
def get_pcode(function, address_factory):
    '''get the pcode from a function'''
    if not function:
        return None

    pcode = []
    try:
        start_addr = function.getEntryPoint()
        end_addr = get_func_end_addr(function, address_factory)
        end_addr_str = str(hex(int(end_addr.toString(), 16))).rstrip("L")
        instr = getInstructionContaining(start_addr)
    except:
        return pcode

    while True:
        if not instr or int(instr.getAddress().toString(), 16) > int(end_addr_str,16):
            break
        pcode.extend([op for op in instr.getPcode()])# if not op.isDead()
        instr = instr.getNext()
    return pcode


def get_pcode_ops(function, address_factory):
    '''return just the pcode ops from function'''
    if not function:
        return None
    pcode = get_pcode(function, address_factory)
    pcode_ops = []
    constants = []

    for code in pcode:
        pcode_ops.append(str(code.getOpcode()))
        if code.getOpcode() == PCODE_ENUMS.COPY:
            for invar in code.getInputs():
                if invar.isConstant():
                    constants.append(invar.toString())
    return pcode_ops, constants
#############################################################################
############################END PCODE STUFF##################################
#############################################################################


#############################################################################
################NOT USED EXPERIMENTAL PCODE STUFF############################
#############################################################################
def get_constant_fold_pcode(function, address_factory, output_path):
    '''Returns pcode as well as if constant folding occured
    This requires the GhidraPAL extension to be installed to work correctly.'''
    try:
        # GhidraPAL extension: https://github.com/RolfRolles/GhidraPAL
        import ghidra.pal.absint.tvl.TVLAbstractGhidraStateFactory as TVLAbstractGhidraStateFactory
        import ghidra.pal.absint.tvl.TVLAnalysisOutputOptions as TVLAnalysisOutputOptions
        import ghidra.pal.absint.tvl.TVLHighLevelInterface as TVLHighLevelInterface
        rand_vars = java.util.Arrays.asList("sp")
        states = TVLAbstractGhidraStateFactory.MakeInputStatesRandInit(\
            currentProgram, 6, rand_vars, None)
        default_addr_space = currentProgram.getAddressFactory().getDefaultAddressSpace()
        start_entry_addr = function.getEntryPoint()
        end_entry_addr = int(function.getEntryPoint().toString(), 16) + \
            function.getBody().getNumAddresses()
        end_entry_addr = default_addr_space.getAddress(end_entry_addr)
        tvl_pcode = TVLHighLevelInterface.AnalyzeRange(
            currentProgram,
            start_entry_addr,
            end_entry_addr,
            True,
            states,
            TVLAnalysisOutputOptions.PcodeComments)
        pcode = []
        for code in tvl_pcode:
            pcode.append(code.y)
        return pcode, True
    except:
        return get_pcode(function, address_factory), False

def get_cfold_pcode(pcode):
    '''still needs implemented'''
    # I have a list of pcode operations coming in. Need to do a constant folding
    # Need to get a CFG or BB model
    # Do a symbolic exe using lattice theory, start at beginning going forward
    # Worklist Algorithm:
    #   while worklist not empty, do:
    #     Process next edge from worklist
    #     symbolic evaluate target node using input state vecotr
    #     if target node is assignment, propagate vin[eval(e)/x] to outptu edge
    #     if target node is branch
    #     if eval(e) is true or false, propagate vin to appropriate output edge
    #     else propagate vin along both output edges
    #     if target node is merge, propagate join(all vin) to output edge
    #     if any output edge state vector has changed, add it to worklist
    # Merge when needed
    return pcode


def get_liveness_pcode(pcode):
    '''do liveness analysis on pcode'''
    pcode_liveness = []
    live_vars = []
    for code in reversed(pcode):
        vn_out = pcode.getOutput()
        vn_ins = pcode.getInputs()

        while vn_out in live_vars:
            live_vars.remove(vn_out)

        live_vars.extend(vn_ins)
        live_vars = list(set(live_vars))
        pcode_liveness.append((code,live_vars))
    #Reverse the order of pcode_liveness to be in the right order now.
    pcode_liveness.reverse()
    return pcode_liveness #Returns a list of tuples, the pcode and list of live vars


def get_avail_expr(pcode):
    '''do available expression analysis on pcode'''
    pcode_avail_expr = []
    avail_expr = set()
    for code in pcode:
        pcode_avail_expr.append((code, list(avail_expr)))
        vn_out = code.getOutput()
        vn_ins = code.getInputs()
        if vn_out not in vn_ins:
            #add to avail expr
            avail_expr.add(code)
        for expr in avail_expr:
            expr_in_vars = expr.getInputs()
            if vn_out in expr_in_vars:
                avail_expr.remove(expr)
    return pcode_avail_expr


def get_cse_pcode(pcode):
    '''do common subexpression elimination analysis on pcode'''
    did_cfe = False
    opt_pcode = []
    pcode_avail_expr = get_avail_expr(pcode)
    for code, avail_expr in pcode_avail_expr:
        if code not in avail_expr:
            opt_pcode.append(code)
        else:
            did_cfe = True
            print("Optimizing out %s!" % code.toString())
    return opt_pcode, did_cfe


def get_optimized_pcode(function, address_factory, output_path):
    '''get optimized pcode, trying to remove some of the pcode'''
    if not function:
        return None
    const_fold_pcode, c_fold = get_constant_fold_pcode(function, address_factory, output_path)
    cse_pcode, did_cfe = get_cse_pcode(const_fold_pcode)
    optimized = False
    if did_cfe or c_fold:
        optimized = True
    return cse_pcode, optimized


def get_optimized_pcode_ops(function, address_factory, output_path):
    '''get pcode ops after optimization'''
    if not function:
        return None
    pcode, optimized = get_optimized_pcode(function, address_factory, output_path)
    pcode_ops = []
    for code in pcode:
        pcode_ops.append(str(code.getOpcode()))
        #Optional depending on the firmwares if we want these next 4 lines
        # if code.getOpcode() == PCODE_ENUMS.COPY:
        #   for invar in code.getInputs():
        #     if invar.isConstant():
        #       pcode_ops.append(invar.toString())
    return pcode_ops, optimized


def get_high_pcode(function):
    '''get the pcode from a high function'''
    high_pcode = []
    interface = decompiler.DecompInterface() #interface for decompiler
    if not interface.openProgram(currentProgram):
        #if we can't initialize correctly, don't run anymore
        print("Decompiler Unable to initialize: %s" % interface.getLastMessage())
        sys.exit()
    interface.setSimplificationStyle("normalize") #normalize the decompliation output
    dec_res = interface.decompileFunction(function, SEC_TO_TIMEOUT, monitor)
    high_func = dec_res.getHighFunction()
    if high_func:
        opiter = high_func.getPcodeOps()
        while opiter.hasNext():
            monitor.checkCanceled()
            op = opiter.next()
            high_pcode.append(op)
    return high_pcode

#############################################################################
##################END EXPERIMENTAL PCODE STUFF###############################
#############################################################################
