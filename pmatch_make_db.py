# Copyright 2021 National Technology & Engineering Solutions of Sandia, LLC (NTESS). 
# Under the terms of Contract DE-NA0003525 with NTESS, the U.S. Government retains 
# certain rights in this software.

# This script will create a database file in yaml format for function matching.
# This is the precursor to running the pmatch_match_funcs.py
#@category Binalysis
#@keybinding
#@menupath
#@toolbar

import os
import re

from ghidra.program.model.symbol.SourceType import *

import pmatch_utils


def check_string(addr, listing):
    '''check to see if any strings are used at the address'''
    data = getDataAt(addr)
    sym  = getSymbolAt(addr)
    if data:
        data_cmp = data.getBaseDataType().getName().lower()
        if data_cmp in ('string', 'unicode'):
            return data.getValue()
    if sym is not None:
        sym_cmp = str(sym).lower()
        if sym_cmp.startswith("ptr_s_") or sym_cmp.startswith("ptr_u_"):
            struct = listing.getDataAt(sym.getAddress())
            if listing.getDataAt(struct.getValue()):
                string = str(listing.getDataAt(struct.getValue()))[4:-1]
            else:
                string = str(sym)[6:]
            return string
    return None


def get_address_list(listing, function):
    '''return the ghidra address list'''
    addr_list = []
    pattern = "0x[a-fA-F0-9]{6,}"
    inst_itr = listing.getInstructions(function.getBody(), True)
    while inst_itr.hasNext():
        inst = inst_itr.next()
        addr = re.findall(pattern,inst.toString())
        if addr:
            addr_list.extend(addr)
    return addr_list


def get_used_strings(listing, function):
    '''Get all used strings in the function'''
    address_list = get_address_list(listing, function)
    used_strings = []
    if address_list:
        for address in address_list:
            name = check_string(toAddr(address), listing)
            if name is not None:
                if len(name) < 5:
                    continue
                name = re.sub(r'[^a-zA-Z0-9_.]+','',name[:50])
                used_strings.append(name)
    return used_strings


def save_functions_pcode(monitor, listing, address_factory):
    '''save all the pcode and strings/constants to yaml file'''
    func_mgr = currentProgram.getFunctionManager()
    monitor.initialize(func_mgr.getFunctionCount())
    filename = askString("Output File Name",
        "Enter Full Path for where to save functions pcode into db(yaml format)")
    db = {}
    function = getFirstFunction()

    while function is not None:
        monitor.checkCanceled()
        monitor.incrementProgress(1)
        name = function.getName()
        pcode, constants = pmatch_utils.get_pcode_ops(function, address_factory)
        called_pcode = []
        called_constants = []
        called_funcs = function.getCalledFunctions(monitor)

        if called_funcs:
            for func in called_funcs:
                cf_pcode, cf_constants = pmatch_utils.get_pcode_ops(func, address_factory)
                if cf_pcode:
                    called_pcode.extend(cf_pcode)
                if cf_constants:
                    called_constants.extend(cf_constants)

        num_vars = len(function.getAllVariables())
        used_strs = get_used_strings(listing, function)

        if len(pcode) > 0 or len(called_pcode) > 0:
            start_addr = int(function.getEntryPoint().toString(), 16)
            end_addr = int(function.getEntryPoint().toString(), 16) + function.getBody().getNumAddresses()
            function_len = (end_addr - start_addr)#get the number of bytes
            if function_len <= 1:
                function_len = 80
            try:
                function_bytes = str(getBytes(function.getEntryPoint(), function_len))
            except:
                pass
            db[name] = {'name':name, 'pcode': "K"+";"+''.join(pcode), \
                        'called_pcode': ''.join(called_pcode), \
                        'file': currentProgram.getName(), \
                        'constants': ''.join(constants), \
                        'called_constants': ''.join(called_constants), \
                        'param_count': function.getParameterCount(), \
                        'num_vars': num_vars, \
                        'used_strs': ''.join(used_strs), \
                        'bytes': function_bytes}

        function = getFunctionAfter(function)

    if not os.path.isfile(filename):
        with open(filename, "w") as outfile:
            outfile.write("function_pcode:\n")

    with open(filename, "a") as outfile:
        for func in db.items():
            func = func[1]
            outfile.write("  - name: %s\n" % func['name'])
            outfile.write("    pcode: %s\n" % func['pcode'])
            outfile.write("    called_pcode: %s\n" % func['called_pcode'])
            outfile.write("    file: %s\n" % func['file'])
            outfile.write("    constants: %s\n" % func['constants'])
            outfile.write("    called_constants: %s\n" % func['called_constants'])
            outfile.write("    param_count: %s\n" % func['param_count'])
            outfile.write("    num_vars: %s\n" % func['num_vars'])
            outfile.write("    used_strs: %s\n" % func['used_strs'])
            outfile.write("    bytes: %s\n" % func['bytes'])
        print("Number of Functions saved to Database: %s\n" % len(db))

if __name__ == '__main__':
    address_factory = currentProgram.getAddressFactory()
    listing = currentProgram.getListing()
    save_functions_pcode(monitor, listing, address_factory)
