# Copyright 2021 National Technology & Engineering Solutions of Sandia, LLC (NTESS). 
# Under the terms of Contract DE-NA0003525 with NTESS, the U.S. Government retains 
# certain rights in this software.

#This script will read yaml database file, then do similarity matching for matching functions
# Must have yaml file in the right format. Run pmatch_make_db.py to create right format db
#@category Binalysis
#@keybinding
#@menupath
#@toolbar
import difflib
import operator
import os
import re
from os.path import expanduser

import ghidra
from ghidra.program.model.symbol.SourceType import *

import pmatch_utils

_TIME_LIM_ = 30
MIN_KEY_LEN = 0 #THIS CAN BE A BIG PART OF ACCURACY!!!
                #Depending on the db matching to, 0 can be just fine, other times not
                #Change to 100 and virtually no False Positives
                #May also mean that not much True Positives. 10 gets rid of stubs,
                #30-100 gets better matching with less False Positives, but needs tweaking
                #depending on the database and library(ies) you are matching to
IMPORTED = ghidra.program.model.symbol.SourceType.IMPORTED
DO_SIMILARITY_MATCH = False
RATIO_LIMIT = 0.98 #Tweak this if DO_SIMILARITY_MATCH is True
                    #Usually somewhere above .97 is good, the higher you go the less
RENAME = True
COMPUTE_STATS = False
COMPUTE_COVERAGE = True


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
    addr_list = get_address_list(listing, function)
    used_strings = []
    if addr_list:
        for address in addr_list:
            name = check_string(toAddr(address), listing)
            if name is not None:
                if len(name) < 5:
                    continue
                name = re.sub(r'[^a-zA-Z0-9_.]+','',name[:50])
                used_strings.append(name)
    return used_strings


def create_db(filename, monitor):
    '''take the yaml db file, and create hashes to match against'''
    db = {}
    bytes_db = {}
    db_collisions = set()
    print("Reading input yaml into raw db before processing, this takes the longest...")
    raw_db = pmatch_utils.read_yaml(filename)
    duplicates = set()
    db_names = set()
    db_byte_names = set()
    num_dups = 0
    short_key = 0
    monitor.initialize(len(raw_db['function_pcode']))
    for func in raw_db['function_pcode']:
        monitor.checkCanceled()
        monitor.incrementProgress(1)
        db_names.add(func['name'])
        db_byte_names.add(func['name'])
        bytes = func['bytes']
        bytes_db[bytes] = {'name': func['name'],
                            'pcode': func['pcode'],
                            'called_pcode': func['called_pcode'],
                            'file': func['file'],
                            'constants': func['constants'],
                            'called_constants': func['called_constants'],
                            'param_count': func['param_count'],
                            'num_vars': func['num_vars'],
                            'used_strs': func['used_strs'],
                            'extended': False,
                            'bytes': func['bytes']} #func['name']

        extended = False
        pcode = func['pcode']
        called_pcode = str(func['called_pcode'])
        used_strs = func['used_strs']
        key = pcode
        if func['constants']:
            key += func['constants']
        if used_strs:
            key += used_strs
        if key in db:
            duplicates.add(key)
            num_dups += 1
        else:
            if len(pcode.split(";")[1]) > MIN_KEY_LEN:
                db[key] = {'name': func['name'],
                            'pcode': pcode,
                            'called_pcode': func['called_pcode'],
                            'file': func['file'],
                            'constants': func['constants'],
                            'called_constants': func['called_constants'],
                            'param_count': func['param_count'],
                            'num_vars': func['num_vars'],
                            'used_strs': func['used_strs'],
                            'extended': extended,
                            'bytes': func['bytes']}
        if key in db:
            item = db[key]
            if item['name'] == func['name'] and \
                        item['pcode'] == func['pcode'] and \
                        item['called_pcode'] == func['called_pcode']:
                continue
            db_collisions.add(key)
            num_dups += 1
            if key not in duplicates: #update existing entry in db
                duplicates.add(key)
            if not item['extended']:
                if called_pcode:
                    new_pcode = key + called_pcode
                if item['called_constants']:
                    new_pcode += item['called_constants']
                new_pcode += str(item['param_count']) + str(item['num_vars'])
                extended = True
                if len(new_pcode.split(";")[1]) > MIN_KEY_LEN:
                    db[new_pcode] = {'name': item['name'],
                                    'pcode': new_pcode,
                                    'called_pcode': called_pcode,
                                    'file': item['file'],
                                    'constants': item['constants'],
                                    'called_constants': item['called_constants'],
                                    'param_count': item['param_count'],
                                    'num_vars': item['num_vars'],
                                    'used_strs': item['used_strs'],
                                    'extended': extended,
                                    'bytes': func['bytes']}
                else:
                    short_key += 1
        else:
            if len(pcode.split(";")[1]) > MIN_KEY_LEN:
                db[key] = {'name': func['name'],
                            'pcode': pcode,
                            'called_pcode': func['called_pcode'],
                            'file': func['file'],
                            'constants': func['constants'],
                            'called_constants': func['called_constants'],
                            'param_count': func['param_count'],
                            'num_vars': func['num_vars'],
                            'used_strs': func['used_strs'],
                            'extended': extended,
                            'bytes': func['bytes']}
            else:
                short_key += 1
    print("Number of duplicates in DB: %d, colliding on %d different hashes"
            % (num_dups, len(duplicates)))
    print("Number of DB with too short hashes: %d" % short_key)
    for k in duplicates: #delete duplicates first
        db.pop(k, None)
    print("Orig DB len: %s\nSaved DB len: %s\n"
                    % (len(db_names), len(db)))
    return db, db_collisions, bytes_db


def get_similarity_ratio(a, b):
    '''does edit distance between 2 strings'''
    try:
        with pmatch_utils.time_limit(_TIME_LIM_):
            #https://docs.python.org/2/library/difflib.html
            s = difflib.SequenceMatcher(None, a, b)
            # return s.ratio() # Better quality
            return s.quick_ratio() #much faster
    except:
        return 0.0


def rename_function(function, name):
    '''rename a function within Ghidra'''
    cur_func_name = function.getName()
    if function and cur_func_name != name:
        comment = '*'*80 + "\n* "
        if not cur_func_name.startswith("FUN_") and not cur_func_name.startswith("thunk"):
            print("CONFLICT: CurrentFunctionName: %s\t FunctionName: %s" % (cur_func_name, name))
            comment += "CONFLICTING RENAMING!!!!!!!!!!!!!!\n" + '*'*80
            createBookmark(function.getEntryPoint(),
                "LIBMATCH ERROR",
                "FIDB and LIBMATCH disagree on naming of function. Previous Name: %s, New Name: %s"
                % (cur_func_name,name))
        comment += "\n* Previous Comment (if any):\n"
        if function.getComment():
            comment += function.getComment()
        comment += "\n" + '*'*80 + "\n* Function Renamed using pmatch_match_funcs.py script*\n"
        try:
            function.setName(name, ghidra.program.model.symbol.SourceType.USER_DEFINED)
        except:
            print("Could not set the function name for %s:%s-%s" %
                (function.getEntryPoint(), cur_func_name, name))
            return 0 #Didn't actually rename the function, even though we tried.
        try:
            function.setComment(comment)
        except:
            print("Could not set the function name for %s:%s-%s : new comment: %s"
                % (function.getEntryPoint(), cur_func_name, name, comment))
        return 1 #We actually renamed the function
    return 0 #didn't actually rename the function


def match_pcode_funcs(monitor, listing, address_factory, in_filename):
    '''For each function, create pcode entry and try to match against db'''
    output_path = expanduser("~") + os.sep + "ghidra_outputs" + os.sep + "ghidra-debug.txt"
    func_mgr = currentProgram.getFunctionManager()
    matches = {}
    good_count = 0
    bad_count = 0
    used_names =  set()
    names_dict = {}
    duplicates = set()
    print("Reading input yaml file and creating DB. May take a while...")
    db, db_collisions, bytes_db = create_db(in_filename, monitor)
    monitor.initialize(func_mgr.getFunctionCount())
    print("Finished reading input db, now matching...")
    function = getFirstFunction()
    while function is not None:
        monitor.checkCanceled()
        monitor.incrementProgress(1)
        bytes_match = False
        name = function.getName()

        start_addr = int(function.getEntryPoint().toString(), 16)
        end_addr = int(function.getEntryPoint().toString(), 16) + function.getBody().getNumAddresses()
        function_len = (end_addr - start_addr)#get the number of bytes
        if function_len <= 1:
            function_len = 80
        function_bytes = str(getBytes(function.getEntryPoint(), function_len))

        if function_bytes in bytes_db:
            match = bytes_db.get(function_bytes, None)
            hash_key = function_bytes
            bytes_match = True
        else:
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
            used_strs = get_used_strings(listing, function)
            if not (len(pcode) > 0 or len(called_pcode) > 0):
                function = getFunctionAfter(function)
                continue
            hash_key = "K" + ";" + ''.join(pcode)
            if constants:
                hash_key += ''.join(constants)
            if used_strs:
                hash_key += ''.join(used_strs)

            if hash_key in db_collisions: #Most likely conflicts, need to lengthen!!!
                called_funcs = function.getCalledFunctions(monitor)
                called_constants = []
                #Lengthen with stuff from functions called
                if called_funcs:
                    for func in called_funcs:
                        cf_pcode, cf_constants = pmatch_utils.get_pcode_ops(function, address_factory)
                        cf_pcode = str(''.join(cf_pcode))
                        if cf_constants:
                            called_constants.extend(cf_constants)
                        if cf_pcode:
                            hash_key += cf_pcode
                    if called_constants:
                        hash_key += ''.join(called_constants)
                    hash_key += str(function.getParameterCount()) + str(len(function.getAllVariables()))
                else:
                    function = getFunctionAfter(function)
                    continue
            #first test if there is exact match, uses hash
            match = db.get(hash_key, None)

        options = {}
        if match: #either an exact match with bytes or pcode
            options[name + "---" + match['name']] = (name, match['name'], 1.0, match)
        elif DO_SIMILARITY_MATCH: #Takes a long time, tweek the RATIO_LIMIT for expected outcomes
            for func in db.items():
                db_key = func[0]
                s_ratio = get_similarity_ratio(hash_key, db_key)
                if s_ratio >= RATIO_LIMIT:
                    func = func[1]
                    options[name+"---"+func['name']] = (name, func['name'], s_ratio, func)
        if options: #only match to highest scoring function
            max_match = options[max(options.iteritems(), key=operator.itemgetter(1))[0]]
            if max_match[1] in used_names and not bytes_match:
                duplicates.add(int(function.getEntryPoint().toString(), 16))
                if max_match[2] == 1.0:
                    duplicates.add(names_dict[max_match[1]])
            else:
                matches[int(function.getEntryPoint().toString(), 16)] = max_match
                used_names.add(max_match[1])
                names_dict[max_match[1]] = int(function.getEntryPoint().toString(), 16)
                if max_match[2] != 1.0:
                    print("GUESSED! %s: %s with ratio: %s at address %s" %(name, max_match[1], \
                                max_match[2], function.getEntryPoint().toString()))
        function = getFunctionAfter(function)
    for element in duplicates:
        matches.pop(element,None)
    #This is just to get stats for good vs bad
    if COMPUTE_STATS:
        for element in matches.items():
            function = getFunctionContaining(pmatch_utils.get_address(element[0], currentProgram))
            function_name = function.getName()
            if (function_name == element[1][1]) or \
                    function_name in element[1][1] or \
                    element[1] in function_name:
                good_count += 1
            elif not (function_name.startswith("FUN_") or \
                    function_name.startswith("thunk_")):
                bad_count += 1
                print("Matched: %s, should be: %s" %(element[1][1], function_name))
        print("Len of duplicates: %s" %len(duplicates))
        print("Num good: %d" % good_count)
        print("Num bad: %d" % bad_count)
    if COMPUTE_COVERAGE:
        #get the total number of bytes in the binary, then subtract out the matches number of bytes.
        max_addr = int(currentProgram.getMaxAddress().toString(), 16)
        min_addr = int(currentProgram.getMinAddress().toString(), 16)
        cumulator_prog_bytes = (max_addr - min_addr)
        const_num_prog_bytes = cumulator_prog_bytes
        for element in matches.items():
            num_bytes = len(element[1][3]['bytes'])
            cumulator_prog_bytes -= num_bytes
        if cumulator_prog_bytes < 0:
            cumulator_prog_bytes = 0
        print("%f of the binary is matched" % float(float(const_num_prog_bytes-cumulator_prog_bytes)/float(const_num_prog_bytes)))
    print("Finished matching!")
    return matches, db


def print_funcs(monitor, matches, db, outfilename):
    '''print the functions we match out to yaml file'''
    functions = pmatch_utils.get_funcs(currentProgram, monitor)
    named_funcs = 0
    num_conflicts = 0
    fidb_only_funcs = 0
    pcode_only_funcs = 0
    with open(outfilename, "w") as outfile:
        outfile.write("architecture: %s\n" % currentProgram.getLanguageID())
        outfile.write("base_address: %s\n" % int(currentProgram.getImageBase().toString(), 16))
        outfile.write("symbols:\n")
        for entry in sorted(matches.items()):
            hex_start_addr = str(hex(entry[0])).rstrip("L")
            outfile.write("  %s: %s\n" % (hex_start_addr,entry[1]))
            # outfile.write("  %s: %s\n" % (entry[0],entry[1]))
        for function in functions:
            name = function.getName()
            startAddr = int(function.getEntryPoint().toString(), 16) + 1
            if not str(name).startswith("FUN_") and \
                            not str(name).startswith("thunk"):
                named_funcs += 1
                pcode, constants = pmatch_utils.get_pcode_ops(function, address_factory)
                pcode = str(''.join(pcode))
                if len(pcode) < MIN_KEY_LEN:
                    print("Possible False Positive from FIDB: \
                        %s : %s : pcode len: %s" % (startAddr, name, len(pcode)))
                    continue
                hex_start_addr = str(hex(startAddr)).rstrip("L")
                if startAddr in matches:
                    if (matches[startAddr] not in name and name not in matches[startAddr]):
                        num_conflicts += 1
                        outfile.write("FIX ME, FIDB AND LIBMATCH DISAGREE:  %s: %s\n"
                            % (hex_start_addr,name))
                else:
                    fidb_only_funcs += 1
            if startAddr in matches and RENAME:
                # rename functions in Ghidra, do it after we write functions
                pcode_only_funcs += rename_function(function, matches[startAddr])

    print("Total of %s functions." % len(functions))
    print("Of those, %s functions are named." % (named_funcs + pcode_only_funcs))
    print("PCode-LibMatch matched on %s functions." % len(matches))
    print("Of those, %s were not already named" % pcode_only_funcs)
    print("There were %s other functions named" % named_funcs)
    print("Existing Names and PCode-LibMatch disagreed on %s function names" \
        % num_conflicts)
    print("%s functions matched previously that PCode-LibMatch could not match" \
        % fidb_only_funcs)

if __name__ == '__main__':
    in_filename = askString("Input File Name",
        "Enter Full Path for file with pcode db(yaml format, obtained from pmatch_make_db.py)")
    outfilename = askString("Function Output File Name",
        "Enter Full Path for where to save function addr and names to (yaml format)")
    setAnalysisOption(currentProgram, "Function ID", "true") #This will use fidb first
    address_factory = currentProgram.getAddressFactory()
    listing = currentProgram.getListing()
    matches, db = match_pcode_funcs(monitor, listing, address_factory, in_filename)
    print_funcs(monitor, matches, db, outfilename)
