<!-- Copyright 2021 National Technology & Engineering Solutions of Sandia, LLC (NTESS). 
Under the terms of Contract DE-NA0003525 with NTESS, the U.S. Government retains 
certain rights in this software. -->

# About
This project was developed to try to do fast function matching inside Ghidra, reusing Ghidra's PCode to create hashes/databases and perform function matching against the PCode rather than bytes or strict control flow. The hope is that functions will match even if they have been moved, use Address Space Layout Randomization, and when absolute addresses are used in the code. It is possible (and recommended) to do a traditional direct hash matching first, then with left-overs do this matching.

# Usage:
Add the folder to your Ghidra scripts directory in Ghidra, then run the script.


# Requires:
(For ease of readability, ```alias jython='java -jar $GHIDRA_HOME/Ghidra/Features/Python/lib/jython-standalone-2.7.2.jar'``` )
`export GHIDRA_VERSION=ghidra_10.0.2_PUBLIC`
`export GHIDRA_HOME=$HOME/Programs/$GHIDRA_VERSION`

## YAML
`jython -m pip install pyyaml`
If this fails, try:
`jython -m easy_install pyyaml` 
If this also fails, download pyyaml and cd to the directory
`jython setup.py --without-libyaml install`


# Optional Setup, but recommended for more matches:
## First get Function ID Enabled in Ghidra


## Import the existing FIDBs.
  In the repo under `fidb/` there is a folder with a bunch of fidb built by others and the arm-none-eabi-libmatch-mbed.fidb that I made from the `libmatch_tests/` folder with objects. You can reuse this or if you want to play with making fidb, look at the blog `https://blog.threatrack.de/2019/09/20/ghidra-fid-generator/` with the corresponding github repository.

## Build a PCODE database from object files
  This is similar to making an fidb, but you can do it from an open binary and running the script:
  `pmatch_make_db.py` I do a batch building instead using the ghidra headless, you can do it as below: (The file is auto saved to ~/ghidra_outputs/func_pcode_db.yaml by default)

  `$GHIDRA_HOME/$GHIDRA_VERSION/support/analyzeHeadless <path_to_ghidra_project> <ghidra_project_name> -scriptPath <path_to_this_repo>/ -postScript pmatch_make_db.py -import <path_to_this_repo>/libmatch_tests/arm-none-eabi/libmbed-cortexm3/*.o -recursive `

  `$GHIDRA_HOME/$GHIDRA_VERSION/support/analyzeHeadless <path_to_ghidra_project> <ghidra_project_name> -scriptPath <path_to_this_repo>/ -postScript pmatch_make_db.py -import <path_to_this_repo>/libmatch_tests/arm-none-eabi/stm32hal_cortexm3/*.o -recursive `

## Run the Function ID analysis
  You need to run the default analysis after you import a binary and look at it. In the default analysis, if you have enabled the Function ID stuff, you should see one of the options for the default analysis as Function ID. Make sure it is checked. If you want more matches or to variate the accuracy of the fidb portion of matching, you can click on the Function ID and change the parameters, something like Instruction count threshold to 1, and the multiple match threshold to 100.

# Using the PMATCH
# Run the function matching script:
  Add the `<path_to_this_repo>/` to the script directories, then you should be able to run `pmatch_match_funcs.py`. If you want to do headless, you can do:

  `$GHIDRA_HOME/$GHIDRA_VERSION/support/analyzeHeadless <path_to_ghidra_project> <ghidra_project_name> -scriptPath <path_to_this_repo>/ -postScript pmatch_match_funcs.py ~/ghidra_outputs/func_pcode_db.yaml <path_to_where_you_want_the_output>/outputMatches.yaml -import <path_to_binary>/example.bin`
  (change ~/ghidra_outputs/func_pcode_db.yaml above if needed. )


# Example commands
(replace `someUser`, `someFolder`, and the path to this repo - right now assumes it is at `/home/someUser/PMatch`. Assuming Ghidra project name is `PcodeDB`)

## Building the pcode db:
  `$GHIDRA_HOME/support/analyzeHeadless /home/someUser/someFolder PcodeDB -scriptPath /home/someUser/PMatch/ -postScript pmatch_make_db.py /home/someUser/ghidra_outputs/func_pcode_db.yaml -import /home/someUser/PMatch/libmatch_tests/objects/arm-none-eabi/libmbed-cortexm3/*.o -recursive `

## Open the project and run the Function ID analysis now

## Run the matching in headless mode:
  `/usr/bin/time -v $GHIDRA_HOME/support/analyzeHeadless /home/someUser/someFolder PcodeDB -scriptPath /home/someUser/PMatch/ -postScript pmatch_match_funcs.py /home/someUser/ghidra_outputs/func_pcode_db.yaml /home/someUser/PMatch/outputMatches.yaml -import /home/someUser/PMatch/libmatch_tests/bins/Nucleo_i2c_master-stripped.elf`
  (You can import a blob as well, you just need to add the options for architecture/etc.)

If project exists and you already imported the objects, to speed up making db:
  `/usr/bin/time -v $GHIDRA_HOME/support/analyzeHeadless /home/someUser/someFolder PcodeDB -scriptPath /home/someUser/PMatch/ -postScript pmatch_make_db.py /home/someUser/ghidra_outputs/func_pcode_db.yaml -process *.o -recursive`
Then to run the analysis:
  `/usr/bin/time -v $GHIDRA_HOME/support/analyzeHeadless /home/someUser/someFolder PcodeDB -scriptPath /home/someUser/PMatch/ -postScript pmatch_match_funcs.py /home/someUser/ghidra_outputs/func_pcode_db.yaml /home/someUser/PMatch/outputMatches.yaml -process Nucleo_i2c_master-stripped.elf`

# Side Notes:
  
If you use the headless analyzer, after you have an existing project, instead of the -import, you can change it to -process, otherwise there will be an error and say it couldn't import because it is existing.

