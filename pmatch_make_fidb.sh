# Copyright 2021 National Technology & Engineering Solutions of Sandia, LLC (NTESS). 
# Under the terms of Contract DE-NA0003525 with NTESS, the U.S. Government retains 
# certain rights in this software.

#!/bin/bash

echo "usage: ${0} [-d /path/to/output] [-f DB_FILENAME.yaml] [-l /path/to/objects/]"

OUTPUT_DB_FOLDER="${HOME}/ghidra_outputs"
DB_FILENAME="pcode_db.yaml"
IMPORT_PATH="./lib/"
PROJ="PcodeDB"
while getopts d:f:l:p: option
do
case "${option}"
in
d) OUTPUT_DB_FOLDER=${OPTARG};;
f) DB_FILENAME=${OPTARG};;
l) IMPORT_PATH=${OPTARG};;
p) PROJ=${OPTARG};;
esac
done

mkdir -p OUTPUT_DB

if [[ ! $GHIDRA_HOME ]]; then
	echo "Must set \$GHIDRA_HOME, (if username is local) e.g. via:"
	echo "export GHIDRA_HOME=/home/local/Programs/$GHIDRA_VERSION"
	exit 1
fi
if [[ ! $GHIDRA_PROJ ]]; then
	echo "Must set \$GHIDRA_PROJ, (if username is local) e.g. via:"
	echo "export GHIDRA_PROJ=/home/local/ghidra_projects"
	exit 1
fi

abs_libpath="${IMPORT_PATH}"
libpath=$(basename $(readlink -f ${abs_libpath}))
provider="${libpath}"
ghidra_path="${GHIDRA_HOME}"
ghidra_headless="${ghidra_path}/support/analyzeHeadless"
ghidra_scripts="${ghidra_path}/Ghidra/Features/FunctionID/ghidra_scripts"
ghidra_proj="${GHIDRA_PROJ}"

echo ${libpath}
echo ${abs_libpath}
echo ${provider}
echo ${ghidra_path}
echo ${ghidra_headless}
echo ${ghidra_scripts}
echo ${ghidra_proj}

#GET THE DIRECTORY WHERE THIS SCRIPT IS SO WE HAVE ACCESS TO THE SCRIPTS HERE
SOURCE="${BASH_SOURCE[0]}"
while [ -h "$SOURCE" ]; do # resolve $SOURCE until the file is no longer a symlink
  script_dir="$( cd -P "$( dirname "$SOURCE" )" >/dev/null 2>&1 && pwd )"
  SOURCE="$(readlink "$SOURCE")"
  [[ $SOURCE != /* ]] && SOURCE="$script_dir/$SOURCE" # if $SOURCE was a relative symlink, we need to resolve it relative to the path where the symlink file was located
done
script_dir="$( cd -P "$( dirname "$SOURCE" )" >/dev/null 2>&1 && pwd )"

###############################################################################
#FIRST EXTRACT LIBRARY IF NECESSARY AND LOG COMMON SYMBOLS
curpath=$(pwd)
common="${OUTPUT_DB_FOLDER}/${provider}-common.txt"
touch ${common}
cd "${abs_libpath}"
find "$(pwd)" -regex ".*\.\(lib\|a\)" | while read lib; do
	echo "${lib} ##########################################################"
	subdir=$(echo "${lib}" | sed 's/\.\(a\|lib\)//g')
	if ! 7z -y x "${lib}" -o"${subdir}"; then
		echo "7z ERROR #####################################################"
		mkdir -p "${subdir}"
	fi
	# fixup names. some .lib contain files with \ in names.
	# 7z doesn't extract these to dirs but includes the \ in name
	# for Ghidra \ = / ... so we must replace \ with _
	find . -name '*\\*' -type f -exec bash -c 't="${0//\\//}"; mkdir -p "${t%/*}"; mv -v "$0" "$t"' {} \;
	cd "${subdir}"
	cat *.txt | awk '{print $2}' >> ${common}
	find -type f -not -iname '*.o' -and -not -iname '*.obj' -exec rm {} \;
	find -type l -exec rm {} \; # delete symlinks
	rm -rf "${lib}"
done
sort -u ${common} -o ${common}
cd ${curpath}
###############################################################################

echo "NOW WE ARE RUNNING PCODE-LIBMATCH"
#NOW RUN THE PCODE-LIBMATCH
/usr/bin/time -v "${ghidra_headless}" "${ghidra_proj}" "${PROJ}" -scriptPath "${script_dir}" -postScript pmatch_make_db.py "${OUTPUT_DB_FOLDER}/${DB_FILENAME}" -import "${abs_libpath}" -recursive -postScript FunctionIDHeadlessPostscript.java | tee -a "${OUTPUT_DB_FOLDER}/${provider}-headless.log"

# /usr/bin/time -v "${ghidra_headless}" "${ghidra_proj}" "${PROJ}" -scriptPath "${script_dir}" -postScript pmatch_make_db.py "${OUTPUT_DB_FOLDER}/${DB_FILENAME}" -process *.o -recursive -postScript FunctionIDHeadlessPostscript.java | tee -a "${OUTPUT_DB_FOLDER}/${provider}-headless.log"

echo "NOW WE ARE RUNNING PCODE-LIBMATCH"
cat "${OUTPUT_DB_FOLDER}/${provider}-headless.log" | grep -o "INFO  REPORT: Import succeeded with language \".*\" and cspec" | grep -o "\".*\"" | sed 's/"//g' | sort -u > "${OUTPUT_DB_FOLDER}/${provider}-langids.txt"


echo "NOW WE ARE GENERATING FIDB"
#NOW WE HAVE IMPORTED EVERYTHING INTO THE PROJECT AND CREATED PCODE-DB. 
#NOW CREATE the FIDB
cat "${OUTPUT_DB_FOLDER}/${provider}-langids.txt" | while read langid; do 
langid_dots="$(echo "${langid}" | sed 's/:/./g')"

touch "${OUTPUT_DB_FOLDER}/duplicate_results.txt"

echo "${ghidra_headless} ${ghidra_proj} ${PROJ} -noanalysis -scriptPath ${script_dir} -preScript z.java ${OUTPUT_DB_FOLDER}/duplicate_results.txt true ${OUTPUT_DB_FOLDER} ${provider}-${langid_dots}.fidb /${provider} ${OUTPUT_DB_FOLDER}/${provider}-common.txt ${langid}"

FIDB_FILE="${provider}-${langid_dots}.fidb"
if [ -f ${FIDB_FILE} ]; then
	echo "Renaming the file"
	mv "${FIDB_FILE}" "${RANDOM}_${FIDB_FILE}"
else
	echo "Not renaming"
fi 

"${ghidra_headless}" "${ghidra_proj}" "${PROJ}" -noanalysis -scriptPath "${script_dir}" -preScript AutoCreateMultipleLibraries.java "${OUTPUT_DB_FOLDER}/duplicate_results.txt" true ${OUTPUT_DB_FOLDER} "${FIDB_FILE}" "/${provider}" ${OUTPUT_DB_FOLDER}/${provider}-common.txt "${langid}"

done
