#!/bin/bash 

YEAR=`date "+%Y"`
COPYRIGHT=""
COPYRIGHT+="/*"$'\n'
COPYRIGHT+=" *  Copyright $YEAR The GmSSL Project. All Rights Reserved."$'\n'
COPYRIGHT+=" *"$'\n'
COPYRIGHT+=" *  Licensed under the Apache License, Version 2.0 (the "License"); you may"$'\n'
COPYRIGHT+=" *  not use this file except in compliance with the License."$'\n'
COPYRIGHT+=" *"$'\n'
COPYRIGHT+=" *  http://www.apache.org/licenses/LICENSE-2.0"$'\n'
COPYRIGHT+=" */"$'\n'
COPYRIGHT_FILE=copyright.txt
echo "$COPYRIGHT" > $COPYRIGHT_FILE
copyright_start_string="/*"
copyright_end_string="*/"

function modify_copyright(){
	file_path=$1
	copyright_start_line=`grep -n "/\*" $file_path  | head -1 | cut -d  ':' -f  1`
	copyright_end_line=`grep -n  "\*/" $file_path | head -1| cut -d  ':' -f  1`
	echo $file_path $copyright_start_line $copyright_end_line
	sed -i $copyright_start_line,$copyright_end_line'd' $file_path
	sed -i "1 r $COPYRIGHT_FILE" $file_path
	sed -i '1d' $file_path
}

function getDir() {
	for filename in $1/*
	do
	    if [ -d $filename ]
	    then
	        getDir $filename
	    else
	        if [[ "${filename##*.}" == 'h'  || "${filename##*.}" == 'c' ]]
	        then
				modify_copyright $filename
	            #sed -i "1i\/*$filename*/" $filename
	        fi
	    fi
	done
}
getDir ..

rm $COPYRIGHT_FILE