#!/bin/bash
#set -x
 


INPUT=executionTimes.csv
OLDIFS=$IFS
IFS=','
CNT=0

#Create directory for results
mkdir -p results results/figures

#[ ! -f $INPUT ] && echo "$INPUT file not found. It must contain execution times for each app to be tested (app,sysnameTime,nativeTime)"; exit 99; 

#Cycle through the entries in the csv file
while read app pistis native
do
    if [ $CNT -gt 0 ]; then
        printf "%s\n" $app
        #Create results for both SYSNAME and native execution times
        java Battery.java results/${app}.Mod.csv $pistis
        java Battery.java results/${app}.Nat.csv $native 
    fi
    
    ((CNT = CNT + 1))
done < $INPUT
IFS=$OLDIFS
