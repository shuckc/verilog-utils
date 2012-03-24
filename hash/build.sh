#!/bin/bash -e
gcc -o jenkins.o jenkins.c
./jenkins.o > jenkins.csv
diff jenkins.csv jenkins.knowngood

