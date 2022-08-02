#!/bin/bash

javac org/gmssl/GmSSL.java
java -Djava.library.path=../ org/gmssl/GmSSL
