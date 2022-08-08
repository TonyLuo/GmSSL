cd /Users/tony/unicom/git/GmSSL/java/
gcc -shared -fPIC -Wall -I./jni -I /Users/tony/unicom/git/GmSSL/include -L /Users/tony/unicom/git/GmSSL/lib SDF.c -lcrypto -lswsds -o libsdfjni.so

javac org/gmssl/SDF.java
java -Djava.library.path=../ org/gmssl/SDF

