cd /Users/tony/unicom/git/GmSSL/java
gcc -shared -fPIC -Wall -I./jni -I /Users/tony/unicom/git/GmSSL/include -L /Users/tony/unicom/git/GmSSL/lib GmSSL.c -lcrypto -lswsds -o libgmssljni.so
gcc -shared -fPIC -Wall -I./jni -I /Users/tony/unicom/git/GmSSL/include -L /Users/tony/unicom/git/GmSSL/lib SDF.c -lcrypto -lswsds -o libsdfjni.so

javac org/gmssl/GmSSL.java
java -Djava.library.path=../ org/gmssl/GmSSL

