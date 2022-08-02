cd /Users/tony/unicom/git/GmSSL/java
gcc -shared -fPIC -Wall -I./jni -I /Users/tony/unicom/git/GmSSL/include -L /Users/tony/unicom/git/GmSSL/lib GmSSL.c -lcrypto -o libgmssljni.so
javac org/gmssl/GmSSL.java
java -Djava.library.path=../ org/gmssl/GmSSL

