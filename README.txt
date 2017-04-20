NS Assignment || a 50.005 Computer System Engineering project
by Gede Ria Ghosalya (1001841) & Keong Jo Hsi (1001685)

1. How to use

1a. Using java compiler

First, compile Crypto.java on both sides.

On the server side, compile & run either SecStoreCP1.java or SecStoreCP2.java depending on the CP of preference.
The program will inform you of the IP Address from which the client can reach the server.

On the client side, compile Client.java and run. If the client is run with 2 arguments (IPAddress, Filename(fullpath)), it will automatically attempt to send the specified file. Otherwise, the program prompts the client for an IPAddress and file name with full path. Make sure that the server is run before the client.

Once these steps are completed, both the server and client programs will print the status of the file transfer. 
The programs will show the etimated time taken & throughput before exiting.

The server code saves the transferred file into C:/NSProject by default. If the directory does not exist, it will attempt to create one. If the attempt fails, the program will warn the user.


1b. Using Windows Batch file

Compile Crypto.java on both sides.
On Windows, simply run secstore1.bat or secstore2.bat (according to CP preference) and client.bat. When run in this manner, client.bat prompts the user for an IPAddress and Filename.



2. Project Structure

There are 4 .java files within the project:

- Client.java
   The client side of the Java code.
- SecStoreCP1.java
   The server side of the Java code implementing file upload, AP & CP1
- SecStoreCP2.java
   The server side of the Java code implementing file upload, AP & CP2
- Crypto.java
   A shared class containing common functions e.g. encrypt() & decrypt()
- CA.crt
   Certificate by CA to authorize public key
- 1001685.crt
   Certificate for Server's public key
- privateServer.der, publicServer.der
   the server's RSA private & public keys

