NS Assignment || a 50.005 Computer System Engineering project
by Gede Ria Ghosalya (1001841) & Keong Johsi (1001685)

1. How to use
1a. Using java compiler

First, make sure to compile Crypto.java on both sides.

On server side, compile & run either SecStoreCP1.java or SecStoreCP2.java (depending on which CP is of preference).
The program will inform you of the IP Address from which the client can reach this server.

On client side, compile Client.java and run. If Client is run with 2 arguments (IPAdress, Filename(fullpath)), it will automatically attempt to send the indicated file.
Else, the program will prompt for IPAdress and the file name with full path. Make sure that the server is running before running client.

Once these steps are taken, both server and client program will print the status of the file transfer. 
The programs will show the Estimated time taken & throughput before exiting.

The server code will safe the transfered file at C:/NSProject by default. If the directory does not exists, it will attempt to make one.
If the attempt fails the program will warn the user.

1b. Using Windows Batch file
Make sure to compile Crypto.java on both sides.
If you are on Windows, you can simply run secstore1.bat or secstore2.bat (according to CP preference),
and run client.bat on client. Note that in this way, the client.bat will prompt you for IPAdress and Filename.


2. Project Structure
there are 4 .java files within the project:
- Client.java
   The client-side of the Java code.
- SecStoreCP1.java
   The server-side of the Java code implementing file upload, AP & CP1
- SecStore CP2.java
   The server-side of the Java code implementing file upload, AP & CP2
- Crypto.java
   A shared class used to contain common functions e.g. encrypt() & decrypt()
- CA.crt
   Certificate by CA to authorize public key
- 1001685.crt
   Certificate for Server's public key
- privateServer.der, publicServer.der
   RSA private & public key for server to use


