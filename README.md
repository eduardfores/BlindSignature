# BlindSignature

[![License](https://img.shields.io/badge/license-GPL--v3.0-orange)](https://github.com/eduardfores/BlindSignature)

Introduction
-------------
This project has an example of RSA comunication between 2 java programs.
This 2 java programs are Bob and Alice where Bob has the server rol and Alice is the solicitant of the information from Bob.

How To Run
-------------
To run this project you must to do: 
 
+ Import this project in to eclipse.
+ First of all you have to start Bob because he is the server.
+ After you will start Alice and she will search the connection with Bob through the port 6000

Usage
-------------

After you have the 2 participants on you can go to the Alice process and here you can answer the question "Do you want challenge?". 
+ If you wirte a 1 the alice call Bob to request one challenge with Blind signature, Bob will send it and Alice will verify the challenge with the RSA.
+ If you write 0 the Alice process close the connection with Bob and the 2 process will finish.
