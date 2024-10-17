# didactic-octo-succotash
Timed implementations of RSA in C++ using GMP Library and chrono.h for timing

Overview
As part of my Honours project, this repository contains the five implementations of RSA in C++ used in experiments pertaining to the efficiency of RSA implementations.

Files
  RSA.cpp -- a naive implementation
  RSA_CRT.cpp -- an implementation of RSA using Chinese Remainder Theorem (CRT)
  ERSA.cpp -- an implementation of RSA using three smaller prime factors in the modulus
  MRSA.cpp -- an implementation of RSA using two moduli, each with two prime factors, and CRT
  PRSA.cpp -- an implementation of RSA using two moduli, each with three smaller prime factors, and CRT

Getting Started
To compile and run the code, you will need:
  A C++ compiler -- the project used g++ 13.2.0
  The GNU Multiple Precision Arithmetic Library

Installation:
To clone the repository, use the command
  git clone https://github.com/Fran-and-Harill/didactic-octo-succotash.git
  cd didactic-octo-succotash
To compile a file using g++, say RSA.cpp
  g++ -o RSA RSA.cpp -lgmp
To run the compiled executable:
  ./RSA

Acknowledgements
  The implementations are based on algorithms in the following studies:
    Al-Hamami, A. H. and Aldariseh, I. A. Enhanced Method for RSA Cryptosystem Algorithm. In 2012 International Conference on Advanced Computer Science Applications and Technologies (ACSAT), pages 402–408. IEEE, 2012.
    Gandhi, T., Navlakha, M., Raheja, R., Mehta, V., Jhaveri, Y., and Shekokar, N. Enhanced RSA Cryptosystem: A Secure and Nimble Approach. In 2022 5th International Conference on Advances in Science and Technology (ICAST), pages 388–392. IEEE, 2022
    Wu, C.-H., Hong, J.-H., and Wu, C.-W. RSA Cryptosystem Design Based on the Chinese Remainder Theorem. In Proceedings of the 2001 Asia and South Pacific Design automation conference, pages 391–395. 2001
