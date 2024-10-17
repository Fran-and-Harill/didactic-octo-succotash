/** This program simulates the RSA algorithm with key generation, encryption and decryption
 * and measures average decryption time
 * Using three smaller prime numbers for the modulus
 */

#include <iostream>
#include <cstdio>
#include <gmpxx.h>
#include <chrono>
#include <string>
#include <iomanip>

using namespace std;

// Prime numbers
mpz_t p, q, r;
// modulus n and totient phi
mpz_t n, phi;
// public and private exponents respectively, e and d
mpz_t e, d;
// message before encryption, M, cipher, C, and message after decryption, D
mpz_t M, C, D;
// random state
gmp_randstate_t state;

mp_bitcnt_t bitcnt[] = {171, 341, 683, 1365}; //size of prime numbers
int sizes[] = {512, 1024, 2048, 4096}; // size of modulus

// plaintext
const char* plaintext = "1403011660068973897026462455009024948617319528034456648873066625426063590617176028730749112107817987929049680206496093819";

void keyGeneration (int z)
{
    /** Key Generation Phase
     *  Generate three random prime numbers
     *  Calculate modulus n and totient phi
     *  Set encryption exponent to 65537
     *  Calculate decryption exponent
    **/

    // Generate three prime numbers, p, q and r
	do
	{
		mpz_rrandomb(p, state, bitcnt[z]);
	} while (mpz_probab_prime_p(p, 50) == 0);
	do
	{
		mpz_rrandomb(q, state, bitcnt[z]);
	} while (mpz_probab_prime_p(q, 50) == 0);
	if (z == 0 || z == 2) {
		do
		{
			mpz_rrandomb(r, state, bitcnt[z] - 1);
		} while (mpz_probab_prime_p(r, 50) == 0);
	} else {
		do
		{
			mpz_rrandomb(r, state, bitcnt[z] + 1);
		} while (mpz_probab_prime_p(r, 50) == 0);
	}

	// Calculate n = pqr
	mpz_mul(n, p, q);
    mpz_mul(n, n, r);
	// Calculate phi = (p - 1)(q - 1)(r - 1)
	mpz_sub_ui(p, p, 1);
	mpz_sub_ui(q, q, 1);
    mpz_sub_ui(r, r, 1);
	mpz_mul(phi, p, q);
    mpz_mul(phi, phi, r);
    mpz_add_ui(p, p, 1);
	mpz_add_ui(q, q, 1);
    mpz_add_ui(r, r, 1);

	// Set e to 65537
	mpz_set_ui(e, 65537);
    // Calculate d
	mpz_invert(d, e, phi);
	return;
}

void encryption ()
{  
    // Encrypt
	mpz_powm(C, M, e, n);
	return;
}
void decryption ()
{
    // Decrypt
	mpz_powm(D, C, d, n);
	return;
}

int main ()
{
	/**
	 * Measure and visualize decryption times over various plaintexts and moduli sizes:
	 * 1. initialize variables
	 * 2. initialize random state
	 * 3. Iterate and print results
	 * 4. Clear variables
	**/
	
	cout << "ERSA Encryption:" << endl << endl;
	// initialize variables
	mpz_inits(p, q, r, n, phi, e, d, M, C, D, NULL);
    mpz_set_str(M, plaintext, 10);

	// initialize state
	gmp_randinit_default(state);
	
	cout << left << setw(20) << "Modulus Size(bits)" << setw(20) << "Generation(ms)" << setw(20) << "Encryption(ms)" << setw(20) << "Decryption(ms)" << endl;

	// iterate for each modulus size
	for (int j = 0; j < 4; j++)
	{
		// averages
		double averageGeneration = 0.0;
		double averageEncryption = 0.0;
		double averageDecryption = 0.0;
		
		// iterate 100 times and get average
		for (int i = 0; i < 100; i++)
		{
			// generate key
			auto start = chrono::high_resolution_clock::now();
			keyGeneration(j);
			auto end = chrono::high_resolution_clock::now();
			
			chrono::duration<double> generationTime = end - start;
			
			averageGeneration += generationTime.count();
			
			// encrypt
			start = chrono::high_resolution_clock::now();
			encryption();
			end = chrono::high_resolution_clock::now();
			
			chrono::duration<double> encryptionTime = end - start;
			
			averageEncryption += encryptionTime.count();
			
			//decrypt
			start = chrono::high_resolution_clock::now();
			decryption();
			end = chrono::high_resolution_clock::now();

			chrono::duration<double> decryptionTime = end - start;
			
			averageDecryption += decryptionTime.count();
			
		}
		averageGeneration *= 10;
		averageEncryption *= 10;
		averageDecryption *= 10; // divide by 100 for average, multiply by 1000 for milliseconds
		
		cout << setw(20) << sizes[j] << fixed << setprecision(3) << setw(20) << averageGeneration << setw(20) << averageEncryption << setw(20) << averageDecryption << endl;
	}
	
	// clear variables
	mpz_clears(p, q, r, n, phi, e, d, M, C, D, NULL);

	return 0;
}