/** This program simulates the RSA algorithm with key generation, encryption and decryption
 * and measures average decryption time
 * Using two moduli and Chinese Remainder Theorem in the Decryption phase
 */

#include <iostream>
#include <cstdio>
#include <gmpxx.h>
#include <chrono>
#include <string>
#include <iomanip>

using namespace std;

// Prime numbers p and q
mpz_t p, q, r, s;
// modulus n=p*q, totient phi=(p-1)*(q-1)
mpz_t n, phi_n, m, phi_m;
// public and private exponents respectively, e and d
mpz_t e, d, f, c;
// private exponent d broken into components, dp=d mod (p-1) and dq=d mod (q-1)
mpz_t dp, dq, cr, cs;
// inverses of prime numbers mod other prime numbers p_inv=p^-1 mod q and q^-1 mod p
mpz_t p_inv, q_inv, r_inv, s_inv;
// message before encryption, M, cipher , C, and message after encryption, D
mpz_t M, C, D;
// cipher in components CP and CQ, and message after encryption, in components DP and DQ
mpz_t CP, CQ, CR, CS, DP, DQ, DR, DS;
// random state
gmp_randstate_t state;

mp_bitcnt_t bitcnt[] = {256, 512, 1024, 2048}; // size of prime numbers
int sizes[] = {512, 1024, 2048, 4096}; // size of modulus

// plaintext
const char* plaintext = "1403011660068973897026462455009024948617319528034456648873066625426063590617176028730749112107817987929049680206496093819";

void keyGeneration (int z)
{
    /** Key Generation Phase
     *  Generate four random prime numbers
     *  Calculate moduli n and m and totients phi_n and phi_m
     *  Set encryption exponents to 65537
     *  Calculate decryption exponent
     *  Calculate components for CRT decryption
    **/

    // Generate two prime numbers, p and q
	do
	{
		mpz_rrandomb(p, state, bitcnt[z]);
	} while (mpz_probab_prime_p(p, 50) == 0);
	do
	{
		mpz_rrandomb(q, state, bitcnt[z]);
	} while (mpz_probab_prime_p(q, 50) == 0);
    mpz_nextprime(r, p);
	mpz_nextprime(s, q);

	// Let n = pq
	mpz_mul(n, p, q);
    mpz_mul(m, r, s);
	// Calculate phi = (p - 1)(q - 1)
	mpz_sub_ui(p, p, 1);
	mpz_sub_ui(q, q, 1);
	mpz_mul(phi_n, p, q);
    mpz_sub_ui(r, r, 1);
    mpz_sub_ui(s, s, 1);
    mpz_mul(phi_m, r, s);

	// Choose e and f
	mpz_set_ui(e, 65537);
	mpz_set_ui(f, 65537);
    // Calculate d
	mpz_invert(d, e, phi_n);
    mpz_invert(c, f, phi_m);
	// Calculate dp and dq
	mpz_mod(dp, d, p); // dp = d mod (p - 1)
	mpz_mod(dq, d, q); // dq = d mod (q - 1)
	mpz_add_ui(p, p, 1); // p = p + 1
	mpz_add_ui(q, q, 1); // q = q + 1
    // Calculate cr and cs
    mpz_mod(cr, c, r);
    mpz_mod(cs, c, s);
    mpz_add_ui(r, r, 1);
    mpz_add_ui(s, s, 1);
    // Calculate p_inv and q_inv
	mpz_invert(p_inv, p, q);
	mpz_invert(q_inv, q, p);
    mpz_invert(r_inv, r, s);
    mpz_invert(s_inv, s, r);
	return;
}

void encryption (){
    // Encrypt
    mpz_powm(C, M, f, m);
	mpz_powm(C, C, e, n);
	return;
}
void decryption (){
    // Decrypt
	mpz_mod(CP, C, p);
	mpz_mod(CQ, C, q);
	mpz_powm(DP, CP, dp, p);
	mpz_powm(DQ, CQ, dq, q);
	mpz_mul(DP, DP, q_inv);
	mpz_mul(DP, DP, q);
	mpz_mul(DQ, DQ, p_inv);
	mpz_mul(DQ, DQ, p);
	mpz_add(D, DP, DQ);
	mpz_mod(D, D, n);
    mpz_mod(CR, D, r);
    mpz_mod(CS, D, s);
    mpz_powm(DR, CR, cr, r);
    mpz_powm(DS, CS, cs, s);
    mpz_mul(DR, DR, s_inv);
    mpz_mul(DR, DR, s);
    mpz_mul(DS, DS, r_inv);
    mpz_mul(DS, DS, r);
    mpz_add(D, DR, DS);
    mpz_mod(D, D, m);
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
	
	cout << "RSA Encryption:" << endl << endl;
	// initialize variables
	mpz_inits(p, q, r, s, n, m, phi_n, phi_m, e, f, d, c, dp, dq, cr, cs, p_inv, q_inv, r_inv, s_inv, M, C, D, CP, CQ, CR, CS, DP, DQ, DR, DS, NULL);
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
	mpz_inits(p, q, r, s, n, m, phi_n, phi_m, e, f, d, c, dp, dq, cr, cs, p_inv, q_inv, r_inv, s_inv, M, C, D, CP, CQ, CR, CS, DP, DQ, DR, DS, NULL);

	return 0;
}