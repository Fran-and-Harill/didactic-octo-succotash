/** This program simulates the RSA algorithm with key generation, encryption and decryption
 * and measures average decryption time
 * using two moduli, each with three prime factors, and CRT in the decryption step
 */

#include <iostream>
#include <cstdio>
#include <gmpxx.h>
#include <chrono>
#include <string>
#include <iomanip>

using namespace std;

// Prime numbers
mpz_t p, q, r, s, t, u, x;
// modulus n=p*q, totient phi=(p-1)*(q-1)
mpz_t n, phi_n, m, phi_m;
// public and private exponents respectively, e and d
mpz_t e, d, f, c;
// private exponent d broken into components, dp=d mod (p-1) and dq=d mod (q-1)
mpz_t dp, dq, dr, cs, ct, cu;
// inverses of prime numbers mod other prime numbers p_inv=p^-1 mod q and q^-1 mod p
mpz_t p_inv, q_inv, r_inv, s_inv, t_inv, u_inv;
// message before encryption, M, cipher , C, and message after encryption, D
mpz_t M, C, D;
// cipher in components CP and CQ, and message after encryption, in components DP and DQ
mpz_t CP, CQ, CR, CS, CT, CU, DP, DQ, DR, DS, DT, DU;
// random state
gmp_randstate_t state;

mp_bitcnt_t bitcnt[] = {171, 341, 683, 1365}; // size of prime numbers
int sizes[] = {512, 1024, 2048, 4096}; // size of modulus

// plaintext
const char* plaintext = "1403011660068973897026462455009024948617319528034456648873066625426063590617176028730749112107817987929049680206496093819";

void keyGeneration (int z)
{
    /** Key Generation Phase
     *  Generate six random prime numbers
     *  Calculate moduli n and m and totients phi_n and phi_m
     *  Set encryption exponents to 65537
     *  Calculate decryption exponents
     *  Calculate components for CRT decryption
     */

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
	mpz_nextprime(s, p);
    mpz_nextprime(t, q);
    mpz_nextprime(u, r);
	// Let n = pqr and m = stu
	mpz_mul(n, p, q);
    mpz_mul(n, n, r);
    mpz_mul(m, s, t);
    mpz_mul(m, m, u);
	// Calculate phi_n = (p - 1)(q - 1)(r - 1) and phi_m = (s - 1)(t - 1)(u - 1)
	mpz_sub_ui(p, p, 1);
	mpz_sub_ui(q, q, 1);
    mpz_sub_ui(r, r, 1);
    mpz_mul(phi_n, p, q);
    mpz_mul(phi_n, phi_n, r);
    mpz_sub_ui(s, s, 1);
    mpz_sub_ui(t, t, 1);
    mpz_sub_ui(u, u, 1);
    mpz_mul(phi_m, s, t);
    mpz_mul(phi_m, phi_m, u);
	// Choose e and f
	mpz_set_ui(e, 65537);
	mpz_set_ui(f, 65537);
	// Calculate d and c
	mpz_invert(d, e, phi_n);
    mpz_invert(c, f, phi_m);
	// Calculate dp dq dr cs ct and cu
	mpz_mod(dp, d, p); // dp = d mod (p - 1)
	mpz_mod(dq, d, q); // dq = d mod (q - 1)
    mpz_mod(dr, d, r);
	mpz_add_ui(p, p, 1); // p = p + 1
	mpz_add_ui(q, q, 1); // q = q + 1
    mpz_add_ui(r, r, 1);
    mpz_mod(cs, c, s);
    mpz_mod(ct, c, t);
    mpz_mod(cu, c, u);
    mpz_add_ui(s, s, 1);
    mpz_add_ui(t, t, 1);
    mpz_add_ui(u, u, 1);
    // Calculate p_inv q_inv r_inv s_inv t_inv and u_inv
    mpz_init(x);
    mpz_mul(x, q, r);
	mpz_invert(p_inv, p, x);
    mpz_mul(x, p, r);
	mpz_invert(q_inv, q, x);
    mpz_mul(x, p, q);
    mpz_invert(r_inv, r, x);
    mpz_mul(x, t, u);
    mpz_invert(s_inv, s, x);
    mpz_mul(x, s, u);
    mpz_invert(t_inv, t, x);
    mpz_mul(x, s, t);
    mpz_invert(u_inv, u, x);
	mpz_clear(x);
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
    mpz_mod(CR, C, r);
	mpz_powm(DP, CP, dp, p);
	mpz_powm(DQ, CQ, dq, q);
    mpz_powm(DR, CR, dr, r);
	mpz_mul(DP, DP, q_inv);
	mpz_mul(DP, DP, q);
    mpz_mul(DP, DP, r_inv);
    mpz_mul(DP, DP, r);
	mpz_mul(DQ, DQ, p_inv);
	mpz_mul(DQ, DQ, p);
    mpz_mul(DQ, DQ, r_inv);
    mpz_mul(DQ, DQ, r);
    mpz_mul(DR, DR, p_inv);
    mpz_mul(DR, DR, p);
    mpz_mul(DR, DR, q_inv);
    mpz_mul(DR, DR, q);
	mpz_add(D, DP, DQ);
    mpz_add(D, D, DR);
	mpz_mod(D, D, n);

    mpz_mod(CS, D, s);
    mpz_mod(CT, D, t);
    mpz_mod(CU, D, u);
    mpz_powm(DS, CS, cs, s);
    mpz_powm(DT, CT, ct, t);
    mpz_powm(DU, CU, cu, u);
    mpz_mul(DS, DS, t_inv);
    mpz_mul(DS, DS, t);
    mpz_mul(DS, DS, u_inv);
    mpz_mul(DS, DS, u);
    mpz_mul(DT, DT, s_inv);
    mpz_mul(DT, DT, s);
    mpz_mul(DT, DT, u_inv);
    mpz_mul(DT, DT, u);
    mpz_mul(DU, DU, s_inv);
    mpz_mul(DU, DU, s);
    mpz_mul(DU, DU, t_inv);
    mpz_mul(DU, DU, t);
    mpz_add(D, DS, DT);
    mpz_add(D, D, DU);
    mpz_mod(D, D, m);

	return;
}

int main ()
{
	cout << "\033[35mPRSA Encryption:\033[0m" << endl << endl;
	/**
	 * Measure and visualize decryption times over various plaintexts and moduli sizes:
	 * 1. initialize variables
	 * 2. initialize state
	 * 3. Iterate and print results
	 * 4. Clear variables
	**/
	
	cout << "RSA Encryption:" << endl << endl;
	// initialize variablesmpz_init(p);
	mpz_inits(p, q, r, s, t, u, n, m, phi_n, phi_m, e, d, f, c, dp, dq, dr, cs, ct, cu, p_inv, q_inv, r_inv, s_inv, t_inv, u_inv, M, C, D, CP, CQ, CR, CS, CT, CU, DP, DQ, DR, DS, DT, DU, NULL);
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
		
		// iterate 10 times and get average
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
			
			// 0 if M == D, anything else otherwise
			//cout << mpz_cmp(M, D) << endl;
			
		}
		averageGeneration *= 10;
		averageEncryption *= 10;
		averageDecryption *= 10; // divide by 100 for average, multiply by 1000 for milliseconds
		
		cout << setw(20) << sizes[j] << fixed << setprecision(3) << setw(20) << averageGeneration << setw(20) << averageEncryption << setw(20) << averageDecryption << endl;
	}
	
	// clear variables
	mpz_clears(p, q, r, s, t, u, n, m, phi_n, phi_m, e, d, f, c, dp, dq, dr, cs, ct, cu, p_inv, q_inv, r_inv, s_inv, t_inv, u_inv, M, C, D, CP, CQ, CR, CS, CT, CU, DP, DQ, DR, DS, DT, DU, NULL);

	return 0;
}