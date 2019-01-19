////////////////////////////////////////////////////////////////////////////////
//
//  File          : cmpsc443_ns_util.c
//  Description   : This file contains utility functions for the NS protocol
//                  assignment.  Feel free to add functions as you wish.
//
//   Author        : Patrick McDaniel
//   Last Modified : Mon Oct  8 16:11:24 PDT 2018
//

// Include files
#include <errno.h>
#include <gcrypt.h>
#include <cmpsc311_log.h>
#include <cmpsc311_util.h>
#include <cmpsc311_network.h>

// Project includes
#include <cmpsc443_ns_proto.h>

// 
// Functions

////////////////////////////////////////////////////////////////////////////////
//
// Function     : createNonce
// Description  : Creates a random nonce using gcrypt
//
// Inputs       : nonce - Pointer to the nonce to populate with random data
// Outputs      : 0 if successful, -1 if failure

int createNonce(ns_nonce_t *nonce) {
	// Just use the existing get randomness function
	getRandomData((char *)nonce, sizeof(ns_nonce_t));
	return(0);
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : makeKeyFromPassword
// Description  : Derives a key from an input password
//
//Inputs        : password - The password to use for key generation
 //               key      - The key to populate wit hthe derived key
// Outputs      : 0 if successful, -1 if failure

int makeKeyFromPassword(char *password, ns_key_t key) {

	// Just take a SHA256 of the password to create the key
	gcry_md_hd_t sha256;
	gcry_md_open(&sha256, GCRY_MD_SHA256, 0);
	gcry_md_write(sha256, password, strlen(password));
	memcpy(key, gcry_md_read(sha256, GCRY_MD_SHA256), sizeof(ns_key_t));
	gcry_md_close(sha256);

	// Return scucessfully
	return(0);
}

