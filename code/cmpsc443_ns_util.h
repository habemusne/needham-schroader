#ifndef CMPSC443_UTIL_INCLUDED
#define CMPSC443_UTIL_INCLUDED

////////////////////////////////////////////////////////////////////////////////
//
//  File          : cmpsc443_ns_util.h
//  Description   : This file contains definitions for utility functions to be
//                  used as part of the assignment.
//
//  Author        : Patrick McDaniel
//  Created       : Mon Oct  8 16:11:24 PDT 2018

// Includes
#include <cmpsc443_ns_proto.h>

/**
 * Function      : createNonce
 * Description   : Creates a random nonce using gcrypt
 * 
 * Inputs        : nonce - Pointer to the nonce to populate with random data
 */
int createNonce(ns_nonce_t* nonce);

/**
 * Function      : makeKeyFromPassword
 * Description   : Derives a key from an input password
 * 
 * Inputs        : password - The password to use for key generation
 *                 key      - The key to populate wit hthe derived key
 */
int makeKeyFromPassword(char *password, ns_key_t key);

#endif
