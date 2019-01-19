#ifndef CMPSC443_PROTO_INCLUDED
#define CMPSC443_PROTO_INCLUDED

////////////////////////////////////////////////////////////////////////////////
//
//  File          : cmpsc443_ns_proto.h
//  Description   : This file contains definitions for the Needham Schroeder 
//                  protocol, that will be used as part of this assignment.
//
//  Author        : Patrick McDaniel
//  Created       : Mon Oct  8 16:11:24 PDT 2018

// Includes
#include <stdint.h>
#include <stdlib.h>

// Defines
#define NS_SERVER_PROTOCOL_PORT 2001 // The server/bob port
#define NS_ALICE_IDENTITY       "Alice" // Alice's
#define NS_ALICE_PASSWORD       "N10dEy3A]&84YhQL"
#define NS_BOB_IDENTITY         "Bob" // Alice's Name
#define NS_BOB_PASSWORD         "v5FYo|10!,U}G1(8"
#define NS_MAX_BACKLOG          5 // The backlog of connection cieling
#define NS_MAX_XMIT_SIZE        1024*32 // 32K maximum xmit
#define LEN_IV                  16
#define LEN_UINT16              2
#define LEN_NONCE               8
#define LEN_ID                  16
#define LEN_KEY                 16
#define LEN_AES_BLK             16
#define LEN_MSG_HDR_1           LEN_UINT16
#define LEN_MSG_HDR_2           LEN_UINT16
#define LEN_BLK_HDR_1           LEN_IV
#define LEN_BLK_HDR_2           LEN_UINT16
#define LEN_MSG_HDR             LEN_MSG_HDR_1+LEN_MSG_HDR_2
#define LEN_BLK_HDR             LEN_BLK_HDR_1+LEN_BLK_HDR_2
#define LEN_TICKET_HDR          LEN_UINT16+LEN_BLK_HDR
#define DATA_RESP_MASK          0xB6


// Message types
// Note: A=Alice, B=Bob, S=Service
typedef enum {
	NS_TKT_REQ = 1,     // Ticket request           (A -> B)
	NS_TKT_RES = 2,     // Ticket response          (S -> A)
	NS_SVC_REQ = 3,     // Service request          (A -> B)
	NS_SVC_RES = 4,     // Service response         (B -> A)
	NS_SVC_ACK = 5,     // Service acknowledgement  (A -> B)
	NS_DAT_REQ = 6,     // Data request             (B -> A)
	NS_DAT_RES = 7,     // Data response            (S -> B)
	NS_SVC_FIN = 8,     // Service finished         (B -> A)
	NS_MSG_MAX_TYPE = 8 // Used for iterators, etc.
} message_type_t;

// User's ID, as issued at the beginning of the assignment
typedef uint8_t ns_id_t[16];

// A nonce, randomly generated to ensure protocol freshness
typedef uint64_t ns_nonce_t;

// A 128-bit AES key, as issues at the beginning of the assignment
typedef uint8_t ns_key_t[16];

// An Initialization Vector, used to ensure that message encryptions are unique
typedef uint8_t ns_iv_t[16];

// Helper structure for managing tickets
typedef struct ticket{
	uint8_t data[NS_MAX_XMIT_SIZE];
	size_t length;
} ns_ticket_t;

//
// Message structures

// Headers
typedef struct {
  uint16_t size;
  uint16_t type;
} msg_header_t;

typedef struct {
  ns_iv_t iv;
  uint16_t size;
} block_header_t;

// Ticket request
typedef struct tkt_req {
	ns_nonce_t N1;
	ns_id_t A;
	ns_id_t B;
} tkt_req_t;

// Ticket response
typedef struct tkt_res {
	ns_nonce_t N1;
	ns_id_t B;
	ns_key_t Kab;
	ns_ticket_t ticket;
} tkt_res_t;

// Service resposne
typedef struct svc_req {
	ns_id_t A;
	ns_id_t B;
	ns_ticket_t ticket;
	ns_nonce_t N2;
} svc_req_t;

// Service resposne
typedef struct svc_res {
	ns_nonce_t N2;
	ns_nonce_t N3;
} svc_res_t;

// Service acknow
typedef struct svc_ack {
	ns_nonce_t N3;
} svc_ack_t;

// Data
typedef struct data_container {
	uint8_t data[NS_MAX_XMIT_SIZE];
	size_t length;
} data_container_t;

#endif
