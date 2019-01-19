////////////////////////////////////////////////////////////////////////////////
//
//  File          : cmpsc443_ns_client.c
//  Description   : This is the client side of the Needham Schroeder 
//                  protocol, and associated main processing loop.
//
//   Author        : Nan Chen
//   Last Modified : 2018.11.07
//

// Includes
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <arpa/inet.h>
#include <cmpsc311_log.h>
#include <cmpsc311_network.h>
#include <cmpsc311_util.h>

// Project Include Files
#include <cmpsc443_ns_proto.h>
#include <cmpsc443_ns_util.h>

int roundToAesBlockLen(int num) {
  int base = LEN_AES_BLK;
  return (num+base-1) - (num+base-1) % base;
}

// Defines
#define NS_ARGUMENTS "h"
#define USAGE \
	"USAGE: cmpsc443_ns_client [-h]\n" \
	"\n" \
	"where:\n" \
	"    -h - help mode (display this message)\n" \
	"\n"
#define ROUND_TO_AES_BLK_LEN(NUM)\
  (NUM+LEN_AES_BLK-1) - (NUM+LEN_AES_BLK-1) % LEN_AES_BLK

#define LEN_TICKET ROUND_TO_AES_BLK_LEN(LEN_KEY + LEN_ID)
#define LEN_TICKET_STR\
  LEN_UINT16 +\
  LEN_BLK_HDR +\
  LEN_TICKET

// define encrypted block body length
#define LEN_PAYLOAD_TKT_RES_BLK1_BODY\
  ROUND_TO_AES_BLK_LEN(LEN_NONCE +\
  LEN_ID +\
  LEN_KEY +\
  LEN_PAYLOAD_TKT_RES_BLK2)
#define LEN_PAYLOAD_SVC_REQ_BLK2_BODY ROUND_TO_AES_BLK_LEN(LEN_NONCE)
#define LEN_PAYLOAD_SVC_RES_BLK1_BODY ROUND_TO_AES_BLK_LEN(LEN_NONCE + LEN_NONCE)
#define LEN_PAYLOAD_ACK_BLK1_BODY ROUND_TO_AES_BLK_LEN(LEN_NONCE)

// define encrypted block length
#define LEN_PAYLOAD_TKT_RES_BLK2 LEN_TICKET_STR
#define LEN_PAYLOAD_TKT_RES_BLK1\
  LEN_BLK_HDR +\
  LEN_PAYLOAD_TKT_RES_BLK1_BODY
#define LEN_PAYLOAD_SVC_REQ_BLK1 LEN_TICKET_STR
#define LEN_PAYLOAD_SVC_REQ_BLK2\
  LEN_BLK_HDR +\
  LEN_PAYLOAD_SVC_REQ_BLK2_BODY
#define LEN_PAYLOAD_SVC_RES_BLK1\
  LEN_BLK_HDR +\
  LEN_PAYLOAD_SVC_RES_BLK1_BODY
#define LEN_PAYLOAD_ACK_BLK1\
  LEN_BLK_HDR +\
  LEN_PAYLOAD_ACK_BLK1_BODY

// define payload length
#define LEN_PAYLOAD_TKT_REQ\
  LEN_NONCE +\
  LEN_ID +\
  LEN_ID
#define LEN_PAYLOAD_TKT_RES LEN_PAYLOAD_TKT_RES_BLK1
#define LEN_PAYLOAD_SVC_REQ\
  LEN_ID +\
  LEN_ID +\
  LEN_PAYLOAD_SVC_REQ_BLK1 +\
  LEN_PAYLOAD_SVC_REQ_BLK2
#define LEN_PAYLOAD_SVC_RES LEN_PAYLOAD_SVC_RES_BLK1
#define LEN_PAYLOAD_ACK LEN_PAYLOAD_ACK_BLK1

// Functional Prototypes
int ns_client( void );


//
// Functions

int checkNonce(ns_nonce_t a, ns_nonce_t b) {
  logMessage(LOG_INFO_LEVEL, "nonce a: %ld", a);
  logMessage(LOG_INFO_LEVEL, "nonce b: %ld", b);
  if (a != b) {
    logMessage(LOG_ERROR_LEVEL, "nonces not match");
    return 1;
  }
  return 0;
}

uint16_t readIv(unsigned char** buf, uint16_t* offset, ns_iv_t* res) {
  uint16_t original = *offset;
  memcpy(res, *buf + *offset, LEN_IV);
  *offset += LEN_IV;
  return original;
}

uint16_t readInt16(unsigned char** buf, uint16_t* offset, uint16_t* res) {
  uint16_t original = *offset;
  *res = (*buf + *offset)[0] << 8 | (*buf + *offset)[1];
  *offset += LEN_UINT16;
  return original;
}

uint16_t readNonce(unsigned char** buf, uint16_t* offset, ns_nonce_t* res) {
  uint16_t original = *offset;
  memcpy(res, *buf + *offset, LEN_NONCE);
  *res = ntohll64(*res);
  *offset += LEN_NONCE;
  return original;
}

uint16_t readIdentity(unsigned char** buf, uint16_t* offset, ns_id_t* res) {
  uint16_t original = *offset;
  memcpy(res, *buf + *offset, LEN_ID);
  *offset += LEN_ID;
  return original;
}

uint16_t readKey(unsigned char** buf, uint16_t* offset, ns_key_t* res) {
  uint16_t original = *offset;
  memcpy(res, *buf + *offset, LEN_KEY);
  *offset += LEN_KEY;
  return original;
}

uint16_t readBytes(unsigned char** buf, uint16_t* offset, unsigned char* res, int numBytes) {
  uint16_t original = *offset;
  memcpy(res, *buf + *offset, numBytes);
  *offset += numBytes;
  return original;
}

uint16_t readMsgHeader(unsigned char** buf, uint16_t* offset, msg_header_t* res) {
  uint16_t original = *offset;
  readInt16(buf, offset, &(res->size));
  readInt16(buf, offset, &(res->type));
  return original;
}

uint16_t readBlockHeader(unsigned char** buf, uint16_t* offset, block_header_t* res) {
  uint16_t original = *offset;
  readIv(buf, offset, &(res->iv));
  readInt16(buf, offset, &(res->size));
  return original;
}

uint16_t writeNonce(unsigned char** buf, uint16_t* offset, ns_nonce_t src) {
  uint16_t original = *offset;
  *(uint64_t*)(*buf + *offset) = htonll64(src);
  *offset += LEN_NONCE;
  return original;
}

uint16_t writeBytes(unsigned char** buf, uint16_t* offset, unsigned char* src, int numBytes) {
  uint16_t original = *offset;
  memcpy(*buf + *offset, src, numBytes);
  *offset += numBytes;
  return original;
}

uint16_t writeInt16(unsigned char** buf, uint16_t* offset, uint16_t src) {
  uint16_t original = *offset;
  uint16_t converted = htons(src);
  memcpy(*buf + *offset, &converted, LEN_UINT16);
  *offset += LEN_UINT16;
  return original;
}

uint16_t writePadding(unsigned char** buf, uint16_t* offset, uint16_t numChars) {
  uint16_t original = *offset;
  for (int i = 0; i < numChars; i++)
    (*buf)[*offset + i] = '\0';
  *offset += numChars;
  return original;
}

void xor(unsigned char** src, int srcLen, uint16_t offset, unsigned char* pad, int padLen) {
  int pad_i = 0;
  for (int src_i = offset; src_i < offset + srcLen; src_i++) {
    (*src)[src_i] ^= pad[(pad_i++) % padLen];
  }
}

void printStrBinary(unsigned char* str, int len) {
  for (int i = 0; i < len; i++) {
    for (int j = 0; j < 8; j++) {
      printf("%d", !!((str[i] << j) & 0x80));
    }
    printf(" ");
  }
  printf("\n");
}

int decrypt(ns_key_t* key, unsigned char** buf, size_t bufLen, uint16_t offset, ns_iv_t* iv, size_t ivLen) {
  gcry_cipher_hd_t hd;
  gcry_cipher_open(&hd, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_CBC, 0);
  if (gcry_cipher_setiv(hd, iv, ivLen) != 0)
    return 1;
  gcry_cipher_setkey(hd, key, sizeof(ns_key_t));
  if (gcry_cipher_decrypt(hd, *buf + offset, bufLen, NULL, 0))
    return 1;
  gcry_cipher_close(hd);
  return 0;
}

int encrypt(ns_key_t* key, unsigned char** buf, size_t bufLen, uint16_t offset, ns_iv_t* iv, size_t ivLen) {
  gcry_cipher_hd_t hd;
  gcry_cipher_open(&hd, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_CBC, 0);
  if (gcry_cipher_setiv(hd, iv, ivLen))
    return 1;
  gcry_cipher_setkey(hd, key, sizeof(ns_key_t));
  if (gcry_cipher_encrypt(hd, *buf + offset, bufLen, NULL, 0))
    return 1;
  gcry_cipher_close(hd);
  return 0;
}

uint16_t writeMsgHeader(message_type_t type, uint16_t payloadSize, unsigned char** buf, uint16_t* offset) {
  uint16_t original = *offset;
  uint16_t type_2bytes = (uint16_t)type;
  uint16_t payloadSize_n = htons(payloadSize);
  uint16_t type_2bytes_n = htons(type_2bytes);
  memcpy(*buf + *offset, &payloadSize_n, LEN_MSG_HDR_1);
  memcpy(*buf + *offset + LEN_MSG_HDR_1, &type_2bytes_n, LEN_MSG_HDR_2);
  *offset += LEN_MSG_HDR;
  return original;
}

uint16_t payloadToBufTicket(tkt_req_t* payload, unsigned char** buf, uint16_t* offset) {
  uint16_t original = *offset;
  writeMsgHeader(NS_TKT_REQ, LEN_PAYLOAD_TKT_REQ, buf, offset);
  writeNonce(buf, offset, payload->N1);
  writeBytes(buf, offset, payload->A, LEN_ID);
  writeBytes(buf, offset, payload->B, LEN_ID);
  return original;
}

uint16_t payloadToBufService(svc_req_t* payload, unsigned char** buf, uint16_t* offset, ns_key_t* Kab) {
  uint16_t original = *offset;
  uint16_t prev = 0;

  writeMsgHeader(NS_SVC_REQ, LEN_PAYLOAD_SVC_REQ, buf, offset);
  writeBytes(buf, offset, payload->A, LEN_ID);
  writeBytes(buf, offset, payload->B, LEN_ID);
  writeBytes(buf, offset, payload->ticket.data, payload->ticket.length);

  // WRITE BLOCK HEADER
  ns_iv_t iv;
  getRandomData((char*)iv, LEN_IV);
  writeBytes(buf, offset, iv, LEN_IV);
  writeInt16(buf, offset, LEN_NONCE);

  // WRITE BLOCK
  prev = writeNonce(buf, offset, payload->N2);
  writePadding(buf, offset, LEN_PAYLOAD_SVC_REQ_BLK2_BODY - LEN_NONCE);
  encrypt(Kab, buf, LEN_PAYLOAD_SVC_REQ_BLK2_BODY, prev, &iv, LEN_IV);

  return original;
}

uint16_t payloadToBufAck(svc_ack_t* payload, unsigned char** buf, uint16_t* offset, ns_key_t* Kab) {
  uint16_t original = *offset;
  uint16_t prev = 0;
  writeMsgHeader(NS_SVC_ACK, LEN_PAYLOAD_ACK, buf, offset);

  // WRITE BLOCK HEADER
  ns_iv_t iv;
  getRandomData((char*)iv, LEN_IV);
  writeBytes(buf, offset, iv, LEN_IV);
  writeInt16(buf, offset, LEN_NONCE);

  // WRITE BLOCK
  prev = writeNonce(buf, offset, payload->N3 - 1);
  writePadding(buf, offset, LEN_PAYLOAD_ACK_BLK1_BODY - LEN_NONCE);
  encrypt(Kab, buf, LEN_PAYLOAD_ACK_BLK1_BODY, prev, &iv, LEN_IV);

  return original;
}

uint16_t payloadToBufData(data_container_t* data, unsigned char** buf, uint16_t* offset, ns_key_t* Kab) {
  uint16_t original = *offset;
  uint16_t prev;
  int blockLen = ROUND_TO_AES_BLK_LEN(data->length);
  int payloadSize =\
    LEN_BLK_HDR +\
    blockLen;
  writeMsgHeader(NS_DAT_RES, payloadSize, buf, offset);

  // WRITE BLOCK HEADER
  ns_iv_t iv;
  getRandomData((char*)iv, LEN_IV);
  writeBytes(buf, offset, iv, LEN_IV);
  writeInt16(buf, offset, data->length);

  // WRITE BLOCK
  prev = writeBytes(buf, offset, data->data, data->length);
  writePadding(buf, offset, blockLen - data->length);
  unsigned char mask = DATA_RESP_MASK;
  xor(buf, blockLen, prev, &mask, sizeof(mask));
  encrypt(Kab, buf, blockLen, prev, &iv, LEN_IV);

  return original;
}

int requestTicket(int sock, tkt_req_t* payload) {
  logMessage(LOG_INFO_LEVEL, "Handling ticket request...");
  unsigned char* buf = malloc(NS_MAX_XMIT_SIZE);
  uint16_t offset = 0;

  // PREPARE PAYLOAD
  ns_nonce_t nonce;
  createNonce(&nonce);
  payload->N1 = nonce;
  logMessage(LOG_INFO_LEVEL, "N1: %ld", nonce);
  ns_id_t A = NS_ALICE_IDENTITY;
  ns_id_t B = NS_BOB_IDENTITY;
  memcpy(&(payload->A), &A, LEN_ID);
  memcpy(&(payload->B), &B, LEN_ID);

  // PAYLOAD TO REQUEST
  payloadToBufTicket(payload, &buf, &offset);

  // SEND REQUEST
  cmpsc311_send_bytes(sock, offset, buf);
  free(buf);
  return 0;
}

int receiveTicket(int sock, tkt_res_t* tktRes, tkt_req_t* tktReq) {
  logMessage(LOG_INFO_LEVEL, "Handling ticket response...");
  unsigned char* buf = malloc(NS_MAX_XMIT_SIZE);
  uint16_t offset = 0;

  // READ DATA
  cmpsc311_read_bytes(sock, LEN_MSG_HDR + LEN_PAYLOAD_TKT_RES, buf + offset);

  // READ MSG HEADER
  msg_header_t msgHeader;
  readMsgHeader(&buf, &offset, &msgHeader);

  // READ BLOCK HEADER
  block_header_t blockHeader;
  readBlockHeader(&buf, &offset, &blockHeader);

  // DECRYPT BLOCK
  ns_key_t key;
  makeKeyFromPassword(NS_ALICE_PASSWORD, key);
  decrypt(&key, &buf, LEN_PAYLOAD_TKT_RES_BLK1_BODY, offset, &(blockHeader.iv), LEN_IV);

  // GET DATA
  readNonce(&buf, &offset, &(tktRes->N1));

  if (checkNonce(tktRes->N1, tktReq->N1) != 0) return 1;
  readIdentity(&buf, &offset, &(tktRes->B));
  readKey(&buf, &offset, &(tktRes->Kab));

  tktRes->ticket.length = msgHeader.size - offset;
  readBytes(&buf, &offset, tktRes->ticket.data, tktRes->ticket.length);
  free(buf);
  return 0;
}

int requestService(int sock, svc_req_t* payload, tkt_res_t* tktRes) {
  logMessage(LOG_INFO_LEVEL, "Handling service request...");
  unsigned char* buf = malloc(NS_MAX_XMIT_SIZE);
  uint16_t offset = 0;

  // MAKE PAYLOAD
  ns_id_t A = NS_ALICE_IDENTITY;
  ns_id_t B = NS_BOB_IDENTITY;
  memcpy(&(payload->A), &A, LEN_ID);
  memcpy(&(payload->B), &B, LEN_ID);
  memcpy(&(payload->ticket), &(tktRes->ticket), sizeof(tktRes->ticket));
  ns_nonce_t nonce;
  createNonce(&nonce);
  memcpy(&(payload->N2), &nonce, LEN_NONCE);
  logMessage(LOG_INFO_LEVEL, "N2: %ld", nonce);

  // PAYLOAD TO REQUEST
  payloadToBufService(payload, &buf, &offset, &(tktRes->Kab));

  // SEND REQUEST
  cmpsc311_send_bytes(sock, offset, buf);

  free(buf);
  return 0;
}

int receiveService(int sock, svc_res_t* svcRes, svc_req_t* svcReq, tkt_res_t* tktRes) {
  logMessage(LOG_INFO_LEVEL, "Handling service response...");
  unsigned char* buf = malloc(NS_MAX_XMIT_SIZE);
  uint16_t offset = 0;

  // READ DATA
  cmpsc311_read_bytes(sock, LEN_MSG_HDR + LEN_PAYLOAD_SVC_RES, buf + offset);

  // READ HEADER
  msg_header_t msgHeader;
  readMsgHeader(&buf, &offset, &msgHeader);

  // READ BLOCK HEADER
  block_header_t blockHeader;
  readBlockHeader(&buf, &offset, &blockHeader);

  // DECRYPT BLOCK
  decrypt(&(tktRes->Kab), &buf, LEN_PAYLOAD_SVC_RES_BLK1_BODY, offset, &(blockHeader.iv), LEN_IV);

  // GET DATA
  readNonce(&buf, &offset, &(svcRes->N2));
  readNonce(&buf, &offset, &(svcRes->N3));
  svcRes->N2 += 1;
  if (checkNonce(svcReq->N2, svcRes->N2) != 0) return 1;

  free(buf);
  return 0;
}

int sendAck(int sock, svc_ack_t* payload, svc_res_t* svcRes, tkt_res_t* tktRes) {
  logMessage(LOG_INFO_LEVEL, "Handling ack...");
  unsigned char* buf = malloc(NS_MAX_XMIT_SIZE);
  uint16_t offset = 0;

  payload->N3 = svcRes->N3;
  payloadToBufAck(payload, &buf, &offset, &(tktRes->Kab));

  cmpsc311_send_bytes(sock, offset, buf);

  free(buf);
  return 0;
}

int receiveData(int sock, data_container_t* data, tkt_res_t* tktRes) {
  logMessage(LOG_INFO_LEVEL, "Handling data request...");
  unsigned char* buf = malloc(NS_MAX_XMIT_SIZE);  // ASSUMPTION: data length does not exceed NS_MAX_XMIT_SIZE
  uint16_t offset = 0;

  // READ MSG HEADER
  cmpsc311_read_bytes(sock, LEN_MSG_HDR, buf + offset);
  msg_header_t msgHeader;
  readMsgHeader(&buf, &offset, &msgHeader);
  cmpsc311_read_bytes(sock, msgHeader.size, buf + offset);

  // READ AND DECEYPT BLOCK HEADER
  block_header_t blockHeader;
  readBlockHeader(&buf, &offset, &blockHeader);
  decrypt(&(tktRes->Kab), &buf, blockHeader.size, offset, &(blockHeader.iv), LEN_IV);

  // FILL DATA TO STRUCT
  memcpy(&(data->data), buf + offset, blockHeader.size);
  data->length = blockHeader.size;

  free(buf);
  return 0;
}

int respondData(int sock, data_container_t* data, tkt_res_t* tktRes) {
  logMessage(LOG_INFO_LEVEL, "Handling data response...");
  unsigned char* buf = malloc(NS_MAX_XMIT_SIZE);
  uint16_t offset = 0;
  payloadToBufData(data, &buf, &offset, &(tktRes->Kab));
  cmpsc311_send_bytes(sock, offset, buf);
  free(buf);
  return 0;
}

int receiveFin(int sock) {
  unsigned char* buf = malloc(NS_MAX_XMIT_SIZE);
  cmpsc311_read_bytes(sock, LEN_MSG_HDR, buf);
  return 0;
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : main
// Description  : The main function for the Needam Schroeder protocol client
//
// Inputs       : argc - the number of command line parameters
//                argv - the parameters
// Outputs      : 0 if successful, -1 if failure

int main( int argc, char *argv[] )
{
	// Local variables
	int ch;

	// Process the command line parameters
	while ((ch = getopt(argc, argv, NS_ARGUMENTS)) != -1) {

		switch (ch) {
		case 'h': // Help, print usage
			fprintf( stderr, USAGE );
			return( -1 );

		default:  // Default (unknown)
			fprintf( stderr, "Unknown command line option (%c), aborting.\n", ch );
			return( -1 );
		}
	}

	// Create the log, run the client
    initializeLogWithFilehandle(STDERR_FILENO);
    enableLogLevels(LOG_INFO_LEVEL);
	ns_client();

	// Return successfully
	return( 0 );
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : ns_client
// Description  : The client function for the Needam Schroeder protocol server
//
// Inputs       : none
// Outputs      : 0 if successful, -1 if failure

int ns_client( void ) {
  char* LOCAL_HOST = "127.0.0.1";
  int sock = cmpsc311_client_connect(LOCAL_HOST, NS_SERVER_PROTOCOL_PORT);

  tkt_req_t tktReq;
  tkt_res_t tktRes;
  svc_req_t svcReq;
  svc_res_t svcRes;
  svc_ack_t svcAck;
  data_container_t data;

  if (requestTicket(sock, &tktReq) != 0) return 1;
  if (receiveTicket(sock, &tktRes, &tktReq) != 0) return 1;
  if (requestService(sock, &svcReq, &tktRes) != 0) return 1;
  if (receiveService(sock, &svcRes, &svcReq, &tktRes) != 0) return 1;
  if (sendAck(sock, &svcAck, &svcRes, &tktRes) != 0) return 1;
  if (receiveData(sock, &data, &tktRes) != 0) return 1;
  if (respondData(sock, &data, &tktRes) != 0) return 1;
  if (receiveFin(sock) != 0) return 1;

  cmpsc311_close(sock);
  return(0);
}
