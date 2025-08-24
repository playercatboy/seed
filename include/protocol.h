/**
 * @file protocol.h
 * @brief Protocol definitions for Seed reverse proxy
 * @author Seed Development Team
 * @date 2025
 */

#ifndef PROTOCOL_H
#define PROTOCOL_H

#include "common.h"

/** Protocol version */
#define PROTOCOL_VERSION 1

/** Protocol magic number */
#define PROTOCOL_MAGIC 0x5345454D /* "SEEM" */

/** Maximum message size */
#define MAX_MESSAGE_SIZE 65536

/** Message types */
enum message_type {
    MSG_TYPE_UNKNOWN = 0,
    
    /* Control messages */
    MSG_TYPE_HELLO,          /** Initial handshake */
    MSG_TYPE_AUTH_REQUEST,   /** Authentication request */
    MSG_TYPE_AUTH_RESPONSE,  /** Authentication response */
    MSG_TYPE_PROXY_REQUEST,  /** Request to create proxy */
    MSG_TYPE_PROXY_RESPONSE, /** Response to proxy request */
    MSG_TYPE_PROXY_CLOSE,    /** Close proxy connection */
    MSG_TYPE_KEEPALIVE,      /** Keep connection alive */
    MSG_TYPE_ERROR,          /** Error message */
    
    /* Data messages */
    MSG_TYPE_DATA_FORWARD,   /** Forward data */
    MSG_TYPE_DATA_BACKWARD,  /** Backward data */
    
    MSG_TYPE_MAX
};

/** Message flags */
enum message_flags {
    MSG_FLAG_NONE = 0x00,
    MSG_FLAG_COMPRESSED = 0x01,  /** Message is compressed */
    MSG_FLAG_ENCRYPTED = 0x02,   /** Message is encrypted */
    MSG_FLAG_FRAGMENTED = 0x04,  /** Message is fragmented */
    MSG_FLAG_FINAL = 0x08         /** Final fragment */
};

/** Protocol message header */
struct protocol_header {
    uint32_t magic;          /** Magic number */
    uint16_t version;        /** Protocol version */
    uint16_t type;           /** Message type */
    uint32_t flags;          /** Message flags */
    uint32_t sequence;       /** Sequence number */
    uint32_t length;         /** Payload length */
    uint32_t checksum;       /** Header checksum */
} PACKED_STRUCT_ATTR;

/** Hello message */
struct msg_hello {
    uint32_t protocol_version;  /** Protocol version */
    char client_id[64];         /** Client identifier */
    uint32_t capabilities;      /** Client capabilities */
} PACKED_STRUCT_ATTR;

/** Authentication request */
struct msg_auth_request {
    char username[64];          /** Username */
    char password[128];         /** Password or token */
} PACKED_STRUCT_ATTR;

/** Authentication response */
struct msg_auth_response {
    uint32_t status;            /** 0 = success, non-zero = error */
    char message[256];          /** Response message */
    char session_token[256];    /** Session token if successful */
} PACKED_STRUCT_ATTR;

/** Proxy request */
struct msg_proxy_request {
    char proxy_name[64];        /** Proxy instance name */
    uint16_t proxy_type;        /** TCP or UDP */
    uint16_t local_port;        /** Local port */
    uint16_t remote_port;       /** Remote port to bind */
    uint16_t encrypt_type;      /** Encryption type */
    char local_addr[16];        /** Local address */
} PACKED_STRUCT_ATTR;

/** Proxy response */
struct msg_proxy_response {
    uint32_t status;            /** 0 = success, non-zero = error */
    char proxy_id[64];          /** Assigned proxy ID */
    uint16_t assigned_port;     /** Actually assigned port */
    char message[256];          /** Response message */
} PACKED_STRUCT_ATTR;
PACKED_STRUCT_END

/** Data forward/backward message */
PACKED_STRUCT_BEGIN
struct msg_data {
    char proxy_id[64];          /** Proxy ID */
    uint32_t connection_id;     /** Connection identifier */
    uint32_t data_length;       /** Data length */
    /* Followed by actual data */
} PACKED_STRUCT_ATTR;
PACKED_STRUCT_END

/** Error message */
PACKED_STRUCT_BEGIN
struct msg_error {
    uint32_t error_code;        /** Error code */
    char message[256];          /** Error message */
} PACKED_STRUCT_ATTR;
PACKED_STRUCT_END

/** Protocol message structure */
struct protocol_message {
    struct protocol_header header;  /** Message header */
    union {
        struct msg_hello hello;
        struct msg_auth_request auth_req;
        struct msg_auth_response auth_resp;
        struct msg_proxy_request proxy_req;
        struct msg_proxy_response proxy_resp;
        struct msg_data data;
        struct msg_error error;
        uint8_t raw[MAX_MESSAGE_SIZE];  /** Raw payload */
    } payload;
};

/**
 * @brief Initialize protocol message
 *
 * @param[out] msg   Message to initialize
 * @param[in]  type  Message type
 */
void protocol_init_message(struct protocol_message *msg, enum message_type type);

/**
 * @brief Calculate header checksum
 *
 * @param[in] header  Protocol header
 *
 * @return Calculated checksum
 */
uint32_t protocol_checksum(const struct protocol_header *header);

/**
 * @brief Validate protocol message
 *
 * @param[in] msg  Message to validate
 *
 * @return 0 if valid, negative error code if invalid
 */
int protocol_validate_message(const struct protocol_message *msg);

/**
 * @brief Serialize message to buffer
 *
 * @param[in]  msg     Message to serialize
 * @param[out] buffer  Output buffer
 * @param[in]  buflen  Buffer length
 *
 * @return Number of bytes written, or negative error code
 */
int protocol_serialize(const struct protocol_message *msg, uint8_t *buffer, size_t buflen);

/**
 * @brief Deserialize message from buffer
 *
 * @param[out] msg     Message to fill
 * @param[in]  buffer  Input buffer
 * @param[in]  buflen  Buffer length
 *
 * @return Number of bytes consumed, or negative error code
 */
int protocol_deserialize(struct protocol_message *msg, const uint8_t *buffer, size_t buflen);

/**
 * @brief Get message type name
 *
 * @param[in] type  Message type
 *
 * @return String name of message type
 */
const char *protocol_type_name(enum message_type type);

#endif /* PROTOCOL_H */