/**
 * @file protocol.c
 * @brief Protocol implementation for Seed reverse proxy
 * @author Seed Development Team
 * @date 2025
 */

#include "protocol.h"
#include "log.h"
#include <time.h>

/** Static sequence counter */
static uint32_t g_sequence = 0;

/** Message type names for debugging */
static const char *message_type_names[] = {
    "UNKNOWN",
    "HELLO",
    "AUTH_REQUEST",
    "AUTH_RESPONSE",
    "PROXY_REQUEST",
    "PROXY_RESPONSE",
    "PROXY_CLOSE",
    "KEEPALIVE",
    "ERROR",
    "DATA_FORWARD",
    "DATA_BACKWARD"
};

/**
 * @brief Simple CRC32 checksum implementation
 *
 * @param[in] data  Data to checksum
 * @param[in] len   Data length
 *
 * @return CRC32 checksum
 */
static uint32_t crc32(const uint8_t *data, size_t len)
{
    uint32_t crc = 0xFFFFFFFF;
    static uint32_t crc_table[256] = {0};
    
    /* Generate CRC table if not already done */
    if (crc_table[1] == 0) {
        for (int i = 0; i < 256; i++) {
            uint32_t c = i;
            for (int j = 0; j < 8; j++) {
                if (c & 1) {
                    c = 0xEDB88320 ^ (c >> 1);
                } else {
                    c = c >> 1;
                }
            }
            crc_table[i] = c;
        }
    }
    
    /* Calculate CRC */
    for (size_t i = 0; i < len; i++) {
        crc = crc_table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
    }
    
    return crc ^ 0xFFFFFFFF;
}

/**
 * @brief Initialize protocol message
 *
 * @param[out] msg   Message to initialize
 * @param[in]  type  Message type
 */
void protocol_init_message(struct protocol_message *msg, enum message_type type)
{
    if (!msg) return;
    
    memset(msg, 0, sizeof(struct protocol_message));
    
    /* Initialize header */
    msg->header.magic = PROTOCOL_MAGIC;
    msg->header.version = PROTOCOL_VERSION;
    msg->header.type = (uint16_t)type;
    msg->header.flags = MSG_FLAG_NONE;
    msg->header.sequence = ++g_sequence;
    msg->header.length = 0;
    msg->header.checksum = 0; /* Will be calculated later */
}

/**
 * @brief Calculate header checksum
 *
 * @param[in] header  Protocol header
 *
 * @return Calculated checksum
 */
uint32_t protocol_checksum(const struct protocol_header *header)
{
    if (!header) return 0;
    
    /* Calculate checksum of header excluding the checksum field */
    struct protocol_header temp = *header;
    temp.checksum = 0;
    
    return crc32((const uint8_t *)&temp, sizeof(temp));
}

/**
 * @brief Validate protocol message
 *
 * @param[in] msg  Message to validate
 *
 * @return 0 if valid, negative error code if invalid
 */
int protocol_validate_message(const struct protocol_message *msg)
{
    if (!msg) {
        return SEED_ERROR_INVALID_ARGS;
    }
    
    /* Check magic number */
    if (msg->header.magic != PROTOCOL_MAGIC) {
        log_error("Invalid protocol magic: 0x%08X", msg->header.magic);
        return SEED_ERROR_PROTOCOL;
    }
    
    /* Check version */
    if (msg->header.version != PROTOCOL_VERSION) {
        log_error("Unsupported protocol version: %d", msg->header.version);
        return SEED_ERROR_PROTOCOL;
    }
    
    /* Check message type */
    if (msg->header.type >= MSG_TYPE_MAX) {
        log_error("Invalid message type: %d", msg->header.type);
        return SEED_ERROR_PROTOCOL;
    }
    
    /* Check payload length */
    if (msg->header.length > MAX_MESSAGE_SIZE) {
        log_error("Message too large: %u bytes", msg->header.length);
        return SEED_ERROR_PROTOCOL;
    }
    
    /* Verify checksum */
    uint32_t calculated_checksum = protocol_checksum(&msg->header);
    if (calculated_checksum != msg->header.checksum) {
        log_error("Checksum mismatch: expected 0x%08X, got 0x%08X",
                  calculated_checksum, msg->header.checksum);
        return SEED_ERROR_PROTOCOL;
    }
    
    return SEED_OK;
}

/**
 * @brief Get payload size for message type
 *
 * @param[in] type  Message type
 *
 * @return Payload size in bytes
 */
static size_t get_payload_size(enum message_type type)
{
    switch (type) {
    case MSG_TYPE_HELLO:
        return sizeof(struct msg_hello);
    case MSG_TYPE_AUTH_REQUEST:
        return sizeof(struct msg_auth_request);
    case MSG_TYPE_AUTH_RESPONSE:
        return sizeof(struct msg_auth_response);
    case MSG_TYPE_PROXY_REQUEST:
        return sizeof(struct msg_proxy_request);
    case MSG_TYPE_PROXY_RESPONSE:
        return sizeof(struct msg_proxy_response);
    case MSG_TYPE_DATA_FORWARD:
    case MSG_TYPE_DATA_BACKWARD:
        return sizeof(struct msg_data);
    case MSG_TYPE_ERROR:
        return sizeof(struct msg_error);
    case MSG_TYPE_KEEPALIVE:
    case MSG_TYPE_PROXY_CLOSE:
        return 0; /* No payload */
    default:
        return 0;
    }
}

/**
 * @brief Serialize message to buffer
 *
 * @param[in]  msg     Message to serialize
 * @param[out] buffer  Output buffer
 * @param[in]  buflen  Buffer length
 *
 * @return Number of bytes written, or negative error code
 */
int protocol_serialize(const struct protocol_message *msg, uint8_t *buffer, size_t buflen)
{
    size_t payload_size;
    size_t total_size;
    struct protocol_header header_copy;
    
    if (!msg || !buffer) {
        return SEED_ERROR_INVALID_ARGS;
    }
    
    /* Determine payload size */
    if (msg->header.type == MSG_TYPE_DATA_FORWARD || msg->header.type == MSG_TYPE_DATA_BACKWARD) {
        payload_size = sizeof(struct msg_data) + msg->payload.data.data_length;
    } else {
        payload_size = get_payload_size((enum message_type)msg->header.type);
    }
    
    total_size = sizeof(struct protocol_header) + payload_size;
    
    /* Check buffer size */
    if (buflen < total_size) {
        log_error("Buffer too small: need %zu bytes, have %zu", total_size, buflen);
        return SEED_ERROR_INVALID_ARGS;
    }
    
    /* Prepare header with correct length and checksum */
    header_copy = msg->header;
    header_copy.length = (uint32_t)payload_size;
    header_copy.checksum = protocol_checksum(&header_copy);
    
    /* Copy header to buffer */
    memcpy(buffer, &header_copy, sizeof(struct protocol_header));
    
    /* Copy payload to buffer */
    if (payload_size > 0) {
        if (msg->header.type == MSG_TYPE_DATA_FORWARD || msg->header.type == MSG_TYPE_DATA_BACKWARD) {
            /* Copy data message header */
            memcpy(buffer + sizeof(struct protocol_header), &msg->payload.data, sizeof(struct msg_data));
            /* Data payload would follow, but it's handled separately in actual implementation */
        } else {
            memcpy(buffer + sizeof(struct protocol_header), &msg->payload, payload_size);
        }
    }
    
    log_debug("Serialized %s message: %zu bytes", 
              protocol_type_name((enum message_type)msg->header.type), total_size);
    
    return (int)total_size;
}

/**
 * @brief Deserialize message from buffer
 *
 * @param[out] msg     Message to fill
 * @param[in]  buffer  Input buffer
 * @param[in]  buflen  Buffer length
 *
 * @return Number of bytes consumed, or negative error code
 */
int protocol_deserialize(struct protocol_message *msg, const uint8_t *buffer, size_t buflen)
{
    size_t total_size;
    int result;
    
    if (!msg || !buffer) {
        return SEED_ERROR_INVALID_ARGS;
    }
    
    /* Check minimum size for header */
    if (buflen < sizeof(struct protocol_header)) {
        return SEED_ERROR_PROTOCOL;
    }
    
    /* Copy header */
    memcpy(&msg->header, buffer, sizeof(struct protocol_header));
    
    /* Validate header */
    result = protocol_validate_message(msg);
    if (result != SEED_OK) {
        return result;
    }
    
    total_size = sizeof(struct protocol_header) + msg->header.length;
    
    /* Check if we have complete message */
    if (buflen < total_size) {
        return SEED_ERROR_PROTOCOL;
    }
    
    /* Copy payload */
    if (msg->header.length > 0) {
        memcpy(&msg->payload, buffer + sizeof(struct protocol_header), msg->header.length);
    }
    
    log_debug("Deserialized %s message: %zu bytes", 
              protocol_type_name((enum message_type)msg->header.type), total_size);
    
    return (int)total_size;
}

/**
 * @brief Get message type name
 *
 * @param[in] type  Message type
 *
 * @return String name of message type
 */
const char *protocol_type_name(enum message_type type)
{
    if (type < MSG_TYPE_MAX) {
        return message_type_names[type];
    }
    return "INVALID";
}