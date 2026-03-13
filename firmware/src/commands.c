/**
 * @file commands.c
 * @author Samuel Meyers
 * @brief eCTF command handlers
 * @date 2026
 *
 * This source file is part of an example system for MITRE's 2026 Embedded CTF (eCTF).
 * This code is being provided only for educational purposes for the 2026 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2026 The MITRE Corporation
 */

#include "host_messaging.h"
#include "commands.h"
#include "filesystem.h"
#include "rng.h"
#include "secrets.h"
#include "simple_crypto.h"
#include <string.h>



/* IMPORTANT COMPONENTS FROM HSM.c */
// extern file_t hsm_status[MAX_FILE_COUNT];
static union {
    file_t file;
    read_response_t resp;
    receive_response_t recv_resp;
} shared_buffer;

#define current_file (shared_buffer.file)
#define global_file_info (shared_buffer.resp)
#define current_recv_resp (shared_buffer.recv_resp)

/**********************************************************
 ******************** HELPER FUNCTIONS ********************
 **********************************************************/

/** @brief List out the files on the system.
 *      To be utilized by list and interrogate
 *
 *  @param file_list A pointer to the list_response_t variable in
 *      which to store the results
 */
void generate_list_files(list_response_t *file_list) {
    file_list->n_files = 0;
    static file_t temp_file;

    // Loop through all files on the system
    for (uint8_t i = 0; i < MAX_FILE_COUNT; i++) {
        // Check if the file is in use
        if (is_slot_in_use(i)) {
            read_file(i, &temp_file);

            file_list->metadata[file_list->n_files].slot = i;
            file_list->metadata[file_list->n_files].group_id = temp_file.group_id;

            // strncpy is used here to prevent potential buffer overflow if temp_file.name is not null-terminated
            strncpy(file_list->metadata[file_list->n_files].name, (char *)&temp_file.name, MAX_NAME_SIZE - 1);
            // Ensure null termination in case temp_file.name is not properly null-terminated
            file_list->metadata[file_list->n_files].name[MAX_NAME_SIZE - 1] = '\0';
            file_list->n_files++;
        }
    }
}


/**********************************************************
 ******************** COMMAND HANDLERS ********************
 **********************************************************/

/** @brief Perform the list operation
 *
 *  @param pkt_len The length of the incoming packet
 *  @param buf A pointer the incoming message buffer
 *
 * @return 0 upon success. A negative value on error.
*/
int list(uint16_t pkt_len, uint8_t *buf) {
    list_command_t *command = (list_command_t*)buf;
    list_response_t file_list;

    if (!check_pin(command->pin)) {
        print_error("Invalid pin");
        return -1;
    }

    memset(&file_list, 0, sizeof(file_list));

    // copy relevant fields into the final struct
    generate_list_files(&file_list);

    // write success packet with list
    pkt_len_t length = LIST_PKT_LEN(file_list.n_files);
    write_packet(CONTROL_INTERFACE, LIST_MSG, &file_list, length);
    return 0;
}


/** @brief Perform the read operation
 *
 *  @param pkt_len The length of the incoming packet
 *  @param buf A pointer the incoming message buffer
 *
 * @return 0 upon success. A negative value on error.
*/
int read(uint16_t pkt_len, uint8_t *buf) {
    if (pkt_len < sizeof(read_command_t)) {
        print_error("Packet too short");
        return -1;
    }

    // Extract what we need from the incoming command
    read_command_t *command = (read_command_t*)buf;
    uint16_t target_slot = command->slot; // Save this before we overwrite buf!

    if (target_slot >= MAX_FILE_COUNT) {
        print_error("Invalid slot");
        return -1;
    }

    if (!check_pin(command->pin)) {
        print_error("Invalid pin");
        return -1;
    }

    // Read the encrypted file from flash into the global current_file
    if (read_file(target_slot, &current_file) < 0) {
        print_error("Failed to read file");
        return -1;
    }

    if (!validate_permission(current_file.group_id, PERM_READ)) {
        print_error("Invalid permission");
        return -1;
    }

    // Cast the incoming 'buf' to our response type and clear it
    read_response_t *resp = (read_response_t*)buf;
    memset(resp, 0, sizeof(read_response_t));

    // Decrypt from current_file into the freshly cleared UART buffer
    if (decrypt_sym(current_file.contents, current_file.contents_len,
                    AES_KEY_TABLE[target_slot], current_file.nonce,
                    resp->contents, current_file.tag) != 0) {
        delay_ms(4000);
        print_error("Decryption failed");
        return -1;
    }

    // Copy the name into the response
    memcpy(resp->name, current_file.name, MAX_NAME_SIZE);

    // Write the packet back to the host
    pkt_len_t length = MAX_NAME_SIZE + current_file.contents_len;
    write_packet(CONTROL_INTERFACE, READ_MSG, resp, length);

    return 0;
}


/** @brief Perform the write operation
 *
 *  @param pkt_len The length of the incoming packet
 *  @param buf A pointer the incoming message buffer
 *
 * @return 0 upon success. A negative value on error.
*/
int write(uint16_t pkt_len, uint8_t *buf) {
    size_t min_expected_len = sizeof(write_command_t) - MAX_CONTENTS_SIZE;

    if (pkt_len < min_expected_len) {
        print_error("Packet too short");
        return -1;
    }
    
    write_command_t *command = (write_command_t*)buf;

    if (!check_pin(command->pin)) {
        print_error("Invalid pin");
        return -1;
    }

    if (!validate_permission(command->group_id, PERM_WRITE)) {
        print_error("Invalid permission");
        return -1;
    }

    if (command->contents_len > MAX_CONTENTS_SIZE) {
        print_error("File too large");
        return -1;
    }

    if (command->slot >= MAX_FILE_COUNT) {
        print_error("Invalid slot");
        return -1;
    }

    // This safely zeros out the structure without destroying our ciphertext.
    create_file(
        &current_file,
        command->group_id,
        command->name,
        command->contents_len,
        NULL  
    );

    uint8_t nonce[NONCE_SIZE];
    uint8_t tag[TAG_SIZE];
    generate_nonce(nonce, NONCE_SIZE);

    if (encrypt_sym(command->contents, command->contents_len, 
                    AES_KEY_TABLE[command->slot], nonce, 
                    current_file.contents, tag) != 0) {
        print_error("Encryption failed");
        return -1;
    }

    // Store the crypto metadata
    memcpy(current_file.nonce, nonce, NONCE_SIZE);
    memcpy(current_file.tag, tag, TAG_SIZE);

    // Write to flash
    if (write_file(command->slot, &current_file, command->uuid) < 0) {
        print_error("Error storing file");
        return -1;
    }

    write_packet(CONTROL_INTERFACE, WRITE_MSG, NULL, 0);
    return 0;
}

/**
 * @brief One-way authentication: the listener proves its identity to the receiver.
 *
 * Listener side: generates a nonce, signs it, sends {HSM_ID, nonce, sig}.
 * Receiver side: reads the announcement and verifies the signature.
 *
 * @param is_listener  1 = listener (sends announcement), 0 = receiver (verifies)
 * @return 0 on success, -1 on failure
 */
static int perform_auth(int is_listener)
{
    auth_announce_t ann;
    msg_type_t      cmd;
    uint16_t        msg_len;
    int             ret;

    if (is_listener) {
        if (HSM_ID >= 8) {
            print_error("Auth: invalid local HSM ID\n");
            return -1;
        }

        ann.hsm_id = HSM_ID;
        generate_nonce(ann.nonce, CHALLENGE_SIZE);

        ret = ed25519_sign(ann.nonce, CHALLENGE_SIZE,
                           ED25519_PRIV_KEY, ED25519_PUB_KEYS[HSM_ID],
                           ann.sig);
        if (ret != 0) {
            print_error("Auth: signing failed\n");
            return -1;
        }

        write_packet(TRANSFER_INTERFACE, AUTH_MSG, &ann, sizeof(auth_announce_t));
        return 0;

    } else {
        msg_len = sizeof(auth_announce_t);
        ret = read_packet(TRANSFER_INTERFACE, &cmd, &ann, &msg_len);
        if (ret != MSG_OK || cmd != AUTH_MSG) {
            print_error("Auth: bad announcement from listener\n");
            return -1;
        }

        if (ann.hsm_id >= 8) {
            print_error("Auth: invalid listener HSM ID\n");
            return -1;
        }

        ret = ed25519_verify(ann.nonce, CHALLENGE_SIZE,
                             ann.sig,
                             ED25519_PUB_KEYS[ann.hsm_id]);
        if (ret != 0) {
            print_error("Auth: listener signature invalid\n");
            return -1;
        }

        return 0;
    }
}

/** @brief Perform the receive operation
 *
 *  @param pkt_len The length of the incoming packet
 *  @param buf A pointer the incoming message buffer
 *
 * @return 0 upon success. A negative value on error.
*/
int receive(uint16_t pkt_len, uint8_t *buf) {
    receive_command_t *command = (receive_command_t *)buf;
    receive_request_t request;
    msg_type_t cmd;
    uint16_t len_recv_msg;

    if (!check_pin(command->pin)) {
        print_error("Invalid pin");
        return -1;
    }

    if (command->read_slot >= MAX_FILE_COUNT || command->write_slot >= MAX_FILE_COUNT) {
        print_error("Invalid slot");
        return -1;
    }

    memset(&current_recv_resp, 0, sizeof(current_recv_resp));
    memset(&request, 0, sizeof(request));

    request.slot = command->read_slot;
    memcpy(&request.permissions, &global_permissions,
           sizeof(group_permission_t) * MAX_PERMS);

    // Send the receive request first — this triggers auth on the listener side
    if (write_packet(TRANSFER_INTERFACE, RECEIVE_MSG, (void *)&request, sizeof(receive_request_t)) != MSG_OK) {
        print_error("Failed to send request to neighbor");
        return -1;
    }

    // Verify the listener's identity before accepting any file data
    if (perform_auth(0) != 0) {
        print_error("Auth failed");
        return -1;
    }

    len_recv_msg = 0xffff;

    // recieve the response message
    if (read_packet(TRANSFER_INTERFACE, &cmd, &current_recv_resp, &len_recv_msg) != MSG_OK) {
        print_error("Failed to receive response from neighbor");
        return -1;
    }
    if (cmd != RECEIVE_MSG) {
        print_error("Opcode mismatch");
        return -1;
    }

    // check permissions on the received file
    if (!validate_permission(current_recv_resp.file.group_id, PERM_RECEIVE)) {
        print_error("Invalid receive permission");
        return -1;
    }

    // write that file into the file system
    if (write_file(command->write_slot, &current_recv_resp.file, current_recv_resp.uuid) < 0) {
        print_error("Writing received file failed");
        return -1;
    }

    write_packet(CONTROL_INTERFACE, RECEIVE_MSG, NULL, 0);
    return 0;
}


/** @brief Perform the interrogate operation
 *
 *  @param pkt_len The length of the incoming packet
 *  @param buf A pointer to the incoming message buffer
 *
 * @return 0 upon success. A negative value on error.
 */
int interrogate(uint16_t pkt_len, uint8_t *buf) {
    interrogate_command_t *command = (interrogate_command_t*)buf;
    msg_type_t cmd;
    list_response_t final_list_buf;
    uint16_t len_recv_msg;

    // pin check
    if (!check_pin(command->pin)) {
        print_error("Invalid pin");
        return -1;
    }

    // request the file list from the neighboring device
    write_packet(TRANSFER_INTERFACE, INTERROGATE_MSG, NULL, 0);

    // set essentially no limit to the receive message size
    len_recv_msg = 0xffff;

    // recieve the response message
    if (read_packet(TRANSFER_INTERFACE, &cmd, &final_list_buf, &len_recv_msg) != MSG_OK) {
        print_error("Failed to receive interrogate response");
        return -1;
    }
    if (cmd != INTERROGATE_MSG) {
        print_error("Opcode mismatch");
        return -1;
    }
    if (final_list_buf.n_files > MAX_FILE_COUNT) {
        print_error("Neighbor sent invalid file count");
        return -1;
    }

    // filter the list based on what we have permissions to receive
    list_response_t filtered_list;
    // zero out the filtered list
    memset(&filtered_list, 0, sizeof(filtered_list));

    // loop through the received list and apply our local permissions to filter it
    for (uint32_t i = 0; i < final_list_buf.n_files; i++) {
        group_id_t group_id = final_list_buf.metadata[i].group_id;

        // local permission to receive this group
        if (validate_permission(group_id, PERM_RECEIVE)) {
            filtered_list.metadata[filtered_list.n_files] = final_list_buf.metadata[i];
            filtered_list.n_files++;
        }
    }

    // Return only allowed files 
    pkt_len_t length = LIST_PKT_LEN(filtered_list.n_files);

    // return the final list to the user
    write_packet(CONTROL_INTERFACE, INTERROGATE_MSG, &filtered_list, length);
    return 0;
}

/** @brief Perform the listen operation
 *
 * @return 0 upon success. A negative value on error.
*/
int listen(uint16_t pkt_len, uint8_t *buf) {
    uint8_t uart_buf[sizeof(receive_request_t)];
    msg_type_t cmd;
    pkt_len_t write_length, read_length;
    list_response_t file_list;
    receive_request_t *command;
    const filesystem_entry_t *metadata;

    read_length = sizeof(uart_buf);
    memset(uart_buf, 0, sizeof(uart_buf));

    // Read first packet from neighbor
    read_packet(TRANSFER_INTERFACE, &cmd, uart_buf, &read_length);

    // INTERROGATE_MSG needs no auth; RECEIVE_MSG triggers listener-initiated auth below
    switch (cmd) {
        case INTERROGATE_MSG:
            memset(&file_list, 0, sizeof(file_list));
            generate_list_files(&file_list);

            // send the list of files on this device
            write_length = LIST_PKT_LEN(file_list.n_files);
            write_packet(TRANSFER_INTERFACE, INTERROGATE_MSG, &file_list, write_length);
            break;

        case RECEIVE_MSG:
            command = (receive_request_t *)uart_buf;

            // Prove our identity to the receiver before sending any file data
            if (perform_auth(1) != 0) {
                print_error("Auth failed in listen");
                return -1;
            }

            memset(&current_recv_resp, 0, sizeof(current_recv_resp));

            if (read_file(command->slot, &current_recv_resp.file) < 0) {
                print_error("Failed to read file");
                write_packet(TRANSFER_INTERFACE, ERROR_MSG, "read failed", 11);
                return -1;
            }
            group_id_t group_id = current_recv_resp.file.group_id;

            // check remote permissions
            bool allowed = false;

            // loop through the permissions sent by the neighbor and see if any match our group_id with receive permissions
            for (int i = 0; i < MAX_PERMS; i++) {
                if (command->permissions[i].group_id == group_id &&
                    command->permissions[i].receive) {
                    allowed = true;
                    break;
                }
            }
            
            if (!allowed) {
                print_error("neighbor HSM lacks receive permission");
                return -1;
            }

            metadata = get_file_metadata(command->slot);
            if (metadata == NULL) {
                print_error("Getting metadata failed");
                write_packet(TRANSFER_INTERFACE, ERROR_MSG, "metadata failed", 15);
                return -1;
            }

            memcpy(&current_recv_resp.uuid, &metadata->uuid, UUID_SIZE);


            // send the file to the neighbor hsm
            write_length = sizeof(receive_response_t);
            write_packet(TRANSFER_INTERFACE, RECEIVE_MSG, &current_recv_resp, write_length);
            break;

        default:
            print_error("Bad message type");
            return -1;
    }

    write_packet(CONTROL_INTERFACE, LISTEN_MSG, NULL, 0);
    return 0;
}