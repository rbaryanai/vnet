/*
 * Copyright (C) 2021 Mellanox Technologies, Ltd. ALL RIGHTS RESERVED.
 *
 * This software product is a proprietary product of Mellanox Technologies Ltd.
 * (the "Company") and all right, title, and interest in and to the software
 * product, including all associated intellectual property rights, are and
 * shall remain exclusively with the Company.
 *
 * This software product is governed by the End User License Agreement
 * provided with the software product.
 *
 */

#ifndef _DOCA_PCAP_H_
#define _DOCA_PCAP_H_

struct doca_pcap_handler;

/**
 * @brief - start pcap file writer
 *
 * @param filename
 *
 * @return handler
 */
struct doca_pcap_handler *doca_pcap_file_start(const char *filename);

/**
 * @brief - write a packet to file
 *
 * @param p_handler    - handler to pcap
 * @param buff         - packet buffer start
 * @param buff_len     - total len of buff
 * @param timestamp    - time of day in microsecond
 * @param cap_len      - option to trim packet. 0 will write entire packet
 *
 * @return
 */
int doca_pcap_write(struct doca_pcap_handler *p_handler, uint8_t *buff,
		    int buff_len, uint64_t timestamp, int cap_len);

/**
 * @brief - close file. p_handler is not valid after that
 *
 * @param p_handler
 */
void doca_pcap_file_stop(struct doca_pcap_handler *p_handler);

#endif
