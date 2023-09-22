/******************************************************************************
    (C) John Forecast                           john@forecast.name

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
******************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <readline/readline.h>
#include <readline/history.h>
#include <netdnet/dn.h>
#include <netdnet/dnetdb.h>

#include "ncp.h"
#include "nice.h"

/*
 * Command table
 */
static struct element commands[] = {
  { "clear", CMD_CLEAR },
  { "copy", CMD_COPY },
  { "define", CMD_DEFINE },
  { "exit", CMD_EXIT },
  { "list", CMD_LIST },
  { "load", CMD_LOAD },
  { "loop", CMD_LOOP },
  { "purge", CMD_PURGE },
  { "set", CMD_SET },
  { "show", CMD_SHOW },
  { "trigger", CMD_TRIGGER },
  { "zero", CMD_ZERO }
};

struct table commandTable = {
  commands, sizeof(commands) / sizeof(struct element)
};

/*
 * Show/List entities
 *
 * Result values:
 *	Byte 0:	Entity type (0 - 5)
 *	Byte 1: Identifier format (Active, Known etc)
 *	Byte 2: Allowed infotypes
 *	Byte 3:
 */
static struct element showEntities[] = {
  { "active areas",
     PACK4(0, READ_OPT(CHAR)|READ_OPT(STATUS)|READ_OPT(SUM),
           NICE_AFMT_ACTIVE, NICE_ENT_AREA) },
  { "active circuits",
     PACK4(0, READ_OPT(CHAR)|READ_OPT(CTRS)|READ_OPT(STATUS)|READ_OPT(SUM),
           NICE_SFMT_ACTIVE, NICE_ENT_CIRCUIT) },
  { "active lines",
     PACK4(0, READ_OPT(CHAR)|READ_OPT(CTRS)|READ_OPT(STATUS)|READ_OPT(SUM),
           NICE_SFMT_ACTIVE, NICE_ENT_LINE) },
  { "active logging",
     PACK4(0, READ_OPT(EVENTS)|READ_OPT(CTRS)|READ_OPT(SUM),
           NICE_SFMT_ACTIVE, NICE_ENT_LOGGING) },
  { "active nodes",
     PACK4(0, READ_OPT(CHAR)|READ_OPT(CTRS)|READ_OPT(STATUS)|READ_OPT(SUM),
           NICE_NFMT_ACTIVE, NICE_ENT_NODE) },
  { "adjacent nodes",
     PACK4(0, READ_OPT(CHAR)|READ_OPT(CTRS)|READ_OPT(STATUS)|READ_OPT(SUM),
           NICE_NFMT_ADJACENT, NICE_ENT_NODE) },
  { "area",
     PACK4(0, READ_OPT(CHAR)|READ_OPT(STATUS)|READ_OPT(SUM),
           NICE_AFMT_ADDRESS, NICE_ENT_AREA) },
  { "circuit",
     PACK4(0, READ_OPT(CHAR)|READ_OPT(CTRS)|READ_OPT(STATUS)|READ_OPT(SUM),
           NICE_SFMT_STRING, NICE_ENT_CIRCUIT) },
  { "executor",
     PACK4(0, READ_OPT(CHAR)|READ_OPT(CTRS)|READ_OPT(STATUS)|READ_OPT(SUM),
           NICE_NFMT_EXECUTOR, NICE_ENT_NODE) },
  { "known areas",
     PACK4(0, READ_OPT(CHAR)|READ_OPT(STATUS)|READ_OPT(SUM),
           NICE_AFMT_KNOWN, NICE_ENT_AREA) },
  { "known circuits",
     PACK4(0, READ_OPT(CHAR)|READ_OPT(CTRS)|READ_OPT(STATUS)|READ_OPT(SUM),
           NICE_SFMT_KNOWN, NICE_ENT_CIRCUIT) },
  { "known lines",
     PACK4(0, READ_OPT(CHAR)|READ_OPT(CTRS)|READ_OPT(STATUS)|READ_OPT(SUM),
           NICE_SFMT_KNOWN, NICE_ENT_LINE) },
  { "known logging",
     PACK4(0, 0, NICE_SFMT_KNOWN, NICE_ENT_LOGGING) },
  { "known nodes",
     PACK4(0, READ_OPT(CHAR)|READ_OPT(CTRS)|READ_OPT(STATUS)|READ_OPT(SUM),
           NICE_NFMT_KNOWN, NICE_ENT_NODE) },
  { "line",
     PACK4(0, READ_OPT(CHAR)|READ_OPT(CTRS)|READ_OPT(STATUS)|READ_OPT(SUM),
           NICE_SFMT_STRING, NICE_ENT_LINE) },
  { "logging console",
     PACK4(0, READ_OPT(EVENTS)|READ_OPT(STATUS)|READ_OPT(SUM),
           0, NICE_ENT_LOGGING) },
  { "logging file",
     PACK4(0, READ_OPT(EVENTS)|READ_OPT(STATUS)|READ_OPT(SUM),
           0, NICE_ENT_LOGGING) },
  { "logging monitor",
     PACK4(0, READ_OPT(EVENTS)|READ_OPT(STATUS)|READ_OPT(SUM),
           0, NICE_ENT_LOGGING) },
  { "loop nodes",
     PACK4(0, READ_OPT(CHAR)|READ_OPT(CTRS)|READ_OPT(STATUS)|READ_OPT(SUM),
           0, NICE_ENT_NODE) }, /*** TODO ***/
  { "module configurator",
     PACK4(0, READ_OPT(CHAR)|READ_OPT(STATUS)|READ_OPT(SUM),
           0, NICE_ENT_MODULE) },
  { "module x25-access",
     PACK4(0, READ_OPT(CHAR)|READ_OPT(STATUS)|READ_OPT(SUM),
           0, NICE_ENT_MODULE) },
  { "module x25-protocol",
     PACK4(0, READ_OPT(CHAR)|READ_OPT(CTRS)|READ_OPT(STATUS)|READ_OPT(SUM),
           0, NICE_ENT_MODULE) },
  { "module x25-server",
     PACK4(0, READ_OPT(CHAR)|READ_OPT(CTRS)|READ_OPT(STATUS)|READ_OPT(SUM),
           0, NICE_ENT_MODULE) },
  { "module x29-server",
     PACK4(0, READ_OPT(CHAR)|READ_OPT(CTRS)|READ_OPT(STATUS)|READ_OPT(SUM),
           0, NICE_ENT_MODULE) },
  { "node",
     PACK4(0, READ_OPT(CHAR)|READ_OPT(CTRS)|READ_OPT(STATUS)|READ_OPT(SUM),
           NICE_NFMT_ADDRESS, NICE_ENT_NODE) },
};

struct table showEntitiesTable = {
  showEntities, sizeof(showEntities) / sizeof(struct element)
};

static struct element listEntities[] = {
  { "circuit",
     PACK4(0, READ_OPT(CHAR)|READ_OPT(CTRS)|READ_OPT(STATUS)|READ_OPT(SUM),
           NICE_SFMT_STRING, NICE_ENT_CIRCUIT) },
  { "executor",
     PACK4(0, READ_OPT(CHAR)|READ_OPT(CTRS)|READ_OPT(STATUS)|READ_OPT(SUM),
           NICE_NFMT_EXECUTOR, NICE_ENT_NODE) },
  { "known circuits",
     PACK4(0, READ_OPT(CHAR)|READ_OPT(CTRS)|READ_OPT(STATUS)|READ_OPT(SUM),
           NICE_SFMT_KNOWN, NICE_ENT_CIRCUIT) },
  { "known lines",
     PACK4(0, READ_OPT(CHAR)|READ_OPT(CTRS)|READ_OPT(STATUS)|READ_OPT(SUM),
           NICE_SFMT_KNOWN, NICE_ENT_LINE) },
  { "known logging",
     PACK4(0, 0, NICE_SFMT_KNOWN, NICE_ENT_LOGGING) },
  { "known nodes",
     PACK4(0, READ_OPT(CHAR)|READ_OPT(CTRS)|READ_OPT(STATUS)|READ_OPT(SUM),
           NICE_NFMT_KNOWN, NICE_ENT_NODE) },
  { "line",
     PACK4(0, READ_OPT(CHAR)|READ_OPT(CTRS)|READ_OPT(STATUS)|READ_OPT(SUM),
           NICE_SFMT_STRING, NICE_ENT_LINE) },
  { "logging console",
     PACK4(0, READ_OPT(EVENTS)|READ_OPT(STATUS)|READ_OPT(SUM),
           0, NICE_ENT_LOGGING) },
  { "logging file",
     PACK4(0, READ_OPT(EVENTS)|READ_OPT(STATUS)|READ_OPT(SUM),
           0, NICE_ENT_LOGGING) },
  { "logging monitor",
     PACK4(0, READ_OPT(EVENTS)|READ_OPT(STATUS)|READ_OPT(SUM),
           0, NICE_ENT_LOGGING) },
  { "loop nodes",
     PACK4(0, READ_OPT(CHAR)|READ_OPT(CTRS)|READ_OPT(STATUS)|READ_OPT(SUM),
           0, NICE_ENT_NODE) }, /*** TODO ***/
  { "module configurator",
     PACK4(0, READ_OPT(CHAR)|READ_OPT(STATUS)|READ_OPT(SUM),
           0, NICE_ENT_MODULE) },
  { "module x25-access",
     PACK4(0, READ_OPT(CHAR)|READ_OPT(STATUS)|READ_OPT(SUM),
           0, NICE_ENT_MODULE) },
  { "module x25-protocol",
     PACK4(0, READ_OPT(CHAR)|READ_OPT(CTRS)|READ_OPT(STATUS)|READ_OPT(SUM),
           0, NICE_ENT_MODULE) },
  { "module x25-server",
     PACK4(0, READ_OPT(CHAR)|READ_OPT(CTRS)|READ_OPT(STATUS)|READ_OPT(SUM),
           0, NICE_ENT_MODULE) },
  { "module x29-server",
     PACK4(0, READ_OPT(CHAR)|READ_OPT(CTRS)|READ_OPT(STATUS)|READ_OPT(SUM),
           0, NICE_ENT_MODULE) },
  { "node",
     PACK4(0, READ_OPT(CHAR)|READ_OPT(CTRS)|READ_OPT(STATUS)|READ_OPT(SUM),
           NICE_NFMT_ADDRESS, NICE_ENT_NODE) },
};

struct table listEntitiesTable = {
  listEntities, sizeof(listEntities) / sizeof(struct element)
};

static struct element infoTypes[] = {
  { "summary", PACK4(0, 0, 0, NICE_READ_OPT_SUM) },
  { "status", PACK4(0, 0, 0, NICE_READ_OPT_STATUS) },
  { "characteristics", PACK4(0, 0, 0, NICE_READ_OPT_CHAR) },
  { "counters", PACK4(0, 0, 0, NICE_READ_OPT_CTRS) },
  { "events", PACK4(0, 0, 0, NICE_READ_OPT_EVENTS) }
};

struct table infoTypeTable = {
  infoTypes, sizeof(infoTypes) / sizeof(struct element)
};

/*
 * Node - mapping tables
 */

/*
 * Value sub-mapping tables
 */
static struct valueTable nodeStateTable[] = {
  VALUE(NICE_P_N_STATE_ON, "On"),
  VALUE(NICE_P_N_STATE_OFF, "Off"),
  VALUE(NICE_P_N_STATE_SHUT, "Shut"),
  VALUE(NICE_P_N_STATE_RESTRICT, "Restricted"),
  VALUE(NICE_P_N_STATE_REACH, "Reachable"),
  VALUE(NICE_P_N_STATE_UNREACH, "Unreachable"),
  { 0, NULL }
};

static struct valueTable nodeServiceDeviceTable[] = {
  VALUE(NICE_P_N_DEV_DP, "DP11-DA"),
  VALUE(NICE_P_N_DEV_UNA, "DEUNA"),
  VALUE(NICE_P_N_DEV_DU, "DU11-DA"),
  VALUE(NICE_P_N_DEV_CNA, "DECNA"),
  VALUE(NICE_P_N_DEV_DL, "DL11-C, -E, -WA"),
  VALUE(NICE_P_N_DEV_QNA, "QNA"),
  VALUE(NICE_P_N_DEV_DQ, "DQ11-DA"),
  VALUE(NICE_P_N_DEV_CI, "CI"),
  VALUE(NICE_P_N_DEV_DA, "DA11-B, -AL"),
  VALUE(NICE_P_N_DEV_PCL, "PCL11-B"),
  VALUE(NICE_P_N_DEV_DUP, "DUP11-DA"),
  VALUE(NICE_P_N_DEV_DMC, "DMC11-DA/AR, -FA/AR, -MA/AL, -MD/AL"),
  VALUE(NICE_P_N_DEV_DN, "DN11-BA, -AA"),
  VALUE(NICE_P_N_DEV_DLV, "DLV11-R, -F, -J, MXV11-A, -B"),
  VALUE(NICE_P_N_DEV_DMP, "DMP11"),
  VALUE(NICE_P_N_DEV_DTE, "DTE20"),
  VALUE(NICE_P_N_DEV_DV, "DV11-AA/BA"),
  VALUE(NICE_P_N_DEV_DZ, "DZ11-A, -B, -C, -D"),
  VALUE(NICE_P_N_DEV_KDP, "KMC11/DUP11-DA"),
  VALUE(NICE_P_N_DEV_KDZ, "KMC11/DZ11-A, -B, -C, -D"),
  VALUE(NICE_P_N_DEV_KL, "KL8-J"),
  VALUE(NICE_P_N_DEV_DMV, "DMV11"),
  VALUE(NICE_P_N_DEV_DPV, "DPV11"),
  VALUE(NICE_P_N_DEV_DMF, "DMF-32"),
  VALUE(NICE_P_N_DEV_DMR, "DMR11-AA, -AB, -AC, -AE"),
  VALUE(NICE_P_N_DEV_KMY, "KMS11-PX"),
  VALUE(NICE_P_N_DEV_KMX, "KMS11-BD/BE"),
  { 0, NULL }
};

static struct valueTable nodeCPUTable[] = {
  VALUE(NICE_P_N_CPU_PDP8, "PDP8"),
  VALUE(NICE_P_N_CPU_PDP11, "PDP11"),
  VALUE(NICE_P_N_CPU_1020, "DECsystem-10/20"),
  VALUE(NICE_P_N_CPU_VAX, "VAX"),
  { 0, NULL }
};

static struct valueTable nodeSNVTable[] = {
  VALUE(NICE_P_N_SNV_III, "Phase III"),
  VALUE(NICE_P_N_SNV_IV, "Phase IV"),
  { 0, NULL }
};

static struct valueTable nodeSWtypeTable[] = {
  VALUE(NICE_P_N_SWTYPE_SECLDR, "Secondary loader"),
  VALUE(NICE_P_N_SWTYPE_TERLDR, "Tertiary loader"),
  VALUE(NICE_P_N_SWTYPE_SYSTEM, "System"),
  { 0, NULL }
};

static struct valueTable nodeProxyTable[] = {
  VALUE(NICE_P_N_PROXY_ENA, "Enabled"),
  VALUE(NICE_P_N_PROXY_DIS, "Disabled"),
  { 0, NULL }
};

static struct valueTable nodeLWTable[] = {
  VALUE(NICE_P_N_LW_ZEROES, "Zeroes"),
  VALUE(NICE_P_N_LW_ONES, "Ones"),
  VALUE(NICE_P_N_LW_MIXED, "Mixed"),
  { 0, NULL }
};

static struct valueTable nodeLHTable[] = {
  VALUE(NICE_P_N_LH_TRANSMIT, "Transmit"),
  VALUE(NICE_P_N_LH_RECEIVE, "Receive"),
  VALUE(NICE_P_N_LH_FULL, "Full"),
  { 0, NULL }
};

static struct valueTable nodeRtypeTable[] = {
  VALUE(NICE_P_N_RTYPE_RTR_III, "Routing III"),
  VALUE(NICE_P_N_RTYPE_NRTR_III, "Nonrouting III"),
  VALUE(NICE_P_N_RTYPE_AREA, "Area"),
  VALUE(NICE_P_N_RTYPE_RTR_IV, "Routing IV"),
  VALUE(NICE_P_N_RTYPE_NRTR_IV, "Nonrouting IV"),
  { 0, NULL }
};

/*
 * Version prefix table
 */
static char *versionPrefixTable[] = {
  "", "V", ".", "."
};

/*
 * Parameter mapping table for node information.
 */
struct nameTable nodeParamTable[] = {
  PARAMETER(NICE_P_N_STATE, "State", nodeStateTable),
  PARAMETER(NICE_P_N_PA, "Physical address", NULL),
  PARAMETER(NICE_P_N_IDENTIFICATION, "Identification", NULL),
  PARAMETER(NICE_P_N_MGMTVERS, "Management version", versionPrefixTable),
  PARAMETER(NICE_P_N_SERV_CIRC, "Service circuit", NULL),
  PARAMETER(NICE_P_N_SERV_PWD, "Service password", NULL),
  PARAMETER(NICE_P_N_SERV_DEV, "Service device", nodeServiceDeviceTable),
  PARAMETER(NICE_P_N_CPU, "CPU", nodeCPUTable),
  PARAMETER(NICE_P_N_HA, "Hardware address", NULL),
  PARAMETER(NICE_P_N_SNV, "Service node version", nodeSNVTable),
  PARAMETER(NICE_P_N_LOADFILE, "Load file", NULL),
  PARAMETER(NICE_P_N_SECLDR, "Secondary loader", NULL),
  PARAMETER(NICE_P_N_TERLDR, "Tertiary loader", NULL),
  PARAMETER(NICE_P_N_DIAGNOSTIC, "Diagnostic file", NULL),
  PARAMETER(NICE_P_N_SWTYPE, "Software type", nodeSWtypeTable),
  PARAMETER(NICE_P_N_SWID, "Software identification", NULL),
  PARAMETER(NICE_P_N_DUMPFILE, "Dump file", NULL),
  PARAMETER(NICE_P_N_SECDUMPER, "Secondary dumper", NULL),
  PARAMETER(NICE_P_N_DUMPADDRESS, "Dump address", NULL),
  PARAMETER(NICE_P_N_DUMPCOUNT, "Dump count", NULL),
  PARAMETER(NICE_P_N_HOST_RO, "Host", NULL),
  PARAMETER(NICE_P_N_HOST_WO, "Host", NULL),
  PARAMETER(NICE_P_N_LC, "Loop count", NULL),
  PARAMETER(NICE_P_N_LL, "Loop length", NULL),
  PARAMETER(NICE_P_N_LW, "Loop with", nodeLWTable),
  PARAMETER(NICE_P_N_LAPA, "Loop assistant physical address", NULL),
  PARAMETER(NICE_P_N_LH, "Loop help", nodeLHTable),
  PARAMETER(NICE_P_N_LN, "Loop node", NULL),
  PARAMETER(NICE_P_N_LAN, "Loop assistant node", NULL),
  PARAMETER(NICE_P_N_CTR_TIMER, "Counter timer", NULL),
  PARAMETER(NICE_P_N_NAME, "Name", NULL),
  PARAMETER(NICE_P_N_CIRC, "Circuit", NULL),
  PARAMETER(NICE_P_N_ADDRESS, "Address", NULL),
  PARAMETER(NICE_P_N_INC_TIMER, "Incoming timer", NULL),
  PARAMETER(NICE_P_N_OUT_TIMER, "Outgoing timer", NULL),
  PARAMETER(NICE_P_N_INC_PROXY, "Incoming proxy", nodeProxyTable),
  PARAMETER(NICE_P_N_OUT_PROXY, "Outgoing proxy", nodeProxyTable),
  PARAMETER(NICE_P_N_ACTIVELINKS, "Active links", NULL),
  PARAMETER(NICE_P_N_DELAY, "Delay", NULL),
  PARAMETER(NICE_P_N_NSPVERSION, "NSP version", versionPrefixTable),
  PARAMETER(NICE_P_N_MAXLINKS, "Maximum links", NULL),
  PARAMETER(NICE_P_N_DELAYFACTOR, "Delay factor", NULL),
  PARAMETER(NICE_P_N_DELAYWEIGHT, "Delay weight", NULL),
  PARAMETER(NICE_P_N_INACT_TIMER, "Inactive timer", NULL),
  PARAMETER(NICE_P_N_RETRANS_FACTOR, "Retransmit factor", NULL),
  PARAMETER(NICE_P_N_TYPE, "Type", nodeRtypeTable),
  PARAMETER(NICE_P_N_COST, "Cost", NULL),
  PARAMETER(NICE_P_N_HOPS, "Hops", NULL),
  PARAMETER(NICE_P_N_CIRCUIT, "Circuit", NULL),
  PARAMETER(NICE_P_N_NEXTNODE, "Next node to destination", NULL),
  PARAMETER(NICE_P_N_RTRVERSION, "Routing version", versionPrefixTable),
  PARAMETER(NICE_P_N_RTYPE, "Type", nodeRtypeTable),
  PARAMETER(NICE_P_N_RTR_TIMER, "Routing timer", NULL),
  PARAMETER(NICE_P_N_SUBADDRESSES, "Subaddresses", NULL),
  PARAMETER(NICE_P_N_BRT, "Broadcast routing timer", NULL),
  PARAMETER(NICE_P_N_MAXADDRESS, "Maximum address", NULL),
  PARAMETER(NICE_P_N_MAXCIRCUITS, "Maximum circuits", NULL),
  PARAMETER(NICE_P_N_MAXCOST, "Maximum cost", NULL),
  PARAMETER(NICE_P_N_MAXHOPS, "Maximum hops", NULL),
  PARAMETER(NICE_P_N_MAXVISITS, "Maximum visits", NULL),
  PARAMETER(NICE_P_N_MAXAREA, "Maximum area", NULL),
  PARAMETER(NICE_P_N_MAXBNRTR, "Max broadcast nonrouters", NULL),
  PARAMETER(NICE_P_N_MAXBRTR, "Max broadcast routers", NULL),
  PARAMETER(NICE_P_N_AMAXCOST, "Area maximum cost", NULL),
  PARAMETER(NICE_P_N_AMAXHOPS, "Area maximum hops", NULL),
  PARAMETER(NICE_P_N_MAXBUFFERS, "Maximum buffers", NULL),
  PARAMETER(NICE_P_N_BUFFERSIZE, "Buffer size", NULL),
  PARAMETER(NICE_P_N_SEGBUFFERSIZE, "Segment buffer size", NULL),
  { 0, NULL, NULL }
};

struct nameTable nodeCtrTable[] = {
  COUNTER(NICE_C_N_SECONDS, "Seconds since last zeroed", NULL),
  COUNTER(NICE_C_N_USERBYTESRCVD, "User bytes received", NULL),
  COUNTER(NICE_C_N_USERBYTESSENT, "User bytes sent", NULL),
  COUNTER(NICE_C_N_USERMSGSRCVD, "User messages received", NULL),
  COUNTER(NICE_C_N_USERMSGSSENT, "User messages sent", NULL),
  COUNTER(NICE_C_N_TOTBYTESRCVD, "Total bytes received", NULL),
  COUNTER(NICE_C_N_TOTBYTESSENT, "Total bytes sent", NULL),
  COUNTER(NICE_C_N_TOTMSGSRCVD, "Total messages received", NULL),
  COUNTER(NICE_C_N_TOTMSGSSENT, "Total messages sent", NULL),
  COUNTER(NICE_C_N_CONNRCVD, "Connects received", NULL),
  COUNTER(NICE_C_N_CONNSENT, "Connects sent", NULL),
  COUNTER(NICE_C_N_RESP_TMO, "Response timeouts", NULL),
  COUNTER(NICE_C_N_CONNRESERR, "Received connect resource errors", NULL),
  COUNTER(NICE_C_N_MAXLINKSACTIVE, "Maximum links active", NULL),
  COUNTER(NICE_C_N_AGEDLOSS, "Aged packet loss", NULL),
  COUNTER(NICE_C_N_UNREACHLOSS, "Node unreachable packet loss", NULL),
  COUNTER(NICE_C_N_RANGELOSS, "Node out-of-range packet loss", NULL),
  COUNTER(NICE_C_N_OVERSIZELOSS, "Oversized packet loss", NULL),
  COUNTER(NICE_C_N_FORMATERR, "Packet format error", NULL),
  COUNTER(NICE_C_N_PARTIALLOSS, "Partial routing update loss", NULL),
  COUNTER(NICE_C_N_VERIFREJECT, "Verification reject", NULL),
  { 0, NULL, NULL }
};

/*
 * Area - mapping tables
 */

/*
 * Value sub-mapping tables
 */
static struct valueTable areaStateTable[] = {
  VALUE(NICE_P_A_STATE_REACH, "Reachable"),
  VALUE(NICE_P_A_STATE_UNREACH, "Unreachable"),
  { 0, NULL }
};

/*
 * Parameter mapping table for area information
 */
struct nameTable areaParamTable[] = {
  PARAMETER(NICE_P_A_STATE, "State", areaStateTable),
  PARAMETER(NICE_P_A_COST, "Cost", NULL),
  PARAMETER(NICE_P_A_HOPS, "Hops", NULL),
  PARAMETER(NICE_P_A_CIRCUIT, "Circuit", NULL),
  PARAMETER(NICE_P_A_NEXTNODE, "Next Node", NULL),
  { 0, NULL, NULL }
};

/*
 * Circuit - mapping tables
 */

/*
 * Value sub-mapping tables
 */
static struct valueTable circuitStateTable[] = {
  VALUE(NICE_P_C_STATE_ON, "On"),
  VALUE(NICE_P_C_STATE_OFF, "Off"),
  VALUE(NICE_P_C_STATE_SERVICE, "Service"),
  VALUE(NICE_P_C_STATE_CLEARED, "Cleared"),
  { 0, NULL }
};

static struct valueTable circuitSStateTable[] = {
  VALUE(NICE_P_C_SSTATE_START, "Starting"),
  VALUE(NICE_P_C_SSTATE_REFLECT, "Reflecting"),
  VALUE(NICE_P_C_SSTATE_LOOP, "Looping"),
  VALUE(NICE_P_C_SSTATE_LOAD, "Loading"),
  VALUE(NICE_P_C_SSTATE_DUMP, "Dumping"),
  VALUE(NICE_P_C_SSTATE_TRIG, "Triggering"),
  VALUE(NICE_P_C_SSTATE_AUTOS, "Autoservice"),
  VALUE(NICE_P_C_SSTATE_AUTOL, "Autoloading"),
  VALUE(NICE_P_C_SSTATE_AUTOD, "Autodumping"),
  VALUE(NICE_P_C_SSTATE_AUTOT, "Autotriggering"),
  VALUE(NICE_P_C_SSTATE_SYNCH, "Synchronizing"),
  VALUE(NICE_P_C_SSTATE_FAILED, "Failed"),
  { 0, NULL }
};

static struct valueTable circuitServiceTable[] = {
  VALUE(NICE_P_C_SERVICE_ENA, "Enabled"),
  VALUE(NICE_P_C_SERVICE_DIS, "Disabled"),
  { 0, NULL }
};

static struct valueTable circuitBlockingTable[] = {
  VALUE(NICE_P_C_BLOCKING_ENA, "Enabled"),
  VALUE(NICE_P_C_BLOCKING_DIS, "Disabled"),
  { 0, NULL }
};

static struct valueTable circuitPStateTable[] = {
  VALUE(NICE_P_C_PSTATE_AUTO, "Automatic"),
  VALUE(NICE_P_C_PSTATE_ACT, "Active"),
  VALUE(NICE_P_C_PSTATE_INACT, "Inactive"),
  VALUE(NICE_P_C_PSTATE_DYING, "Dying"),
  VALUE(NICE_P_C_PSTATE_DEAD, "Dead"),
  { 0, NULL }
};

static struct valueTable circuitPSStateTable[] = {
  VALUE(NICE_P_C_PSSTATE_ACT, "Active"),
  VALUE(NICE_P_C_PSSTATE_INACT, "Inactive"),
  VALUE(NICE_P_C_PSSTATE_DYING, "Dying"),
  VALUE(NICE_P_C_PSSTATE_DEAD, "Dead"),
  { 0, NULL }
};

static struct valueTable circuitUsageTable[] = {
  VALUE(NICE_P_C_USAGE_PERM, "Permanent"),
  VALUE(NICE_P_C_USAGE_INC, "Incoming"),
  VALUE(NICE_P_C_USAGE_OUT, "Outgoing"),
  { 0, NULL }
};

static struct valueTable circuitTypeTable[] = {
  VALUE(NICE_P_C_TYPE_D_POINT, "DDCMP point-to-point"),
  VALUE(NICE_P_C_TYPE_D_CTRL, "DDCMP control"),
  VALUE(NICE_P_C_TYPE_D_TRIB, "DDCMP tributary"),
  VALUE(NICE_P_C_TYPE_X25, "X25"),
  VALUE(NICE_P_C_TYPE_D_DMC, "DDCMP DMC-11"),
  VALUE(NICE_P_C_TYPE_ETHER, "Ethernet"),
  VALUE(NICE_P_C_TYPE_CI, "CI"),
  VALUE(NICE_P_C_TYPE_QP2, "QP2 (DTE20)"),
  VALUE(NICE_P_C_TYPE_BISYNC, "BISYNC"),
  { 0, NULL }
};

static struct valueTable circuitInboundTable[] = {
  VALUE(NICE_C_C_D_DE_IN_DATA, "data block check"),
  VALUE(NICE_C_C_D_DE_IN_REP, "REP response"),
  {0, NULL }
};

static struct valueTable circuitOutboundTable[] = {
  VALUE(NICE_C_C_D_DE_OUT_HDR, "header block check"),
  VALUE(NICE_C_C_D_DE_OUT_DATA, "data block check"),
  VALUE(NICE_C_C_D_DE_OUT_REP, "REP response"),
  { 0, NULL }
};

static struct valueTable circuitRemBufTable[] = {
  VALUE(NICE_C_C_D_RBUF_UNAVAIL, "buffer unavailable"),
  VALUE(NICE_C_C_D_RBUF_SMALL, "buffer too small"),
  { 0, NULL }
};

static struct valueTable circuitLocBufTable[] = {
  VALUE(NICE_C_C_D_LBUF_UNAVAIL, "buffer unavailable"),
  VALUE(NICE_C_C_D_LBUF_SMALL, "buffer too small"),
  { 0, NULL }
};

static struct valueTable circuitSelectionTable[] = {
  VALUE(NICE_C_C_D_SEL_TMO_NO, "No reply to select"),
  VALUE(NICE_C_C_D_SEL_TMO_INC, "Incomplete reply to select"),
  { 0, NULL }
};

/*
 * Parameter mapping table for circuit information
 */
struct nameTable circuitParamTable[] = {
  PARAMETER(NICE_P_C_STATE, "State", circuitStateTable),
  PARAMETER(NICE_P_C_SSTATE, "Substate", circuitSStateTable),
  PARAMETER(NICE_P_C_SERVICE, "Service", circuitServiceTable),
  PARAMETER(NICE_P_C_CTR_TIMER, "Counter timer", NULL),
  PARAMETER(NICE_P_C_SERVICE_PA, "Service physical address", NULL),
  PARAMETER(NICE_P_C_SSSTATE, "Service substate", circuitSStateTable),
  PARAMETER(NICE_P_C_CONNNODE, "Connected node", NULL),
  PARAMETER(NICE_P_C_CONNOBJ, "Connected object", NULL),
  PARAMETER(NICE_P_C_LOOPNAME, "Loopback name", NULL),
  PARAMETER(NICE_P_C_ADJNODE, "Adjacent node", NULL),
  PARAMETER(NICE_P_C_DR, "Designated router", NULL),
  PARAMETER(NICE_P_C_BLOCKSIZE, "Block size", NULL),
  PARAMETER(NICE_P_C_OQLIMIT, "Originating queue limit", NULL),
  PARAMETER(NICE_P_C_COST, "Cost", NULL),
  PARAMETER(NICE_P_C_MAXROUTERS, "Maximum routers", NULL),
  PARAMETER(NICE_P_C_RPRIORITY, "Router priority", NULL),
  PARAMETER(NICE_P_C_HELLO, "Hello timer", NULL),
  PARAMETER(NICE_P_C_LISTEN, "Listen timer", NULL),
  PARAMETER(NICE_P_C_BLOCKING, "Blocking", circuitBlockingTable),
  PARAMETER(NICE_P_C_MAXRECALLS, "Maximum recalls", NULL),
  PARAMETER(NICE_P_C_RECALL, "Recall timer", NULL),
  PARAMETER(NICE_P_C_NUMBER, "Number", NULL),
  PARAMETER(NICE_P_C_USER, "User", NULL),
  PARAMETER(NICE_P_C_PSTATE, "Polling state", circuitPStateTable),
  PARAMETER(NICE_P_C_PSSTATE, "Polling substate", circuitPSStateTable),
  PARAMETER(NICE_P_C_OWNER, "Owner", NULL),
  PARAMETER(NICE_P_C_LINE, "Line", NULL),
  PARAMETER(NICE_P_C_USAGE, "Usage", circuitUsageTable),
  PARAMETER(NICE_P_C_TYPE, "Type", circuitTypeTable),
  PARAMETER(NICE_P_C_DTE, "DTE", NULL),
  PARAMETER(NICE_P_C_CHANNEL, "Channel", NULL),
  PARAMETER(NICE_P_C_MAXDATA, "Maximum data", NULL),
  PARAMETER(NICE_P_C_MAXWINDOW, "Maximum window", NULL),
  PARAMETER(NICE_P_C_TRIB, "Tributary", NULL),
  PARAMETER(NICE_P_C_BABBLE, "Babble timer", NULL),
  PARAMETER(NICE_P_C_TRANSMIT, "Transmit timer", NULL),
  PARAMETER(NICE_P_C_MAXBUFFERS, "Maximum buffers", NULL),
  PARAMETER(NICE_P_C_MAXTRANSMITS, "Maximum transmits", NULL),
  PARAMETER(NICE_P_C_ACTIVEBASE, "Active base", NULL),
  PARAMETER(NICE_P_C_ACTIVEINCR, "Active increment", NULL),
  PARAMETER(NICE_P_C_INACTIVEBASE, "Inactive base", NULL),
  PARAMETER(NICE_P_C_INACTIVEINCR, "Inactive increment", NULL),
  PARAMETER(NICE_P_C_INACTIVETHRESH, "Inactive threshold", NULL),
  PARAMETER(NICE_P_C_DYINGBASE, "Dying base", NULL),
  PARAMETER(NICE_P_C_DYINGINCR, "Dying increment", NULL),
  PARAMETER(NICE_P_C_DYINGTHRESH, "Dying threshold", NULL),
  PARAMETER(NICE_P_C_DEADTHRESH, "Dead threshold", NULL),
  { 0, NULL, NULL }
};

struct nameTable circuitCtrTable[] = {
  COUNTER(NICE_C_C_SECONDS, "Seconds since zeroed", NULL),
  COUNTER(NICE_C_C_PKTSRCVD, "Terminating packets received", NULL),
  COUNTER(NICE_C_C_PKTSSENT, "Terminating packets sent", NULL),
  COUNTER(NICE_C_C_CONGLOSS, "Congestion loss", NULL),
  COUNTER(NICE_C_C_CORRLOSS, "Corruption loss", NULL),
  COUNTER(NICE_C_C_TRANS_PKTSRCVD, "Transit packets received", NULL),
  COUNTER(NICE_C_C_TRANS_PKTSSENT, "Transit packets sent", NULL),
  COUNTER(NICE_C_C_TRANS_CONGLOSS, "Transit congestion loss", NULL),
  COUNTER(NICE_C_C_CIRC_DOWN, "Circuit down", NULL),
  COUNTER(NICE_C_C_INIT_FAIL, "Initialization failure", NULL),
  COUNTER(NICE_C_C_D_BYTESRCVD, "Bytes received", NULL),
  COUNTER(NICE_C_C_D_BYTESSENT, "Bytes sent", NULL),
  COUNTER(NICE_C_C_D_DBRCVD, "Data blocks received", NULL),
  COUNTER(NICE_C_C_D_DBSENT, "Data blocks sent", NULL),
  COUNTER(NICE_C_C_D_DE_IN, "Data errors inbound", circuitInboundTable),
  COUNTER(NICE_C_C_D_DE_OUT, "Data errors outbound", circuitOutboundTable),
  COUNTER(NICE_C_C_D_RREP_TMO, "Remote reply timouts", NULL),
  COUNTER(NICE_C_C_D_LREP_TMO, "Local reply timeouts", NULL),
  COUNTER(NICE_C_C_D_RBUF, "Remote buffer errors", circuitRemBufTable),
  COUNTER(NICE_C_C_D_LBUF, "Local buffer errors", circuitLocBufTable),
  COUNTER(NICE_C_C_D_SEL_INT, "Selection intervals", NULL),
  COUNTER(NICE_C_C_D_SEL_TMO, "Selection timeouts", circuitSelectionTable),
  COUNTER(NICE_C_C_X_BYTESRCVD, "Bytes received", NULL),
  COUNTER(NICE_C_C_X_BYTESSENT, "Bytes sent", NULL),
  COUNTER(NICE_C_C_X_DBRCVD, "Data blocks received", NULL),
  COUNTER(NICE_C_C_X_DBSENT, "Data blocks sent", NULL),
  COUNTER(NICE_C_C_X_LOCAL_RESET, "Local resets", NULL),
  COUNTER(NICE_C_C_X_REMOTE_RESET, "Remote resets", NULL),
  COUNTER(NICE_C_C_X_NET_RESET, "Network resets", NULL),
  COUNTER(NICE_C_C_E_BYTESRCVD, "Bytes received", NULL),
  COUNTER(NICE_C_C_E_BYTESSENT, "Bytes sent", NULL),
  COUNTER(NICE_C_C_E_DBRCVD, "Data blocks received", NULL),
  COUNTER(NICE_C_C_E_DBSENT, "Data blocks sent", NULL),
  COUNTER(NICE_C_C_E_NOBUF, "User buffer unavailable", NULL),
  { 0, NULL, NULL }
};

/*
 * Zero entities
 *
 * Result values:
 *	Byte 0: Entity type (0 - 5)
 *	Byte 1: Identifier format (Active, Known etc)
 *	Byte 2:
 *	Byte 3:
 */
static struct element zeroEntities[] = {
  { "circuit", 
     PACK4(0, 0, NICE_SFMT_STRING, NICE_ENT_CIRCUIT) },
  { "executor", 
     PACK4(0, 0, NICE_NFMT_EXECUTOR, NICE_ENT_NODE) },
  { "known circuits", 
     PACK4(0, 0, NICE_SFMT_KNOWN, NICE_ENT_CIRCUIT) },
  { "known lines", 
     PACK4(0, 0, NICE_SFMT_KNOWN, NICE_ENT_LINE) },
  { "known nodes", 
     PACK4(0, 0, NICE_NFMT_KNOWN, NICE_ENT_NODE) },
  { "line", 
     PACK4(0, 0, NICE_SFMT_STRING, NICE_ENT_LINE) },
  { "module x25-protocol", 
     PACK4(0, 0, 0, NICE_ENT_MODULE) },
  { "module x25-server", 
     PACK4(0, 0, 0, NICE_ENT_MODULE) },
  { "node", 
     PACK4(0, 0, NICE_NFMT_ADDRESS, NICE_ENT_NODE) },
};

struct table zeroEntitiesTable = {
  zeroEntities, sizeof(zeroEntities) / sizeof(struct element)
};

/*
 * Copy entities
 *
 * Result values:
 *	Byte 0:
 *	Byte 1:
 *	Byte 2:
 *	Byte 3:
 */
static struct element copyEntities[] = {
  { "known nodes from", 1 },
  { "known nodes", 1 },			/* The "from" keyword is optional */
};

struct table copyEntitiesTable = {
  copyEntities, sizeof(copyEntities) / sizeof(struct element)
};

