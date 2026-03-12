/*
 * sm_common.h — Shared definitions for SmKext WFP Callout Driver
 * Used by both kernel driver and usermode bridge
 */

#ifndef SM_COMMON_H
#define SM_COMMON_H

#ifdef _KERNEL_MODE
#include <ntddk.h>
#else
#include <windows.h>
#endif

/* ── Device names ──────────────────────────────────────────── */
#define SM_DEVICE_NAME    L"\\Device\\SmKext"
#define SM_SYMBOLIC_LINK  L"\\DosDevices\\SmKext"
#define SM_DEVICE_TYPE    0x8000

/* ── IOCTL codes (METHOD_BUFFERED) ─────────────────────────── */
#define IOCTL_SM_ADD_RULE       CTL_CODE(SM_DEVICE_TYPE, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SM_REMOVE_RULE    CTL_CODE(SM_DEVICE_TYPE, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SM_CLEAR_RULES    CTL_CODE(SM_DEVICE_TYPE, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SM_GET_STATUS     CTL_CODE(SM_DEVICE_TYPE, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SM_ENABLE         CTL_CODE(SM_DEVICE_TYPE, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SM_DISABLE        CTL_CODE(SM_DEVICE_TYPE, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* ── Match types ───────────────────────────────────────────── */
#define SM_MATCH_ALL         0   /* Block all traffic (inbound/outbound)   */
#define SM_MATCH_IP_RANGE    1   /* CIDR range (LAN block)                 */
#define SM_MATCH_PORT        2   /* Port list (device discovery block)     */
#define SM_MATCH_ICMP_TYPE   3   /* ICMP type (ping block)                 */
#define SM_MATCH_IP_EXACT    4   /* Single IP (dynamic IP block)           */
#define SM_MATCH_PORT_DST    5   /* Destination port (DNS bypass block)    */

/* ── Directions ────────────────────────────────────────────── */
#define SM_DIR_INBOUND    0x01
#define SM_DIR_OUTBOUND   0x02
#define SM_DIR_BOTH       0x03

/* ── Rule structure (32 bytes, packed) ─────────────────────── */
#pragma pack(push, 1)
typedef struct _SM_RULE {
    UINT32 ruleId;
    UINT8  direction;     /* SM_DIR_*                              */
    UINT8  action;        /* 0 = BLOCK, 1 = PERMIT                */
    UINT8  matchType;     /* SM_MATCH_*                            */
    UINT8  protocol;      /* 0 = any, 1 = ICMP, 6 = TCP, 17 = UDP */
    UINT8  ipVersion;     /* 0 = both, 4 = IPv4, 6 = IPv6         */
    UINT8  reserved[3];
    union {
        struct {
            UINT32 networkAddr;
            UINT32 subnetMask;
        } ipRange;                          /* SM_MATCH_IP_RANGE   */
        struct {
            UINT16 ports[8];
            UINT8  portCount;
            UINT8  pad[7];
        } portMatch;                        /* SM_MATCH_PORT       */
        struct {
            UINT8  icmpType;
            UINT8  pad[15];
        } icmpMatch;                        /* SM_MATCH_ICMP_TYPE  */
        struct {
            UINT32 ipAddr;
            UINT8  pad[12];
        } ipExact;                          /* SM_MATCH_IP_EXACT   */
        struct {
            UINT16 dstPort;
            UINT8  pad[14];
        } dstPortMatch;                     /* SM_MATCH_PORT_DST   */
        UINT8 matchData[16];
    };
    UINT16 weight;        /* Priority (higher = evaluated first)   */
    UINT16 reserved2;
} SM_RULE;
#pragma pack(pop)

/* Compile-time size check */
#ifdef _KERNEL_MODE
C_ASSERT(sizeof(SM_RULE) == 32);
#endif

/* ── Status structure (returned by IOCTL_SM_GET_STATUS) ────── */
#pragma pack(push, 1)
typedef struct _SM_STATUS {
    UINT32 version;           /* Driver version: 0x00010000 = 1.0  */
    UINT32 ruleCount;         /* Current number of active rules    */
    UINT8  filteringEnabled;  /* 1 = filtering active, 0 = paused */
    UINT8  reserved[3];
    UINT32 blockedCount;      /* Total blocked connections (stat)  */
    UINT32 permittedCount;    /* Total permitted connections (stat)*/
} SM_STATUS;
#pragma pack(pop)

/* ── Constants ─────────────────────────────────────────────── */
#define SM_MAX_RULES        256
#define SM_DRIVER_VERSION   0x00010000  /* 1.0 */

#endif /* SM_COMMON_H */
