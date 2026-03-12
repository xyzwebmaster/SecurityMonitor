/*
 * driver_entry.c — SmKext WFP Callout Driver entry point
 * Creates device object, symbolic link, sets up IRP dispatch
 */

#include <ntddk.h>
#include <fwpsk.h>
#include <fwpmk.h>
#include "sm_common.h"

/* ── External declarations ─────────────────────────────────── */

/* wfp_register.c */
extern NTSTATUS SmWfpRegister(PDEVICE_OBJECT deviceObject);
extern VOID     SmWfpUnregister(VOID);

/* rule_engine.c */
extern VOID SmRuleEngineInit(VOID);
extern VOID SmRuleEngineCleanup(VOID);

/* ioctl_dispatch.c */
extern NTSTATUS SmIoctlDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp);

/* ── Globals ───────────────────────────────────────────────── */

static PDEVICE_OBJECT g_DeviceObject = NULL;
static UNICODE_STRING g_DeviceName;
static UNICODE_STRING g_SymbolicLink;

/* ── IRP Dispatch: Create / Close ──────────────────────────── */

static NTSTATUS SmDispatchCreateClose(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

/* ── Driver Unload ─────────────────────────────────────────── */

static VOID SmDriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    /* 1. Unregister WFP callouts/filters */
    SmWfpUnregister();

    /* 2. Cleanup rule engine */
    SmRuleEngineCleanup();

    /* 3. Delete symbolic link */
    IoDeleteSymbolicLink(&g_SymbolicLink);

    /* 4. Delete device object */
    if (g_DeviceObject) {
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
    }

    DbgPrint("[SmKext] Driver unloaded\n");
}

/* ── Driver Entry ──────────────────────────────────────────── */

NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrint("[SmKext] DriverEntry starting\n");

    /* Initialize unicode strings */
    RtlInitUnicodeString(&g_DeviceName, SM_DEVICE_NAME);
    RtlInitUnicodeString(&g_SymbolicLink, SM_SYMBOLIC_LINK);

    /* 1. Create device object */
    status = IoCreateDevice(
        DriverObject,
        0,                      /* DeviceExtensionSize */
        &g_DeviceName,
        SM_DEVICE_TYPE,
        0,                      /* DeviceCharacteristics */
        FALSE,                  /* Exclusive */
        &g_DeviceObject
    );
    if (!NT_SUCCESS(status)) {
        DbgPrint("[SmKext] IoCreateDevice failed: 0x%08X\n", status);
        return status;
    }

    /* 2. Create symbolic link for usermode access */
    status = IoCreateSymbolicLink(&g_SymbolicLink, &g_DeviceName);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[SmKext] IoCreateSymbolicLink failed: 0x%08X\n", status);
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
        return status;
    }

    /* 3. Set up IRP dispatch table */
    DriverObject->MajorFunction[IRP_MJ_CREATE] = SmDispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]  = SmDispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = SmIoctlDispatch;
    DriverObject->DriverUnload = SmDriverUnload;

    /* 4. Initialize rule engine */
    SmRuleEngineInit();

    /* 5. Register WFP callouts */
    status = SmWfpRegister(g_DeviceObject);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[SmKext] SmWfpRegister failed: 0x%08X\n", status);
        SmRuleEngineCleanup();
        IoDeleteSymbolicLink(&g_SymbolicLink);
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
        return status;
    }

    DbgPrint("[SmKext] Driver loaded successfully\n");
    return STATUS_SUCCESS;
}
