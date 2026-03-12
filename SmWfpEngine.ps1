param(
    [Parameter(Mandatory=$true)]
    [ValidateSet('BlockInbound','UnblockInbound','BlockOutbound','UnblockOutbound','BlockAll','UnblockAll','Status')]
    [string]$Action
)

# SmWfpEngine.ps1 - WFP (Windows Filtering Platform) user-mode filter engine
# Adds block filters at TRANSPORT and ALE layers using proper struct marshaling
# Bypasses third-party antivirus/firewall (ESET, Norton, Kaspersky etc.)

$wfpSource = @'
using System;
using System.Runtime.InteropServices;

public static class SmWfpEngine
{
    // ─── Native struct definitions with correct layout ───

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct FWPM_DISPLAY_DATA0
    {
        [MarshalAs(UnmanagedType.LPWStr)] public string name;
        [MarshalAs(UnmanagedType.LPWStr)] public string description;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct FWP_BYTE_BLOB
    {
        public uint size;
        public IntPtr data;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct FWPM_SUBLAYER0
    {
        public Guid subLayerKey;
        public FWPM_DISPLAY_DATA0 displayData;
        public uint flags;
        public IntPtr providerKey;
        public FWP_BYTE_BLOB providerData;
        public ushort weight;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct FWP_VALUE0
    {
        public uint type;
        public ulong value;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct FWPM_ACTION0
    {
        public uint type;
        public Guid filterType;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct FWPM_FILTER0
    {
        public Guid filterKey;
        public FWPM_DISPLAY_DATA0 displayData;
        public uint flags;
        public IntPtr providerKey;
        public FWP_BYTE_BLOB providerData;
        public Guid layerKey;
        public Guid subLayerKey;
        public FWP_VALUE0 weight;
        public uint numFilterConditions;
        public IntPtr filterCondition;
        public FWPM_ACTION0 action;
        public ulong rawContext;
        public IntPtr reserved;
        public ulong filterId;
        public FWP_VALUE0 effectiveWeight;
    }

    // ─── WFP API imports ───
    [DllImport("Fwpuclnt.dll")]
    static extern uint FwpmEngineOpen0(
        [MarshalAs(UnmanagedType.LPWStr)] string serverName,
        uint authnService, IntPtr authIdentity, IntPtr session, out IntPtr engineHandle);

    [DllImport("Fwpuclnt.dll")]
    static extern uint FwpmEngineClose0(IntPtr engineHandle);

    [DllImport("Fwpuclnt.dll")]
    static extern uint FwpmSubLayerAdd0(IntPtr engineHandle, ref FWPM_SUBLAYER0 subLayer, IntPtr sd);

    [DllImport("Fwpuclnt.dll")]
    static extern uint FwpmSubLayerDeleteByKey0(IntPtr engineHandle, ref Guid key);

    [DllImport("Fwpuclnt.dll")]
    static extern uint FwpmFilterAdd0(IntPtr engineHandle, ref FWPM_FILTER0 filter, IntPtr sd, out ulong id);

    [DllImport("Fwpuclnt.dll")]
    static extern uint FwpmFilterDeleteByKey0(IntPtr engineHandle, ref Guid key);

    // ─── Constants ───
    const uint RPC_C_AUTHN_WINNT = 10;
    const uint FWP_E_ALREADY_EXISTS = 0x80320009;
    const uint FWP_ACTION_BLOCK = 0x00001001;
    const uint FWP_UINT8 = 1;

    // ─── GUIDs ───
    static readonly Guid SM_SUBLAYER_KEY = new Guid("d3b1c2a4-e4f5-6789-abcd-ef0123456789");

    // WFP Transport layers (not hooked by third-party AV)
    static readonly Guid FWPM_LAYER_INBOUND_TRANSPORT_V4  = new Guid("5926dfc8-e3cf-4426-a283-dc393f5d0f9d");
    static readonly Guid FWPM_LAYER_INBOUND_TRANSPORT_V6  = new Guid("634a869f-fc23-4b90-b0c1-bf620a36ae6f");
    static readonly Guid FWPM_LAYER_OUTBOUND_TRANSPORT_V4 = new Guid("09e61aea-d214-46e2-9b21-b26b0b2f28c8");
    static readonly Guid FWPM_LAYER_OUTBOUND_TRANSPORT_V6 = new Guid("e1735bde-013f-4571-b005-1a95010c3030");

    // WFP ALE layers (connection-level, as backup)
    static readonly Guid FWPM_LAYER_ALE_AUTH_CONNECT_V4     = new Guid("c38d57d1-05a7-4c33-904f-7fbceee60e82");
    static readonly Guid FWPM_LAYER_ALE_AUTH_CONNECT_V6     = new Guid("4a72393b-319f-44bc-84c3-ba54dcb3b6b4");
    static readonly Guid FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4 = new Guid("e1cd9fe7-f4b5-4273-96c0-592e487b8650");
    static readonly Guid FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6 = new Guid("a3b42c97-9f04-4672-b87e-cee9c483257f");

    // Stable filter keys
    static readonly Guid FILTER_IN_TRANSPORT_V4  = new Guid("b1b1b1b1-1111-1111-1111-000000000001");
    static readonly Guid FILTER_IN_TRANSPORT_V6  = new Guid("b1b1b1b1-1111-1111-1111-000000000002");
    static readonly Guid FILTER_OUT_TRANSPORT_V4 = new Guid("b1b1b1b1-2222-2222-2222-000000000001");
    static readonly Guid FILTER_OUT_TRANSPORT_V6 = new Guid("b1b1b1b1-2222-2222-2222-000000000002");
    static readonly Guid FILTER_IN_ALE_V4        = new Guid("b1b1b1b1-3333-3333-3333-000000000001");
    static readonly Guid FILTER_IN_ALE_V6        = new Guid("b1b1b1b1-3333-3333-3333-000000000002");
    static readonly Guid FILTER_OUT_ALE_V4       = new Guid("b1b1b1b1-4444-4444-4444-000000000001");
    static readonly Guid FILTER_OUT_ALE_V6       = new Guid("b1b1b1b1-4444-4444-4444-000000000002");

    static IntPtr OpenEngine()
    {
        IntPtr engine;
        uint r = FwpmEngineOpen0(null, RPC_C_AUTHN_WINNT, IntPtr.Zero, IntPtr.Zero, out engine);
        if (r != 0) throw new Exception("FwpmEngineOpen0 failed: 0x" + r.ToString("X8"));
        return engine;
    }

    static void EnsureSubLayer(IntPtr engine)
    {
        var sl = new FWPM_SUBLAYER0();
        sl.subLayerKey = SM_SUBLAYER_KEY;
        sl.displayData.name = "SecurityMonitor WFP";
        sl.displayData.description = "SecurityMonitor Block Filters";
        sl.weight = 0xFFFF;
        sl.flags = 0;
        sl.providerKey = IntPtr.Zero;
        sl.providerData.size = 0;
        sl.providerData.data = IntPtr.Zero;

        uint r = FwpmSubLayerAdd0(engine, ref sl, IntPtr.Zero);
        if (r != 0 && r != FWP_E_ALREADY_EXISTS)
            throw new Exception("FwpmSubLayerAdd0 failed: 0x" + r.ToString("X8"));
    }

    static bool TryAddBlockFilter(IntPtr engine, Guid filterKey, Guid layerKey, string name, out string error)
    {
        error = null;
        // Remove existing first
        Guid fk = filterKey;
        FwpmFilterDeleteByKey0(engine, ref fk);

        var f = new FWPM_FILTER0();
        f.filterKey = filterKey;
        f.displayData.name = name;
        f.displayData.description = "SecurityMonitor WFP Block";
        f.flags = 0;
        f.providerKey = IntPtr.Zero;
        f.providerData.size = 0;
        f.providerData.data = IntPtr.Zero;
        f.layerKey = layerKey;
        f.subLayerKey = SM_SUBLAYER_KEY;
        f.weight.type = FWP_UINT8;
        f.weight.value = 15;
        f.numFilterConditions = 0;
        f.filterCondition = IntPtr.Zero;
        f.action.type = FWP_ACTION_BLOCK;
        f.action.filterType = Guid.Empty;
        f.rawContext = 0;
        f.reserved = IntPtr.Zero;
        f.filterId = 0;
        f.effectiveWeight.type = 0;
        f.effectiveWeight.value = 0;

        ulong filterId;
        uint r = FwpmFilterAdd0(engine, ref f, IntPtr.Zero, out filterId);
        if (r != 0 && r != FWP_E_ALREADY_EXISTS) {
            error = name + ":0x" + r.ToString("X8");
            return false;
        }
        return true;
    }

    static void RemoveFilter(IntPtr engine, Guid filterKey)
    {
        Guid fk = filterKey;
        FwpmFilterDeleteByKey0(engine, ref fk);
    }

    // ─── Public API ───
    public static string BlockInbound()
    {
        IntPtr engine = OpenEngine();
        try {
            EnsureSubLayer(engine);
            int ok = 0; string err = "";
            string e;
            if (TryAddBlockFilter(engine, FILTER_IN_TRANSPORT_V4, FWPM_LAYER_INBOUND_TRANSPORT_V4, "SM_BlockIn_Transport_V4", out e)) ok++; else err += e + ";";
            if (TryAddBlockFilter(engine, FILTER_IN_TRANSPORT_V6, FWPM_LAYER_INBOUND_TRANSPORT_V6, "SM_BlockIn_Transport_V6", out e)) ok++; else err += e + ";";
            if (TryAddBlockFilter(engine, FILTER_IN_ALE_V4, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, "SM_BlockIn_ALE_V4", out e)) ok++; else err += e + ";";
            if (TryAddBlockFilter(engine, FILTER_IN_ALE_V6, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, "SM_BlockIn_ALE_V6", out e)) ok++; else err += e + ";";
            return ok > 0 ? "OK:BlockInbound(" + ok + "/4)" + (err.Length > 0 ? " WARN:" + err : "") : "ERR:" + err;
        } catch (Exception ex) {
            return "ERR:" + ex.Message;
        } finally { FwpmEngineClose0(engine); }
    }

    public static string UnblockInbound()
    {
        IntPtr engine = OpenEngine();
        try {
            RemoveFilter(engine, FILTER_IN_TRANSPORT_V4);
            RemoveFilter(engine, FILTER_IN_TRANSPORT_V6);
            RemoveFilter(engine, FILTER_IN_ALE_V4);
            RemoveFilter(engine, FILTER_IN_ALE_V6);
            return "OK:UnblockInbound";
        } catch (Exception ex) {
            return "ERR:" + ex.Message;
        } finally { FwpmEngineClose0(engine); }
    }

    public static string BlockOutbound()
    {
        IntPtr engine = OpenEngine();
        try {
            EnsureSubLayer(engine);
            int ok = 0; string err = "";
            string e;
            if (TryAddBlockFilter(engine, FILTER_OUT_TRANSPORT_V4, FWPM_LAYER_OUTBOUND_TRANSPORT_V4, "SM_BlockOut_Transport_V4", out e)) ok++; else err += e + ";";
            if (TryAddBlockFilter(engine, FILTER_OUT_TRANSPORT_V6, FWPM_LAYER_OUTBOUND_TRANSPORT_V6, "SM_BlockOut_Transport_V6", out e)) ok++; else err += e + ";";
            if (TryAddBlockFilter(engine, FILTER_OUT_ALE_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V4, "SM_BlockOut_ALE_V4", out e)) ok++; else err += e + ";";
            if (TryAddBlockFilter(engine, FILTER_OUT_ALE_V6, FWPM_LAYER_ALE_AUTH_CONNECT_V6, "SM_BlockOut_ALE_V6", out e)) ok++; else err += e + ";";
            return ok > 0 ? "OK:BlockOutbound(" + ok + "/4)" + (err.Length > 0 ? " WARN:" + err : "") : "ERR:" + err;
        } catch (Exception ex) {
            return "ERR:" + ex.Message;
        } finally { FwpmEngineClose0(engine); }
    }

    public static string UnblockOutbound()
    {
        IntPtr engine = OpenEngine();
        try {
            RemoveFilter(engine, FILTER_OUT_TRANSPORT_V4);
            RemoveFilter(engine, FILTER_OUT_TRANSPORT_V6);
            RemoveFilter(engine, FILTER_OUT_ALE_V4);
            RemoveFilter(engine, FILTER_OUT_ALE_V6);
            return "OK:UnblockOutbound";
        } catch (Exception ex) {
            return "ERR:" + ex.Message;
        } finally { FwpmEngineClose0(engine); }
    }

    public static string BlockAll()
    {
        return BlockInbound() + "|" + BlockOutbound();
    }

    public static string UnblockAll()
    {
        string r = UnblockInbound() + "|" + UnblockOutbound();
        try {
            IntPtr engine = OpenEngine();
            try {
                Guid sk = SM_SUBLAYER_KEY;
                FwpmSubLayerDeleteByKey0(engine, ref sk);
            } finally { FwpmEngineClose0(engine); }
        } catch {}
        return r;
    }
}
'@

try {
    Add-Type -TypeDefinition $wfpSource -ErrorAction Stop
} catch {
    if ($_.Exception.Message -notmatch 'already exists') {
        Write-Error "WFP Engine compile error: $_"
        exit 1
    }
}

$result = switch ($Action) {
    'BlockInbound'    { [SmWfpEngine]::BlockInbound() }
    'UnblockInbound'  { [SmWfpEngine]::UnblockInbound() }
    'BlockOutbound'   { [SmWfpEngine]::BlockOutbound() }
    'UnblockOutbound' { [SmWfpEngine]::UnblockOutbound() }
    'BlockAll'        { [SmWfpEngine]::BlockAll() }
    'UnblockAll'      { [SmWfpEngine]::UnblockAll() }
    'Status'          { "WFP Engine loaded" }
}

Write-Output $result
