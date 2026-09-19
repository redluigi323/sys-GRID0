#include "nifm_shim.hpp"
#include "bsd_shim.hpp"
#include "lan_titles.hpp"
#include "../zt_port.hpp"

namespace ztnx::mitm {
    namespace {
        ztnx::Port *g_port = nullptr;
        constexpr int64_t NifmTransportBarrierTimeoutMs = 10'000;

        void PutIp(NifmIpV4Address &out, u32 ip) { out.addr[0]=ip>>24; out.addr[1]=ip>>16; out.addr[2]=ip>>8; out.addr[3]=ip; }
        bool GetIp(u32 *ip, u32 *mask) { return g_port != nullptr && g_port->GetLanIpConfig(ip, mask); }
        bool RyujinxInternetEnabled(u64 program_id, bool lan_requested) {
            /* Ryujinx keeps Guest Internet Access OFF during boot and enables
             * it only after LAN mode is selected. Mirror that edge, but do not
             * turn a brief ZeroTier wire pause into a NIFM failure: once the
             * virtual network has an assigned address, the game can keep its
             * sockets open while the uplink recycler reconnects. */
            u32 ip = 0;
            return UsesRyujinxNifmRequestModel(program_id) && lan_requested &&
                   g_port != nullptr && g_port->GetLanIpConfig(std::addressof(ip), nullptr);
        }
        bool RewriteIpConfig(NifmIpConfigInfo &value, const char *source) {
            u32 ip = 0, mask = 0;
            if (!GetIp(std::addressof(ip), std::addressof(mask))) { return false; }

            const NifmIpV4Address physical = value.ip.current;
            const u32 physical_ip = (static_cast<u32>(physical.addr[0]) << 24) |
                                    (static_cast<u32>(physical.addr[1]) << 16) |
                                    (static_cast<u32>(physical.addr[2]) << 8) |
                                    physical.addr[3];
            const u32 physical_mask = (static_cast<u32>(value.ip.mask.addr[0]) << 24) |
                                      (static_cast<u32>(value.ip.mask.addr[1]) << 16) |
                                      (static_cast<u32>(value.ip.mask.addr[2]) << 8) |
                                      value.ip.mask.addr[3];
            ObservePhysicalIpConfig(physical_ip, physical_mask);
            value.ip.automatic = 1;
            PutIp(value.ip.current, ip);
            PutIp(value.ip.mask, mask);
            PutIp(value.ip.gateway, 0);
            NoteNifm("nifm %-7s     %u.%u.%u.%u -> %u.%u.%u.%u",
                     source,
                     physical.addr[0], physical.addr[1], physical.addr[2], physical.addr[3],
                     value.ip.current.addr[0], value.ip.current.addr[1],
                     value.ip.current.addr[2], value.ip.current.addr[3]);
            return true;
        }
        void NoteForward(u32 command_id) {
            NoteNifm("nifm cmd%-2u       forward", command_id);
        }
    }
    void SetNifmPort(ztnx::Port *port) { g_port = port; }
    bool NifmShim::ShouldMitm(const ams::sm::MitmProcessInfo &client) {
        const LanTitle *title = FindLanTitle(client.program_id.value);
        if (title == nullptr) { return false; }
        NoteSync("nifm ask         %016llx pid %llu -> yes (%s)",
                 (unsigned long long)client.program_id.value,
                 (unsigned long long)client.process_id.value, title->name);
        ztnx::Trace("nifm: intercept %s (%016llx) pid %llu",
                    title->name, (unsigned long long)client.program_id.value,
                    (unsigned long long)client.process_id.value);
        return true;
    }

    Result NifmShim::CreateGeneralService(ams::sf::Out<ams::sf::SharedPointer<INifmGeneralShim>> out, const ams::sf::ClientProcessId &) {
        /* Nintendo's command 5 request has one raw u64 (reserved, always zero)
         * and a PID descriptor. libstratosphere models ClientProcessId as an
         * eight-byte raw slot as well as requiring that descriptor, so listing
         * both `reserved` and ClientProcessId incorrectly made it expect 16
         * raw bytes. Let ClientProcessId occupy the request's sole reserved
         * slot; the framework replaces its zero with the descriptor PID before
         * invocation, and the forwarded command still sends reserved = 0. */
        NoteNifm("nifm cmd5        enter");
        /* m_forward deliberately remains a normal session. The client-facing
         * service is converted into a domain locally by our server manager;
         * converting this target session was the source of HIPC 11-301. */
        Service general;
        const u64 reserved = 0;
        const Result rc = serviceMitmDispatchIn(m_forward.get(), 5, reserved, .in_send_pid = true, .out_num_objects = 1, .out_objects = std::addressof(general), .override_pid = m_client.process_id.value);
        if (R_FAILED(rc)) {
            NoteNifm("nifm cmd5        forward failed 0x%x", rc.GetValue());
            R_THROW(rc);
        }
        *out = ams::sf::CreateSharedObjectEmplaced<INifmGeneralShim, NifmGeneralShim>(
            general, m_client.process_id.value, m_client.program_id.value);
        R_SUCCEED();
    }
    Result NifmGeneralShim::CreateRequest(ams::sf::Out<ams::sf::SharedPointer<INifmRequestShim>> out, s32 type) {
        NoteNifm("nifm cmd4        request type %d", type);
        Service request{};
        /* Always retain a genuine Nintendo IRequest underneath the local
         * proxy. The fully synthetic Splatoon experiment was never built and
         * would leave every non-Ryujinx-model command forwarding through an
         * invalid Service. The compatibility methods below may still expose
         * Ryujinx-like state/events, but uncommon methods remain wire-exact. */
        R_TRY(serviceMitmDispatchIn(
            std::addressof(m_forward), 4, type,
            .out_num_objects = 1, .out_objects = std::addressof(request),
            .override_pid = m_pid));
        if (UsesRyujinxNifmRequestModel(m_program_id)) {
            NoteNifm("ryu request title %016llx real backing type %d",
                     (unsigned long long)m_program_id, type);
        }
        *out = ams::sf::CreateSharedObjectEmplaced<INifmRequestShim, NifmRequestShim>(
            request, m_pid, m_program_id);
        R_SUCCEED();
    }
    Result NifmGeneralShim::GetClientId(ams::sf::Out<NifmClientIdData> out) {
        NoteForward(1);
        R_RETURN(serviceMitmDispatch(
            std::addressof(m_forward), 1,
            .buffer_attrs = { SfBufferAttr_Out | SfBufferAttr_HipcPointer | SfBufferAttr_FixedSize },
            .buffers = { { out.GetPointer(), sizeof(NifmClientIdData) } },
            .override_pid = m_pid));
    }
    Result NifmGeneralShim::GetCurrentNetworkProfile(ams::sf::Out<NifmSfNetworkProfileData> out) {
        R_TRY(serviceMitmDispatch(
            std::addressof(m_forward), 5,
            .buffer_attrs = { SfBufferAttr_Out | SfBufferAttr_HipcPointer | SfBufferAttr_FixedSize },
            .buffers = { { out.GetPointer(), sizeof(NifmSfNetworkProfileData) } },
            .override_pid = m_pid));
        (void)RewriteIpConfig(out.GetPointer()->ip_config, "profile");
        R_SUCCEED();
    }
    Result NifmGeneralShim::EnumerateNetworkProfiles(ams::sf::Out<s32> out_count, u8 type,
                                                     const ams::sf::OutMapAliasBuffer &out_profiles) {
        NoteForward(7);
        R_RETURN(serviceMitmDispatchInOut(
            std::addressof(m_forward), 7, type, *out_count,
            .buffer_attrs = { SfBufferAttr_Out | SfBufferAttr_HipcMapAlias },
            .buffers = { { out_profiles.GetPointer(), out_profiles.GetSize() } },
            .override_pid = m_pid));
    }
    Result NifmGeneralShim::GetNetworkProfile(ams::sf::Out<NifmSfNetworkProfileData> out,
                                              const NifmUuid &profile_id) {
        R_TRY(serviceMitmDispatchIn(
            std::addressof(m_forward), 8, profile_id,
            .buffer_attrs = { SfBufferAttr_Out | SfBufferAttr_HipcPointer | SfBufferAttr_FixedSize },
            .buffers = { { out.GetPointer(), sizeof(NifmSfNetworkProfileData) } },
            .override_pid = m_pid));
        (void)RewriteIpConfig(out.GetPointer()->ip_config, "profile");
        R_SUCCEED();
    }
    Result NifmGeneralShim::SetNetworkProfile(ams::sf::Out<NifmUuid> out_profile_id,
                                              const NifmSfNetworkProfileData &profile) {
        NoteForward(9);
        R_RETURN(serviceMitmDispatchOut(
            std::addressof(m_forward), 9, *out_profile_id,
            .buffer_attrs = { SfBufferAttr_In | SfBufferAttr_HipcPointer | SfBufferAttr_FixedSize },
            .buffers = { { std::addressof(profile), sizeof(NifmSfNetworkProfileData) } },
            .override_pid = m_pid));
    }
    Result NifmGeneralShim::GetCurrentIpAddress(ams::sf::Out<NifmIpV4Address> out) {
        NifmIpV4Address value{};
        R_TRY(serviceMitmDispatchOut(std::addressof(m_forward), 12, value, .override_pid = m_pid));
        u32 ip=0, mask=0; if (GetIp(std::addressof(ip), std::addressof(mask))) { PutIp(value, ip); NoteNifm("nifm IPv4        %u.%u.%u.%u", value.addr[0],value.addr[1],value.addr[2],value.addr[3]); } *out=value; R_SUCCEED();
    }
    Result NifmGeneralShim::GetCurrentIpConfigInfo(ams::sf::Out<NifmIpConfigInfo> out) {
        NifmIpConfigInfo value{};
        R_TRY(serviceMitmDispatchOut(std::addressof(m_forward), 15, value, .override_pid = m_pid));
        (void)RewriteIpConfig(value, "config");
        *out=value; R_SUCCEED();
    }
    Result NifmGeneralShim::IsWirelessCommunicationEnabled(ams::sf::Out<u8> out) {
        NoteForward(17);
        R_RETURN(serviceMitmDispatchOut(std::addressof(m_forward), 17, *out, .override_pid = m_pid));
    }
    Result NifmGeneralShim::GetInternetConnectionStatus(ams::sf::Out<NifmInternetConnectionStatus> out) {
        NoteForward(18);
        R_RETURN(serviceMitmDispatchOut(std::addressof(m_forward), 18, *out, .override_pid = m_pid));
    }
    Result NifmGeneralShim::IsEthernetCommunicationEnabled(ams::sf::Out<u8> out) {
        NoteForward(20);
        R_RETURN(serviceMitmDispatchOut(std::addressof(m_forward), 20, *out, .override_pid = m_pid));
    }
    Result NifmGeneralShim::IsAnyInternetRequestAccepted(ams::sf::Out<u8> out,
                                                         const NifmClientIdData &client_id) {
        NoteForward(21);
        R_RETURN(serviceMitmDispatchOut(
            std::addressof(m_forward), 21, *out,
            .buffer_attrs = { SfBufferAttr_In | SfBufferAttr_HipcPointer | SfBufferAttr_FixedSize },
            .buffers = { { std::addressof(client_id), sizeof(NifmClientIdData) } },
            .override_pid = m_pid));
    }
    Result NifmGeneralShim::IsAnyForegroundRequestAccepted(ams::sf::Out<u8> out) {
        NoteForward(22);
        R_RETURN(serviceMitmDispatchOut(std::addressof(m_forward), 22, *out, .override_pid = m_pid));
    }
    Result NifmGeneralShim::PutToSleep() {
        NoteForward(23);
        R_RETURN(serviceMitmDispatch(std::addressof(m_forward), 23, .override_pid = m_pid));
    }
    Result NifmGeneralShim::WakeUp() {
        NoteForward(24);
        R_RETURN(serviceMitmDispatch(std::addressof(m_forward), 24, .override_pid = m_pid));
    }
    Result NifmGeneralShim::SetWowlDelayedWakeTime(s32 value) {
        NoteForward(43);
        R_RETURN(serviceMitmDispatchIn(std::addressof(m_forward), 43, value, .override_pid = m_pid));
    }
    Result NifmGeneralShim::IsWiredConnectionAvailable(ams::sf::Out<u8> out) {
        NoteForward(44);
        R_RETURN(serviceMitmDispatchOut(std::addressof(m_forward), 44, *out, .override_pid = m_pid));
    }
    Result NifmGeneralShim::IsNetworkEmulationFeatureEnabled(ams::sf::Out<u8> out) {
        NoteForward(45);
        R_RETURN(serviceMitmDispatchOut(std::addressof(m_forward), 45, *out, .override_pid = m_pid));
    }
    Result NifmGeneralShim::SelectActiveNetworkEmulationProfileIdForDebug(u32 profile_id) {
        NoteForward(46);
        R_RETURN(serviceMitmDispatchIn(std::addressof(m_forward), 46, profile_id, .override_pid = m_pid));
    }
    Result NifmGeneralShim::GetScanData(ams::sf::Out<u32> out_count, u32 filter,
                                        const ams::sf::OutMapAliasBuffer &out_data) {
        NoteForward(47);
        R_RETURN(serviceMitmDispatchInOut(
            std::addressof(m_forward), 47, filter, *out_count,
            .buffer_attrs = { SfBufferAttr_Out | SfBufferAttr_HipcMapAlias },
            .buffers = { { out_data.GetPointer(), out_data.GetSize() } },
            .override_pid = m_pid));
    }
    Result NifmGeneralShim::ResetActiveNetworkEmulationProfileId() {
        NoteForward(48);
        R_RETURN(serviceMitmDispatch(std::addressof(m_forward), 48, .override_pid = m_pid));
    }
    Result NifmGeneralShim::GetActiveNetworkEmulationProfileId(ams::sf::Out<u32> out) {
        NoteForward(49);
        R_RETURN(serviceMitmDispatchOut(std::addressof(m_forward), 49, *out, .override_pid = m_pid));
    }
    Result NifmGeneralShim::IsRewriteFeatureEnabled(ams::sf::Out<u8> out) {
        NoteForward(50);
        R_RETURN(serviceMitmDispatchOut(std::addressof(m_forward), 50, *out, .override_pid = m_pid));
    }
    Result NifmGeneralShim::CreateRewriteRule(ams::sf::Out<u64> out_rule_id, u8 enabled,
                                              const NifmRewriteRuleData &rule) {
        NoteForward(51);
        R_RETURN(serviceMitmDispatchInOut(
            std::addressof(m_forward), 51, enabled, *out_rule_id,
            .buffer_attrs = { SfBufferAttr_In | SfBufferAttr_HipcMapAlias | SfBufferAttr_FixedSize },
            .buffers = { { std::addressof(rule), sizeof(rule) } },
            .override_pid = m_pid));
    }
    Result NifmGeneralShim::DestroyRewriteRule(u64 rule_id) {
        NoteForward(52);
        R_RETURN(serviceMitmDispatchIn(std::addressof(m_forward), 52, rule_id, .override_pid = m_pid));
    }
    Result NifmGeneralShim::IsActiveNetworkEmulationProfileIdSelected(ams::sf::Out<u8> out) {
        NoteForward(53);
        R_RETURN(serviceMitmDispatchOut(std::addressof(m_forward), 53, *out, .override_pid = m_pid));
    }
    Result NifmGeneralShim::SelectDefaultNetworkEmulationProfileId(u32 profile_id) {
        NoteForward(54);
        R_RETURN(serviceMitmDispatchIn(std::addressof(m_forward), 54, profile_id, .override_pid = m_pid));
    }
    Result NifmGeneralShim::GetDefaultNetworkEmulationProfileId(ams::sf::Out<u32> out) {
        NoteForward(55);
        R_RETURN(serviceMitmDispatchOut(std::addressof(m_forward), 55, *out, .override_pid = m_pid));
    }
    Result NifmGeneralShim::GetNetworkEmulationProfile(ams::sf::Out<NifmNetworkEmulationProfile> out,
                                                       u32 profile_id) {
        NoteForward(56);
        R_RETURN(serviceMitmDispatchIn(
            std::addressof(m_forward), 56, profile_id,
            .buffer_attrs = { SfBufferAttr_Out | SfBufferAttr_HipcAutoSelect | SfBufferAttr_FixedSize },
            .buffers = { { out.GetPointer(), sizeof(NifmNetworkEmulationProfile) } },
            .override_pid = m_pid));
    }
    Result NifmGeneralShim::SetWowlTcpKeepAliveTimeout(u32 timeout) {
        NoteForward(57);
        R_RETURN(serviceMitmDispatchIn(std::addressof(m_forward), 57, timeout, .override_pid = m_pid));
    }
    Result NifmRequestShim::GetRequestState(ams::sf::Out<u32> out) {
        /* Ryujinx's known-working Splatoon 3 LAN path does not submit a host
         * NIFM request. Its state is Error while Guest Internet Access is off
         * (the required boot configuration), then Available as soon as that
         * toggle is enabled inside the Shoal. Mirror the same edge using the
         * selected ZeroTier network's assigned address. Wire recovery is
         * handled independently by Port, so a short uplink pause does not make
         * the game's NIFM request fail and emit 2110-0101. */
        if (UsesRyujinxNifmRequestModel(m_program_id)) {
            constexpr u32 Error = 1;
            constexpr u32 Available = 3;
            const bool lan_requested = m_connection_confirmation_option == 1;
            bool enabled = RyujinxInternetEnabled(m_program_id, lan_requested);

            /* The successful boot-safe capture distinguishes the two uses of
             * this IRequest: option 4 is the startup availability check, while
             * option 1 is submitted when LAN mode is initialized in the Shoal.
             * Never make option 4 available during offline startup. For option
             * 1, keep the request available while Port reconnects its wire. */
            if (lan_requested && !m_ryujinx_shoal_wait_complete && g_port != nullptr) {
                m_ryujinx_shoal_wait_complete = true;
                NoteNifm("ryu shoal title %016llx wire %s; keeping LAN state available",
                         (unsigned long long)m_program_id,
                         g_port->LanTransportReady() ? "ready" : "paused");
            }

            const u32 state = enabled ? Available : Error;
            *out = state;
            NoteNifm("ryu state title %016llx value %u virtual %s wire %s",
                     (unsigned long long)m_program_id, state,
                     enabled ? "ready" : "offline",
                     (g_port != nullptr && g_port->LanTransportReady()) ? "ready" : "paused");
            R_SUCCEED();
        }

        u32 state = 0;
        const Result rc = serviceMitmDispatchOut(
            std::addressof(m_forward), 0, state, .override_pid = m_pid);
        if (R_SUCCEEDED(rc)) {
            /* HOS reported Available roughly three seconds before ZeroTier's
             * UDP/9993 transport recovered in the 2026-08-27 Shoal capture.
             * Returning a fabricated OnHold could consume NIFM's final state
             * event and strand the game forever, so hold this one IPC reply
             * instead. The node runs on another thread and can recover while
             * we wait. A strict timeout preserves stock behavior if the
             * virtual network cannot come back. */
            if (state == 3 && !m_readiness_barrier_complete &&
                FindLanTitle(m_program_id) != nullptr && g_port != nullptr) {
                m_readiness_barrier_complete = true;
                if (!g_port->LanTransportReady()) {
                    const int64_t started = ztnx::NowMs();
                    NoteNifm("barrier title %016llx waiting for ZT wire",
                             (unsigned long long)m_program_id);
                    const bool ready = g_port->WaitForLanTransportReady(
                        NifmTransportBarrierTimeoutMs);
                    const int64_t waited = ztnx::NowMs() - started;
                    NoteNifm("barrier title %016llx %s after %lld ms",
                             (unsigned long long)m_program_id,
                             ready ? "ready" : "TIMEOUT",
                             (long long)waited);
                }
            }

            *out = state;
            NoteNifm("typed state title %016llx value %u",
                     (unsigned long long)m_program_id, state);
        }
        R_RETURN(rc);
    }

    Result NifmRequestShim::GetResult() {
        if (UsesRyujinxNifmRequestModel(m_program_id)) {
            NoteNifm("ryu result title %016llx success",
                     (unsigned long long)m_program_id);
            R_SUCCEED();
        }

        /* Preserve Nintendo's exact result. The state trace proved Splatoon
         * ignores GetResult success until IRequest reaches state 3, so the
         * earlier 0x8AE6E/0xDE6E normalization changed no game behavior. */
        R_RETURN(serviceMitmDispatch(
            std::addressof(m_forward), 1, .override_pid = m_pid));
    }
    Result NifmRequestShim::GetEvents(ams::sf::OutCopyHandle state, ams::sf::OutCopyHandle event) {
        if (UsesRyujinxNifmRequestModel(m_program_id)) {
            /* Ryujinx creates two private KEvents for IRequest and never
             * signals either one. Do the same instead of exposing events from
             * the real Nintendo request whose genuine state remains Error
             * while our compatibility surface reports Available. That
             * event/state contradiction is the last material difference in
             * the sequence immediately preceding Splatoon's nnSdk assertion. */
            if (!m_ryujinx_events_initialized) {
                R_TRY(ams::os::CreateSystemEvent(
                    m_ryujinx_state_event.GetBase(),
                    ams::os::EventClearMode_ManualClear, true));

                const Result rc = ams::os::CreateSystemEvent(
                    m_ryujinx_result_event.GetBase(),
                    ams::os::EventClearMode_ManualClear, true);
                if (R_FAILED(rc)) {
                    ams::os::DestroySystemEvent(m_ryujinx_state_event.GetBase());
                    R_THROW(rc);
                }
                m_ryujinx_events_initialized = true;
                NoteNifm("ryu events title %016llx local unsignalled",
                         (unsigned long long)m_program_id);
            }

            state.SetValue(m_ryujinx_state_event.GetReadableHandle(), false);
            event.SetValue(m_ryujinx_result_event.GetReadableHandle(), false);
            R_SUCCEED();
        }

        ::Handle handles[2]={INVALID_HANDLE,INVALID_HANDLE};
        R_TRY(serviceMitmDispatch(std::addressof(m_forward),2,.out_handle_attrs={SfOutHandleAttr_HipcCopy,SfOutHandleAttr_HipcCopy},.out_handles=handles,.override_pid=m_pid));
        state.SetValue(handles[0],true); event.SetValue(handles[1],true); R_SUCCEED();
    }
    Result NifmRequestShim::Cancel() {
        m_readiness_barrier_complete = false;
        m_ryujinx_shoal_wait_complete = false;
        if (UsesRyujinxNifmRequestModel(m_program_id)) {
            NoteNifm("ryu cancel title %016llx success",
                     (unsigned long long)m_program_id);
            R_SUCCEED();
        }
        R_RETURN(serviceMitmDispatch(std::addressof(m_forward), 3, .override_pid = m_pid));
    }
    Result NifmRequestShim::Submit() {
        m_readiness_barrier_complete = false;
        m_ryujinx_shoal_wait_complete = false;
        if (UsesRyujinxNifmRequestModel(m_program_id)) {
            /* Deliberately do not submit the real Nintendo request. Apart from
             * matching Ryujinx, this prevents NIFM from re-arbitrating the
             * Wi-Fi route just as ZeroTier is resuming after Shoal's radio
             * transition. */
            NoteNifm("ryu submit title %016llx no-op success",
                     (unsigned long long)m_program_id);
            R_SUCCEED();
        }
        R_RETURN(serviceMitmDispatch(std::addressof(m_forward), 4, .override_pid = m_pid));
    }
    Result NifmRequestShim::SetRequirement(const NifmRequirement &requirement) {
        NoteForward(5);
        R_RETURN(serviceMitmDispatchIn(std::addressof(m_forward), 5, requirement, .override_pid = m_pid));
    }
    Result NifmRequestShim::SetNetworkProfileId(const NifmUuid &profile_id) {
        NoteForward(9);
        R_RETURN(serviceMitmDispatchIn(std::addressof(m_forward), 9, profile_id, .override_pid = m_pid));
    }
    Result NifmRequestShim::SetConnectionConfirmationOption(s8 option) {
        if (UsesRyujinxNifmRequestModel(m_program_id)) {
            m_connection_confirmation_option = option;
            /* A later option-1 request is a fresh LAN initialization attempt
             * and gets its own single bounded recovery wait. */
            if (option == 1) { m_ryujinx_shoal_wait_complete = false; }
            NoteNifm("ryu confirm title %016llx option %d no-op success",
                     (unsigned long long)m_program_id, static_cast<int>(option));
            R_SUCCEED();
        }
        R_RETURN(serviceMitmDispatchIn(
            std::addressof(m_forward), 11, option, .override_pid = m_pid));
    }
    Result NifmRequestShim::SetPersistent() {
        NoteForward(12);
        R_RETURN(serviceMitmDispatch(std::addressof(m_forward), 12, .override_pid = m_pid));
    }
    Result NifmRequestShim::GetRequirement(ams::sf::Out<NifmRequirement> out) {
        NoteForward(19);
        R_RETURN(serviceMitmDispatchOut(std::addressof(m_forward), 19, *out, .override_pid = m_pid));
    }
    Result NifmRequestShim::GetAppletInfo(ams::sf::Out<NifmAppletInfo> out, u32 theme_color,
                                          const ams::sf::OutMapAliasBuffer &out_data) {
        NoteForward(21);
        R_RETURN(serviceMitmDispatchInOut(
            std::addressof(m_forward), 21, theme_color, *out,
            .buffer_attrs = { SfBufferAttr_Out | SfBufferAttr_HipcMapAlias },
            .buffers = { { out_data.GetPointer(), out_data.GetSize() } },
            .override_pid = m_pid));
    }
    Result NifmRequestShim::SetKeptInSleep(u8 kept) {
        NoteForward(23);
        R_RETURN(serviceMitmDispatchIn(std::addressof(m_forward), 23, kept, .override_pid = m_pid));
    }
    Result NifmRequestShim::RegisterSocketDescriptor(s32 fd) {
        NoteForward(24);
        R_RETURN(serviceMitmDispatchIn(std::addressof(m_forward), 24, fd, .override_pid = m_pid));
    }
    Result NifmRequestShim::UnregisterSocketDescriptor(s32 fd) {
        NoteForward(25);
        R_RETURN(serviceMitmDispatchIn(std::addressof(m_forward), 25, fd, .override_pid = m_pid));
    }
    Result NifmRequestShim::GetNetworkAccessStatus(ams::sf::Out<NifmNetworkAccessStatus> out) {
        NoteForward(26);
        R_RETURN(serviceMitmDispatch(
            std::addressof(m_forward), 26,
            .buffer_attrs = { SfBufferAttr_Out | SfBufferAttr_HipcPointer | SfBufferAttr_FixedSize },
            .buffers = { { out.GetPointer(), sizeof(NifmNetworkAccessStatus) } },
            .override_pid = m_pid));
    }
}
