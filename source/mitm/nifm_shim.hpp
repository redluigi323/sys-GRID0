/* Title-scoped nifm:u address-identity proxy for native LAN-mode games. */
#pragma once

#include <stratosphere.hpp>

namespace ztnx { class Port; }
namespace ztnx::mitm {
    namespace hos = ::ams::hos;
    using Result = ::ams::Result;
    struct NifmIpV4Address { u8 addr[4]; };
    struct NifmIpAddressSetting { u8 automatic; NifmIpV4Address current, mask, gateway; };
    struct NifmDnsSetting { u8 automatic; NifmIpV4Address primary, secondary; };
    struct NifmIpConfigInfo { NifmIpAddressSetting ip; NifmDnsSetting dns; };
    static_assert(sizeof(NifmIpConfigInfo) == 22);

    struct NifmUuid { u8 data[0x10]; };
    struct NifmInternetConnectionStatus { u8 interface_type, wifi_strength, state; };
    struct NifmRequirement { u8 data[0x24]; };
    struct NifmAppletInfo { u32 applet_id, mode, data_size; };
    static_assert(sizeof(NifmUuid) == 0x10);
    static_assert(sizeof(NifmInternetConnectionStatus) == 3);
    static_assert(sizeof(NifmRequirement) == 0x24);
    static_assert(sizeof(NifmAppletInfo) == 0x0C);

    /* These payloads are intentionally opaque. Their sizes and transfer modes
     * come from Nintendo's IPC metadata; the proxy only relays the bytes. */
    struct NifmRewriteRuleData : ams::sf::LargeData, ams::sf::PrefersMapAliasTransferMode {
        u8 data[0x410];
    };
    struct NifmNetworkEmulationProfile : ams::sf::LargeData, ams::sf::PrefersAutoSelectTransferMode {
        u8 data[0x1438];
    };
    struct NifmNetworkAccessStatus : ams::sf::LargeData {
        u8 data[0x100];
    };
    struct NifmClientIdData : ams::sf::LargeData {
        u32 id;
    };
    /* libnx's NifmSfNetworkProfileData starts with NifmIpSettingData, whose
     * first 22 bytes are exactly IpAddressSetting + DnsSetting. Keep the rest
     * opaque, but expose that prefix: Splatoon 3 calls command 5 and obtains
     * its address from this profile instead of commands 12/15. */
    struct NifmSfNetworkProfileData : ams::sf::LargeData {
        NifmIpConfigInfo ip_config;
        u8 opaque[0x17C - sizeof(NifmIpConfigInfo)];
    };
    static_assert(sizeof(NifmRewriteRuleData) == 0x410);
    static_assert(sizeof(NifmNetworkEmulationProfile) == 0x1438);
    static_assert(sizeof(NifmNetworkAccessStatus) == 0x100);
    static_assert(sizeof(NifmClientIdData) == 0x4);
    static_assert(sizeof(NifmSfNetworkProfileData) == 0x17C);
}

#define AMS_ZTNX_NIFM_REQUEST(C, H) \
    AMS_SF_METHOD_INFO(C, H, 0, Result, GetRequestState, (ams::sf::Out<u32> out), (out)) \
    AMS_SF_METHOD_INFO(C, H, 1, Result, GetResult, (), ()) \
    AMS_SF_METHOD_INFO(C, H, 2, Result, GetEvents, (ams::sf::OutCopyHandle state, ams::sf::OutCopyHandle event), (state, event)) \
    AMS_SF_METHOD_INFO(C, H, 3, Result, Cancel, (), ()) \
    AMS_SF_METHOD_INFO(C, H, 4, Result, Submit, (), ()) \
    AMS_SF_METHOD_INFO(C, H, 5, Result, SetRequirement, (const ztnx::mitm::NifmRequirement &requirement), (requirement)) \
    AMS_SF_METHOD_INFO(C, H, 9, Result, SetNetworkProfileId, (const ztnx::mitm::NifmUuid &profile_id), (profile_id)) \
    AMS_SF_METHOD_INFO(C, H, 11, Result, SetConnectionConfirmationOption, (s8 option), (option)) \
    AMS_SF_METHOD_INFO(C, H, 12, Result, SetPersistent, (), ()) \
    AMS_SF_METHOD_INFO(C, H, 19, Result, GetRequirement, (ams::sf::Out<ztnx::mitm::NifmRequirement> out), (out)) \
    AMS_SF_METHOD_INFO(C, H, 21, Result, GetAppletInfo, (ams::sf::Out<ztnx::mitm::NifmAppletInfo> out, u32 theme_color, const ams::sf::OutMapAliasBuffer &out_data), (out, theme_color, out_data)) \
    AMS_SF_METHOD_INFO(C, H, 23, Result, SetKeptInSleep, (u8 kept), (kept), hos::Version_3_0_0) \
    AMS_SF_METHOD_INFO(C, H, 24, Result, RegisterSocketDescriptor, (s32 fd), (fd), hos::Version_3_0_0) \
    AMS_SF_METHOD_INFO(C, H, 25, Result, UnregisterSocketDescriptor, (s32 fd), (fd), hos::Version_3_0_0) \
    AMS_SF_METHOD_INFO(C, H, 26, Result, GetNetworkAccessStatus, (ams::sf::Out<ztnx::mitm::NifmNetworkAccessStatus> out), (out), hos::Version_21_0_0)
AMS_SF_DEFINE_INTERFACE(ztnx::mitm, INifmRequestShim, AMS_ZTNX_NIFM_REQUEST, 0x5A544E52)

#define AMS_ZTNX_NIFM_GENERAL(C, H) \
    AMS_SF_METHOD_INFO(C, H, 1, Result, GetClientId, (ams::sf::Out<ztnx::mitm::NifmClientIdData> out), (out)) \
    AMS_SF_METHOD_INFO(C, H, 4, Result, CreateRequest, (ams::sf::Out<ams::sf::SharedPointer<ztnx::mitm::INifmRequestShim>> out, s32 type), (out, type)) \
    AMS_SF_METHOD_INFO(C, H, 5, Result, GetCurrentNetworkProfile, (ams::sf::Out<ztnx::mitm::NifmSfNetworkProfileData> out), (out)) \
    AMS_SF_METHOD_INFO(C, H, 7, Result, EnumerateNetworkProfiles, (ams::sf::Out<s32> out_count, u8 type, const ams::sf::OutMapAliasBuffer &out_profiles), (out_count, type, out_profiles)) \
    AMS_SF_METHOD_INFO(C, H, 8, Result, GetNetworkProfile, (ams::sf::Out<ztnx::mitm::NifmSfNetworkProfileData> out, const ztnx::mitm::NifmUuid &profile_id), (out, profile_id)) \
    AMS_SF_METHOD_INFO(C, H, 9, Result, SetNetworkProfile, (ams::sf::Out<ztnx::mitm::NifmUuid> out_profile_id, const ztnx::mitm::NifmSfNetworkProfileData &profile), (out_profile_id, profile)) \
    AMS_SF_METHOD_INFO(C, H, 12, Result, GetCurrentIpAddress, (ams::sf::Out<ztnx::mitm::NifmIpV4Address> out), (out)) \
    AMS_SF_METHOD_INFO(C, H, 15, Result, GetCurrentIpConfigInfo, (ams::sf::Out<ztnx::mitm::NifmIpConfigInfo> out), (out)) \
    AMS_SF_METHOD_INFO(C, H, 17, Result, IsWirelessCommunicationEnabled, (ams::sf::Out<u8> out), (out)) \
    AMS_SF_METHOD_INFO(C, H, 18, Result, GetInternetConnectionStatus, (ams::sf::Out<ztnx::mitm::NifmInternetConnectionStatus> out), (out)) \
    AMS_SF_METHOD_INFO(C, H, 20, Result, IsEthernetCommunicationEnabled, (ams::sf::Out<u8> out), (out)) \
    AMS_SF_METHOD_INFO(C, H, 21, Result, IsAnyInternetRequestAccepted, (ams::sf::Out<u8> out, const ztnx::mitm::NifmClientIdData &client_id), (out, client_id)) \
    AMS_SF_METHOD_INFO(C, H, 22, Result, IsAnyForegroundRequestAccepted, (ams::sf::Out<u8> out), (out)) \
    AMS_SF_METHOD_INFO(C, H, 23, Result, PutToSleep, (), ()) \
    AMS_SF_METHOD_INFO(C, H, 24, Result, WakeUp, (), ()) \
    AMS_SF_METHOD_INFO(C, H, 43, Result, SetWowlDelayedWakeTime, (s32 value), (value), hos::Version_9_0_0) \
    AMS_SF_METHOD_INFO(C, H, 44, Result, IsWiredConnectionAvailable, (ams::sf::Out<u8> out), (out), hos::Version_18_0_0) \
    AMS_SF_METHOD_INFO(C, H, 45, Result, IsNetworkEmulationFeatureEnabled, (ams::sf::Out<u8> out), (out), hos::Version_18_0_0) \
    AMS_SF_METHOD_INFO(C, H, 46, Result, SelectActiveNetworkEmulationProfileIdForDebug, (u32 profile_id), (profile_id), hos::Version_18_0_0) \
    AMS_SF_METHOD_INFO(C, H, 47, Result, GetScanData, (ams::sf::Out<u32> out_count, u32 filter, const ams::sf::OutMapAliasBuffer &out_data), (out_count, filter, out_data), hos::Version_18_0_1) \
    AMS_SF_METHOD_INFO(C, H, 48, Result, ResetActiveNetworkEmulationProfileId, (), (), hos::Version_20_0_0) \
    AMS_SF_METHOD_INFO(C, H, 49, Result, GetActiveNetworkEmulationProfileId, (ams::sf::Out<u32> out), (out), hos::Version_18_0_0) \
    AMS_SF_METHOD_INFO(C, H, 50, Result, IsRewriteFeatureEnabled, (ams::sf::Out<u8> out), (out), hos::Version_18_0_0) \
    AMS_SF_METHOD_INFO(C, H, 51, Result, CreateRewriteRule, (ams::sf::Out<u64> out_rule_id, u8 enabled, const ztnx::mitm::NifmRewriteRuleData &rule), (out_rule_id, enabled, rule), hos::Version_18_0_0) \
    AMS_SF_METHOD_INFO(C, H, 52, Result, DestroyRewriteRule, (u64 rule_id), (rule_id), hos::Version_18_0_0) \
    AMS_SF_METHOD_INFO(C, H, 53, Result, IsActiveNetworkEmulationProfileIdSelected, (ams::sf::Out<u8> out), (out), hos::Version_20_0_0) \
    AMS_SF_METHOD_INFO(C, H, 54, Result, SelectDefaultNetworkEmulationProfileId, (u32 profile_id), (profile_id), hos::Version_20_0_0) \
    AMS_SF_METHOD_INFO(C, H, 55, Result, GetDefaultNetworkEmulationProfileId, (ams::sf::Out<u32> out), (out), hos::Version_20_0_0) \
    AMS_SF_METHOD_INFO(C, H, 56, Result, GetNetworkEmulationProfile, (ams::sf::Out<ztnx::mitm::NifmNetworkEmulationProfile> out, u32 profile_id), (out, profile_id), hos::Version_20_0_0) \
    AMS_SF_METHOD_INFO(C, H, 57, Result, SetWowlTcpKeepAliveTimeout, (u32 timeout), (timeout), hos::Version_20_0_0)
AMS_SF_DEFINE_INTERFACE(ztnx::mitm, INifmGeneralShim, AMS_ZTNX_NIFM_GENERAL, 0x5A544E47)

#define AMS_ZTNX_NIFM_ROOT(C, H) \
    AMS_SF_METHOD_INFO(C, H, 5, Result, CreateGeneralService, (ams::sf::Out<ams::sf::SharedPointer<ztnx::mitm::INifmGeneralShim>> out, const ams::sf::ClientProcessId &pid), (out, pid))
/* This object is installed on an SM MITM port, but its client-facing IPC is a
 * fully local proxy. Marking it as an sf MITM object makes unknown dispatches
 * try ServerSession::ForwardRequest even though this local session has no
 * framework forward service. */
AMS_SF_DEFINE_INTERFACE(ztnx::mitm, INifmShim, AMS_ZTNX_NIFM_ROOT, 0x5A544E46)

namespace ztnx::mitm {
    class NifmRequestShim {
        Service m_forward;
        u64 m_pid;
        u64 m_program_id;
        bool m_readiness_barrier_complete{false};
        s8 m_connection_confirmation_option{0};
        bool m_ryujinx_shoal_wait_complete{false};
        ams::os::SystemEvent m_ryujinx_state_event;
        ams::os::SystemEvent m_ryujinx_result_event;
        bool m_ryujinx_events_initialized{false};
      public:
        NifmRequestShim(Service forward, u64 pid, u64 program_id) :
            m_forward(forward), m_pid(pid), m_program_id(program_id) { }
        ~NifmRequestShim() { serviceClose(std::addressof(m_forward)); }
        NifmRequestShim(const NifmRequestShim &) = delete;
        NifmRequestShim &operator=(const NifmRequestShim &) = delete;
        #define ZTNX_DECLARE(C, I, R, N, A, AN, V0, V1) R N A;
        AMS_ZTNX_NIFM_REQUEST(NifmRequestShim, ZTNX_DECLARE)
        #undef ZTNX_DECLARE
    };
    class NifmGeneralShim {
        Service m_forward;
        u64 m_pid;
        u64 m_program_id;
      public:
        NifmGeneralShim(Service forward, u64 pid, u64 program_id) :
            m_forward(forward), m_pid(pid), m_program_id(program_id) { }
        ~NifmGeneralShim() { serviceClose(std::addressof(m_forward)); }
        NifmGeneralShim(const NifmGeneralShim &) = delete;
        NifmGeneralShim &operator=(const NifmGeneralShim &) = delete;
        #define ZTNX_DECLARE(C, I, R, N, A, AN, V0, V1) R N A;
        AMS_ZTNX_NIFM_GENERAL(NifmGeneralShim, ZTNX_DECLARE)
        #undef ZTNX_DECLARE
    };
    class NifmShim {
        std::shared_ptr<Service> m_forward; ams::sm::MitmProcessInfo m_client;
      public:
        NifmShim(std::shared_ptr<Service> &&forward, const ams::sm::MitmProcessInfo &client) : m_forward(std::move(forward)), m_client(client) { }
        static bool ShouldMitm(const ams::sm::MitmProcessInfo &client);
        Result CreateGeneralService(ams::sf::Out<ams::sf::SharedPointer<INifmGeneralShim>> out, const ams::sf::ClientProcessId &pid);
    };
    void SetNifmPort(ztnx::Port *port);
}
