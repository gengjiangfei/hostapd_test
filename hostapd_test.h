#ifndef __HOSAT_TEST_H__
#define __HOSAT_TEST_H__

#ifndef IFNAMSIZ
#define IFNAMSIZ 16
#endif
struct l2_packet_data
{
	int fd; /* packet socket for EAPOL frames */
	char ifname[IFNAMSIZ + 1];
	int ifindex;
	u8 own_addr[ETH_ALEN];
	void (*rx_callback)(void *ctx, const u8 *src_addr,const u8 *buf, size_t len);
	void *rx_callback_ctx;
	int l2_hdr; /* whether to include layer 2 (Ethernet) header data
		     * buffers */

};

struct sta_info
{
	struct sta_info *next; /* next entry in sta list */
	struct sta_info *hnext; /* next entry in hash table list */
	u8 addr[6];
	be32 ipaddr;
	u16 aid; /* STA's unique AID (1 .. 2007) or 0 if not yet assigned */
	u32 flags; /* Bitfield of WLAN_STA_* */
};



/**
 * struct wpa_driver_ops - Driver interface API definition
 *
 * This structure defines the API that each driver interface needs to implement
 * for core wpa_supplicant code. All driver specific functionality is captured
 * in this wrapper.
 */
struct wpa_driver_ops
{
	const char *name;
	const char *desc;
	int (*get_bssid)(void *priv, u8 *bssid);
	int (*get_ssid)(void *priv, u8 *ssid);
	int (*set_key)(const char *ifname, void *priv, enum wpa_alg alg,
		       const u8 *addr, int key_idx, int set_tx,
		       const u8 *seq, size_t seq_len,
		       const u8 *key, size_t key_len);

	void * (*init)(void *ctx, const char *ifname);

	void (*deinit)(void *priv);
	int (*set_param)(void *priv, const char *param);
	int (*set_countermeasures)(void *priv, int enabled);
	int (*deauthenticate)(void *priv, const u8 *addr, int reason_code);
	int (*associate)(void *priv,
			 struct wpa_driver_associate_params *params);
	int (*add_pmkid)(void *priv, const u8 *bssid, const u8 *pmkid);
	int (*remove_pmkid)(void *priv, const u8 *bssid, const u8 *pmkid);
	int (*flush_pmkid)(void *priv);
	int (*get_capa)(void *priv, struct wpa_driver_capa *capa);
	void (*poll)(void *priv);
	unsigned int (*get_ifindex)(void *priv);
	const char * (*get_ifname)(void *priv);
	const u8 * (*get_mac_addr)(void *priv);
	int (*set_operstate)(void *priv, int state);
	int (*mlme_setprotection)(void *priv, const u8 *addr, int protect_type,
				  int key_type);
	int (*send_mlme)(void *priv, const u8 *data, size_t data_len,
			 int noack, unsigned int freq, const u16 *csa_offs,
			 size_t csa_offs_len);
	struct wpa_interface_info * (*get_interfaces)(void *global_priv);

	int (*authenticate)(void *priv,
			    struct wpa_driver_auth_params *params);
	int (*set_ap)(void *priv, struct wpa_driver_ap_params *params);
	int (*set_acl)(void *priv, struct hostapd_acl_params *params);
	void * (*hapd_init)(struct hostapd_data *hapd,struct wpa_init_params *params);

	void (*hapd_deinit)(void *priv);
	int (*set_ieee8021x)(void *priv, struct wpa_bss_params *params);
	int (*set_privacy)(void *priv, int enabled);

	int (*get_seqnum)(const char *ifname, void *priv, const u8 *addr,
			  int idx, u8 *seq);
	int (*flush)(void *priv);
	int (*read_sta_data)(void *priv, struct hostap_sta_driver_data *data,
			     const u8 *addr);
	int (*hapd_send_eapol)(void *priv, const u8 *addr, const u8 *data,
			       size_t data_len, int encrypt,
			       const u8 *own_addr, u32 flags);
	int (*sta_deauth)(void *priv, const u8 *own_addr, const u8 *addr,
			  int reason);
	int (*sta_disassoc)(void *priv, const u8 *own_addr, const u8 *addr,
			    int reason);
	int (*sta_remove)(void *priv, const u8 *addr);
	int (*hapd_get_ssid)(void *priv, u8 *buf, int len);

	int (*hapd_set_ssid)(void *priv, const u8 *buf, int len);
	int (*hapd_set_countermeasures)(void *priv, int enabled);
	int (*sta_add)(void *priv, struct hostapd_sta_add_params *params);
    int (*sta_clear_stats)(void *priv, const u8 *addr);
	int (*if_add)(void *priv, enum wpa_driver_if_type type,
		      const char *ifname, const u8 *addr, void *bss_ctx,
		      void **drv_priv, char *force_ifname, u8 *if_addr,
		      const char *bridge, int use_existing, int setup_ap);

	int (*if_remove)(void *priv, enum wpa_driver_if_type type,
			 const char *ifname);
	int (*send_ether)(void *priv, const u8 *dst, const u8 *src, u16 proto,
			  const u8 *data, size_t data_len);
};

/**
 * struct hostapd_data - hostapd per-BSS data structure
 */
struct hostapd_data
{
//	struct hostapd_iface *iface;
//	struct hostapd_config *iconf;
//	struct hostapd_bss_config *conf;
//	int interface_added; /* virtual interface added for this BSS */
//	unsigned int started:1;
//	unsigned int disabled:1;
//	unsigned int reenable_beacon:1;
	u8 own_addr[ETH_ALEN];
	int num_sta; /* number of entries in sta_list */
	struct sta_info *sta_list; /* STA info list head */
#define STA_HASH_SIZE 256
#define STA_HASH(sta) (sta[5])
	struct sta_info *sta_hash[STA_HASH_SIZE];
#define AID_WORDS ((2008 + 31) / 32)
	u32 sta_aid[AID_WORDS];
	const struct wpa_driver_ops *driver;
	void *drv_priv;
	void (*new_assoc_sta_cb)(struct hostapd_data *hapd,struct sta_info *sta, int reassoc);
	struct wpa_authenticator *wpa_auth;
//	struct eapol_authenticator *eapol_auth;
//	struct rsn_preauth_interface *preauth_iface;
//	struct os_reltime michael_mic_failure;
	int michael_mic_failures;
	int tkip_countermeasures;
	struct l2_packet_data *l2;
};

struct wpa_init_params
{
	void *global_priv;
	const u8 *bssid;
	const char *ifname;
	const char *driver_params;
	u8 *own_addr; /* buffer for writing own MAC address */
};

/***************************** start===>ieee802_11_defs.h*************************************/
#ifndef __packed
#define __packed    __attribute__((__packed__))
#endif

struct ieee80211_hdr
{
	le16 frame_control;
	le16 duration_id;
	u8 addr1[6];
	u8 addr2[6];
	u8 addr3[6];
	le16 seq_ctrl;
	/* followed by 'u8 addr4[6];' if ToDS and FromDS is set in data frame
	 */
} STRUCT_PACKED;

struct ieee80211req_mlme
{
	u_int8_t	im_op;		/* operation to perform */
#define	IEEE80211_MLME_ASSOC		1	/* associate station */
#define	IEEE80211_MLME_DISASSOC		2	/* disassociate station */
#define	IEEE80211_MLME_DEAUTH		3	/* deauthenticate station */
#define	IEEE80211_MLME_AUTHORIZE	4	/* authorize station */
#define	IEEE80211_MLME_UNAUTHORIZE	5	/* unauthorize station */
#define	IEEE80211_MLME_STOP_BSS		6	/* stop bss */
#define	IEEE80211_MLME_CLEAR_STATS	7	/* clear station statistic */
#define	IEEE80211_MLME_AUTH	        8	/* auth resp to station */
#define	IEEE80211_MLME_REASSOC	    9	/* reassoc to station */
#define	IEEE80211_MLME_AUTH_FILS    10	/* AUTH - when FILS enabled */
	u_int8_t	im_ssid_len;	/* length of optional ssid */
	u_int16_t	im_reason;	/* 802.11 reason code */
	u_int16_t	im_seq;	        /* seq for auth */
	u_int8_t	im_macaddr[IEEE80211_ADDR_LEN];
	u_int8_t	im_ssid[IEEE80211_NWID_LEN];
	u_int8_t    im_optie[IEEE80211_MAX_OPT_IE];
	u_int16_t   im_optie_len;
//	struct      ieee80211req_fils_aad  fils_aad;
} __packed;

#define IEEE80211_HDRLEN (sizeof(struct ieee80211_hdr))
#define WLAN_FC_GET_TYPE(fc)	(((fc) & 0x000c) >> 2)
#define WLAN_FC_GET_STYPE(fc)	(((fc) & 0x00f0) >> 4)

#define WLAN_FC_TYPE_MGMT		0
#define WLAN_FC_TYPE_CTRL		1
#define WLAN_FC_TYPE_DATA		2

#define WLAN_FC_STYPE_ASSOC_REQ		0
#define WLAN_FC_STYPE_ASSOC_RESP	1
#define WLAN_FC_STYPE_REASSOC_REQ	2
#define WLAN_FC_STYPE_REASSOC_RESP	3
#define WLAN_FC_STYPE_PROBE_REQ		4
#define WLAN_FC_STYPE_PROBE_RESP	5
#define WLAN_FC_STYPE_BEACON		8
#define WLAN_FC_STYPE_ATIM		9
#define WLAN_FC_STYPE_DISASSOC		10
#define WLAN_FC_STYPE_AUTH		11
#define WLAN_FC_STYPE_DEAUTH		12
#define WLAN_FC_STYPE_ACTION		13

/* Reason codes (IEEE Std 802.11-2016, 9.4.1.7, Table 9-45) */
#define WLAN_REASON_UNSPECIFIED 1
#define WLAN_REASON_PREV_AUTH_NOT_VALID 2
#define WLAN_REASON_DEAUTH_LEAVING 3
#define WLAN_REASON_DISASSOC_DUE_TO_INACTIVITY 4
#define WLAN_REASON_DISASSOC_AP_BUSY 5
#define WLAN_REASON_CLASS2_FRAME_FROM_NONAUTH_STA 6
#define WLAN_REASON_CLASS3_FRAME_FROM_NONASSOC_STA 7
#define WLAN_REASON_DISASSOC_STA_HAS_LEFT 8
#define WLAN_REASON_STA_REQ_ASSOC_WITHOUT_AUTH 9
#define WLAN_REASON_PWR_CAPABILITY_NOT_VALID 10
#define WLAN_REASON_SUPPORTED_CHANNEL_NOT_VALID 11
#define WLAN_REASON_BSS_TRANSITION_DISASSOC 12
#define WLAN_REASON_INVALID_IE 13
#define WLAN_REASON_MICHAEL_MIC_FAILURE 14
#define WLAN_REASON_4WAY_HANDSHAKE_TIMEOUT 15
#define WLAN_REASON_GROUP_KEY_UPDATE_TIMEOUT 16
#define WLAN_REASON_IE_IN_4WAY_DIFFERS 17
#define WLAN_REASON_GROUP_CIPHER_NOT_VALID 18
#define WLAN_REASON_PAIRWISE_CIPHER_NOT_VALID 19
#define WLAN_REASON_AKMP_NOT_VALID 20
#define WLAN_REASON_UNSUPPORTED_RSN_IE_VERSION 21
#define WLAN_REASON_INVALID_RSN_IE_CAPAB 22
#define WLAN_REASON_IEEE_802_1X_AUTH_FAILED 23
#define WLAN_REASON_CIPHER_SUITE_REJECTED 24
#define WLAN_REASON_TDLS_TEARDOWN_UNREACHABLE 25
#define WLAN_REASON_TDLS_TEARDOWN_UNSPECIFIED 26
#define WLAN_REASON_SSP_REQUESTED_DISASSOC 27
#define WLAN_REASON_NO_SSP_ROAMING_AGREEMENT 28
#define WLAN_REASON_BAD_CIPHER_OR_AKM 29
#define WLAN_REASON_NOT_AUTHORIZED_THIS_LOCATION 30
#define WLAN_REASON_SERVICE_CHANGE_PRECLUDES_TS 31
#define WLAN_REASON_UNSPECIFIED_QOS_REASON 32
#define WLAN_REASON_NOT_ENOUGH_BANDWIDTH 33
#define WLAN_REASON_DISASSOC_LOW_ACK 34
#define WLAN_REASON_EXCEEDED_TXOP 35
#define WLAN_REASON_STA_LEAVING 36
#define WLAN_REASON_END_TS_BA_DLS 37
#define WLAN_REASON_UNKNOWN_TS_BA 38
#define WLAN_REASON_TIMEOUT 39
#define WLAN_REASON_PEERKEY_MISMATCH 45
#define WLAN_REASON_AUTHORIZED_ACCESS_LIMIT_REACHED 46
#define WLAN_REASON_EXTERNAL_SERVICE_REQUIREMENTS 47
#define WLAN_REASON_INVALID_FT_ACTION_FRAME_COUNT 48
#define WLAN_REASON_INVALID_PMKID 49
#define WLAN_REASON_INVALID_MDE 50
#define WLAN_REASON_INVALID_FTE 51
#define WLAN_REASON_MESH_PEERING_CANCELLED 52
#define WLAN_REASON_MESH_MAX_PEERS 53
#define WLAN_REASON_MESH_CONFIG_POLICY_VIOLATION 54
#define WLAN_REASON_MESH_CLOSE_RCVD 55
#define WLAN_REASON_MESH_MAX_RETRIES 56
#define WLAN_REASON_MESH_CONFIRM_TIMEOUT 57
#define WLAN_REASON_MESH_INVALID_GTK 58
#define WLAN_REASON_MESH_INCONSISTENT_PARAMS 59
#define WLAN_REASON_MESH_INVALID_SECURITY_CAP 60
#define WLAN_REASON_MESH_PATH_ERROR_NO_PROXY_INFO 61
#define WLAN_REASON_MESH_PATH_ERROR_NO_FORWARDING_INFO 62
#define WLAN_REASON_MESH_PATH_ERROR_DEST_UNREACHABLE 63
#define WLAN_REASON_MAC_ADDRESS_ALREADY_EXISTS_IN_MBSS 64
#define WLAN_REASON_MESH_CHANNEL_SWITCH_REGULATORY_REQ 65
#define WLAN_REASON_MESH_CHANNEL_SWITCH_UNSPECIFIED 66

#define WLAN_EID_SSID 0
#define WLAN_EID_SUPP_RATES 1
#define WLAN_EID_DS_PARAMS 3
#define WLAN_EID_CF_PARAMS 4
#define WLAN_EID_TIM 5
#define WLAN_EID_IBSS_PARAMS 6
#define WLAN_EID_COUNTRY 7
#define WLAN_EID_REQUEST 10
#define WLAN_EID_BSS_LOAD 11
#define WLAN_EID_EDCA_PARAM_SET 12
#define WLAN_EID_TSPEC 13
#define WLAN_EID_TCLAS 14
#define WLAN_EID_SCHEDULE 15
#define WLAN_EID_CHALLENGE 16
#define WLAN_EID_PWR_CONSTRAINT 32
#define WLAN_EID_PWR_CAPABILITY 33
#define WLAN_EID_TPC_REQUEST 34
#define WLAN_EID_TPC_REPORT 35
#define WLAN_EID_SUPPORTED_CHANNELS 36
#define WLAN_EID_CHANNEL_SWITCH 37
#define WLAN_EID_MEASURE_REQUEST 38
#define WLAN_EID_MEASURE_REPORT 39
#define WLAN_EID_QUIET 40
#define WLAN_EID_IBSS_DFS 41
#define WLAN_EID_ERP_INFO 42
#define WLAN_EID_TS_DELAY 43
#define WLAN_EID_TCLAS_PROCESSING 44
#define WLAN_EID_HT_CAP 45
#define WLAN_EID_QOS 46
#define WLAN_EID_RSN 48
#define WLAN_EID_EXT_SUPP_RATES 50
#define WLAN_EID_AP_CHANNEL_REPORT 51
#define WLAN_EID_NEIGHBOR_REPORT 52
#define WLAN_EID_RCPI 53
#define WLAN_EID_MOBILITY_DOMAIN 54
#define WLAN_EID_FAST_BSS_TRANSITION 55
#define WLAN_EID_TIMEOUT_INTERVAL 56
#define WLAN_EID_RIC_DATA 57
#define WLAN_EID_DSE_REGISTERED_LOCATION 58
#define WLAN_EID_SUPPORTED_OPERATING_CLASSES 59
#define WLAN_EID_EXT_CHANSWITCH_ANN 60
#define WLAN_EID_HT_OPERATION 61
#define WLAN_EID_SECONDARY_CHANNEL_OFFSET 62
#define WLAN_EID_BSS_AVERAGE_ACCESS_DELAY 63
#define WLAN_EID_ANTENNA 64
#define WLAN_EID_RSNI 65
#define WLAN_EID_MEASUREMENT_PILOT_TRANSMISSION 66
#define WLAN_EID_BSS_AVAILABLE_ADM_CAPA 67
#define WLAN_EID_BSS_AC_ACCESS_DELAY 68 /* note: also used by WAPI */
#define WLAN_EID_TIME_ADVERTISEMENT 69
#define WLAN_EID_RRM_ENABLED_CAPABILITIES 70
#define WLAN_EID_MULTIPLE_BSSID 71
#define WLAN_EID_20_40_BSS_COEXISTENCE 72
#define WLAN_EID_20_40_BSS_INTOLERANT 73
#define WLAN_EID_OVERLAPPING_BSS_SCAN_PARAMS 74
#define WLAN_EID_RIC_DESCRIPTOR 75
#define WLAN_EID_MMIE 76
#define WLAN_EID_EVENT_REQUEST 78
#define WLAN_EID_EVENT_REPORT 79
#define WLAN_EID_DIAGNOSTIC_REQUEST 80
#define WLAN_EID_DIAGNOSTIC_REPORT 81
#define WLAN_EID_LOCATION_PARAMETERS 82
#define WLAN_EID_NONTRANSMITTED_BSSID_CAPA 83
#define WLAN_EID_SSID_LIST 84
#define WLAN_EID_MLTIPLE_BSSID_INDEX 85
#define WLAN_EID_FMS_DESCRIPTOR 86
#define WLAN_EID_FMS_REQUEST 87
#define WLAN_EID_FMS_RESPONSE 88
#define WLAN_EID_QOS_TRAFFIC_CAPABILITY 89
#define WLAN_EID_BSS_MAX_IDLE_PERIOD 90
#define WLAN_EID_TFS_REQ 91
#define WLAN_EID_TFS_RESP 92
#define WLAN_EID_WNMSLEEP 93
#define WLAN_EID_TIM_BROADCAST_REQUEST 94
#define WLAN_EID_TIM_BROADCAST_RESPONSE 95
#define WLAN_EID_COLLOCATED_INTERFERENCE_REPORT 96
#define WLAN_EID_CHANNEL_USAGE 97
#define WLAN_EID_TIME_ZONE 98
#define WLAN_EID_DMS_REQUEST 99
#define WLAN_EID_DMS_RESPONSE 100
#define WLAN_EID_LINK_ID 101
#define WLAN_EID_WAKEUP_SCHEDULE 102
#define WLAN_EID_CHANNEL_SWITCH_TIMING 104
#define WLAN_EID_PTI_CONTROL 105
#define WLAN_EID_TPU_BUFFER_STATUS 106
#define WLAN_EID_INTERWORKING 107
#define WLAN_EID_ADV_PROTO 108
#define WLAN_EID_EXPEDITED_BANDWIDTH_REQ 109
#define WLAN_EID_QOS_MAP_SET 110
#define WLAN_EID_ROAMING_CONSORTIUM 111
#define WLAN_EID_EMERGENCY_ALERT_ID 112
#define WLAN_EID_MESH_CONFIG 113
#define WLAN_EID_MESH_ID 114
#define WLAN_EID_MESH_LINK_METRIC_REPORT 115
#define WLAN_EID_CONGESTION_NOTIFICATION 116
#define WLAN_EID_PEER_MGMT 117
#define WLAN_EID_MESH_CHANNEL_SWITCH_PARAMETERS 118
#define WLAN_EID_MESH_AWAKE_WINDOW 119
#define WLAN_EID_BEACON_TIMING 120
#define WLAN_EID_MCCAOP_SETUP_REQUEST 121
#define WLAN_EID_MCCAOP_SETUP_REPLY 122
#define WLAN_EID_MCCAOP_ADVERTISEMENT 123
#define WLAN_EID_MCCAOP_TEARDOWN 124
#define WLAN_EID_GANN 125
#define WLAN_EID_RANN 126
#define WLAN_EID_EXT_CAPAB 127
#define WLAN_EID_PREQ 130
#define WLAN_EID_PREP 131
#define WLAN_EID_PERR 132
#define WLAN_EID_PXU 137
#define WLAN_EID_PXUC 138
#define WLAN_EID_AMPE 139
#define WLAN_EID_MIC 140
#define WLAN_EID_DESTINATION_URI 141
#define WLAN_EID_U_APSD_COEX 142
#define WLAN_EID_DMG_WAKEUP_SCHEDULE 143
#define WLAN_EID_EXTENDED_SCHEDULE 144
#define WLAN_EID_STA_AVAILABILITY 145
#define WLAN_EID_DMG_TSPEC 146
#define WLAN_EID_NEXT_DMG_ATI 147
#define WLAN_EID_DMG_CAPABILITIES 148
#define WLAN_EID_DMG_OPERATION 151
#define WLAN_EID_DMG_BSS_PARAMETER_CHANGE 152
#define WLAN_EID_DMG_BEAM_REFINEMENT 153
#define WLAN_EID_CHANNEL_MEASUREMENT_FEEDBACK 154
#define WLAN_EID_CCKM 156
#define WLAN_EID_AWAKE_WINDOW 157
#define WLAN_EID_MULTI_BAND 158
#define WLAN_EID_ADDBA_EXTENSION 159
#define WLAN_EID_NEXTPCP_LIST 160
#define WLAN_EID_PCP_HANDOVER 161
#define WLAN_EID_DMG_LINK_MARGIN 162
#define WLAN_EID_SWITCHING_STREAM 163
#define WLAN_EID_SESSION_TRANSITION 164
#define WLAN_EID_DYNAMIC_TONE_PAIRING_REPORT 165
#define WLAN_EID_CLUSTER_REPORT 166
#define WLAN_EID_REPLAY_CAPABILITIES 167
#define WLAN_EID_RELAY_TRANSFER_PARAM_SET 168
#define WLAN_EID_BEAMLINK_MAINTENANCE 169
#define WLAN_EID_MULTIPLE_MAC_SUBLAYERS 170
#define WLAN_EID_U_PID 171
#define WLAN_EID_DMG_LINK_ADAPTATION_ACK 172
#define WLAN_EID_MCCAOP_ADVERTISEMENT_OVERVIEW 174
#define WLAN_EID_QUIET_PERIOD_REQUEST 175
#define WLAN_EID_QUIET_PERIOD_RESPONSE 177
#define WLAN_EID_QMF_POLICY 181
#define WLAN_EID_ECAPC_POLICY 182
#define WLAN_EID_CLUSTER_TIME_OFFSET 183
#define WLAN_EID_INTRA_ACCESS_CATEGORY_PRIORITY 184
#define WLAN_EID_SCS_DESCRIPTOR 185
#define WLAN_EID_QLOAD_REPORT 186
#define WLAN_EID_HCCA_TXOP_UPDATE_COUNT 187
#define WLAN_EID_HIGHER_LAYER_STREAM_ID 188
#define WLAN_EID_GCR_GROUP_ADDRESS 189
#define WLAN_EID_ANTENNA_SECTOR_ID_PATTERN 190
#define WLAN_EID_VHT_CAP 191
#define WLAN_EID_VHT_OPERATION 192
#define WLAN_EID_VHT_EXTENDED_BSS_LOAD 193
#define WLAN_EID_VHT_WIDE_BW_CHSWITCH  194
#define WLAN_EID_VHT_TRANSMIT_POWER_ENVELOPE 195
#define WLAN_EID_VHT_CHANNEL_SWITCH_WRAPPER 196
#define WLAN_EID_VHT_AID 197
#define WLAN_EID_VHT_QUIET_CHANNEL 198
#define WLAN_EID_VHT_OPERATING_MODE_NOTIFICATION 199
#define WLAN_EID_UPSIM 200
#define WLAN_EID_REDUCED_NEIGHBOR_REPORT 201
#define WLAN_EID_TVHT_OPERATION 202
#define WLAN_EID_DEVICE_LOCATION 204
#define WLAN_EID_WHITE_SPACE_MAP 205
#define WLAN_EID_FTM_PARAMETERS 206
#define WLAN_EID_VENDOR_SPECIFIC 221
#define WLAN_EID_CAG_NUMBER 237
#define WLAN_EID_AP_CSN 239
#define WLAN_EID_FILS_INDICATION 240
#define WLAN_EID_DILS 241
#define WLAN_EID_FRAGMENT 242
#define WLAN_EID_EXTENSION 255

#define WLAN_STATUS_SUCCESS 0
#define WLAN_STATUS_UNSPECIFIED_FAILURE 1
#define WLAN_STATUS_TDLS_WAKEUP_ALTERNATE 2
#define WLAN_STATUS_TDLS_WAKEUP_REJECT 3
#define WLAN_STATUS_SECURITY_DISABLED 5
#define WLAN_STATUS_UNACCEPTABLE_LIFETIME 6
#define WLAN_STATUS_NOT_IN_SAME_BSS 7
#define WLAN_STATUS_CAPS_UNSUPPORTED 10
#define WLAN_STATUS_REASSOC_NO_ASSOC 11
#define WLAN_STATUS_ASSOC_DENIED_UNSPEC 12
#define WLAN_STATUS_NOT_SUPPORTED_AUTH_ALG 13
#define WLAN_STATUS_UNKNOWN_AUTH_TRANSACTION 14
#define WLAN_STATUS_CHALLENGE_FAIL 15
#define WLAN_STATUS_AUTH_TIMEOUT 16
#define WLAN_STATUS_AP_UNABLE_TO_HANDLE_NEW_STA 17
#define WLAN_STATUS_ASSOC_DENIED_RATES 18
#define WLAN_STATUS_ASSOC_DENIED_NOSHORT 19
#define WLAN_STATUS_SPEC_MGMT_REQUIRED 22
#define WLAN_STATUS_PWR_CAPABILITY_NOT_VALID 23
#define WLAN_STATUS_SUPPORTED_CHANNEL_NOT_VALID 24
#define WLAN_STATUS_ASSOC_DENIED_NO_SHORT_SLOT_TIME 25
#define WLAN_STATUS_ASSOC_DENIED_NO_HT 27
#define WLAN_STATUS_R0KH_UNREACHABLE 28
#define WLAN_STATUS_ASSOC_DENIED_NO_PCO 29
#define WLAN_STATUS_ASSOC_REJECTED_TEMPORARILY 30
#define WLAN_STATUS_ROBUST_MGMT_FRAME_POLICY_VIOLATION 31
#define WLAN_STATUS_UNSPECIFIED_QOS_FAILURE 32
#define WLAN_STATUS_DENIED_INSUFFICIENT_BANDWIDTH 33
#define WLAN_STATUS_DENIED_POOR_CHANNEL_CONDITIONS 34
#define WLAN_STATUS_DENIED_QOS_NOT_SUPPORTED 35
#define WLAN_STATUS_REQUEST_DECLINED 37
#define WLAN_STATUS_INVALID_PARAMETERS 38
#define WLAN_STATUS_REJECTED_WITH_SUGGESTED_CHANGES 39
#define WLAN_STATUS_INVALID_IE 40
#define WLAN_STATUS_GROUP_CIPHER_NOT_VALID 41
#define WLAN_STATUS_PAIRWISE_CIPHER_NOT_VALID 42
#define WLAN_STATUS_AKMP_NOT_VALID 43
#define WLAN_STATUS_UNSUPPORTED_RSN_IE_VERSION 44
#define WLAN_STATUS_INVALID_RSN_IE_CAPAB 45
#define WLAN_STATUS_CIPHER_REJECTED_PER_POLICY 46
#define WLAN_STATUS_TS_NOT_CREATED 47
#define WLAN_STATUS_DIRECT_LINK_NOT_ALLOWED 48
#define WLAN_STATUS_DEST_STA_NOT_PRESENT 49
#define WLAN_STATUS_DEST_STA_NOT_QOS_STA 50
#define WLAN_STATUS_ASSOC_DENIED_LISTEN_INT_TOO_LARGE 51
#define WLAN_STATUS_INVALID_FT_ACTION_FRAME_COUNT 52
#define WLAN_STATUS_INVALID_PMKID 53
#define WLAN_STATUS_INVALID_MDIE 54
#define WLAN_STATUS_INVALID_FTIE 55
#define WLAN_STATUS_REQUESTED_TCLAS_NOT_SUPPORTED 56
#define WLAN_STATUS_INSUFFICIENT_TCLAS_PROCESSING_RESOURCES 57
#define WLAN_STATUS_TRY_ANOTHER_BSS 58
#define WLAN_STATUS_GAS_ADV_PROTO_NOT_SUPPORTED 59
#define WLAN_STATUS_NO_OUTSTANDING_GAS_REQ 60
#define WLAN_STATUS_GAS_RESP_NOT_RECEIVED 61
#define WLAN_STATUS_STA_TIMED_OUT_WAITING_FOR_GAS_RESP 62
#define WLAN_STATUS_GAS_RESP_LARGER_THAN_LIMIT 63
#define WLAN_STATUS_REQ_REFUSED_HOME 64
#define WLAN_STATUS_ADV_SRV_UNREACHABLE 65
#define WLAN_STATUS_REQ_REFUSED_SSPN 67
#define WLAN_STATUS_REQ_REFUSED_UNAUTH_ACCESS 68
#define WLAN_STATUS_INVALID_RSNIE 72
#define WLAN_STATUS_U_APSD_COEX_NOT_SUPPORTED 73
#define WLAN_STATUS_U_APSD_COEX_MODE_NOT_SUPPORTED 74
#define WLAN_STATUS_BAD_INTERVAL_WITH_U_APSD_COEX 75
#define WLAN_STATUS_ANTI_CLOGGING_TOKEN_REQ 76
#define WLAN_STATUS_FINITE_CYCLIC_GROUP_NOT_SUPPORTED 77
#define WLAN_STATUS_CANNOT_FIND_ALT_TBTT 78
#define WLAN_STATUS_TRANSMISSION_FAILURE 79
#define WLAN_STATUS_REQ_TCLAS_NOT_SUPPORTED 80
#define WLAN_STATUS_TCLAS_RESOURCES_EXCHAUSTED 81
#define WLAN_STATUS_REJECTED_WITH_SUGGESTED_BSS_TRANSITION 82
#define WLAN_STATUS_REJECT_WITH_SCHEDULE 83
#define WLAN_STATUS_REJECT_NO_WAKEUP_SPECIFIED 84
#define WLAN_STATUS_SUCCESS_POWER_SAVE_MODE 85
#define WLAN_STATUS_PENDING_ADMITTING_FST_SESSION 86
#define WLAN_STATUS_PERFORMING_FST_NOW 87
#define WLAN_STATUS_PENDING_GAP_IN_BA_WINDOW 88
#define WLAN_STATUS_REJECT_U_PID_SETTING 89
#define WLAN_STATUS_REFUSED_EXTERNAL_REASON 92
#define WLAN_STATUS_REFUSED_AP_OUT_OF_MEMORY 93
#define WLAN_STATUS_REJECTED_EMERGENCY_SERVICE_NOT_SUPPORTED 94
#define WLAN_STATUS_QUERY_RESP_OUTSTANDING 95
#define WLAN_STATUS_REJECT_DSE_BAND 96
#define WLAN_STATUS_TCLAS_PROCESSING_TERMINATED 97
#define WLAN_STATUS_TS_SCHEDULE_CONFLICT 98
#define WLAN_STATUS_DENIED_WITH_SUGGESTED_BAND_AND_CHANNEL 99
#define WLAN_STATUS_MCCAOP_RESERVATION_CONFLICT 100
#define WLAN_STATUS_MAF_LIMIT_EXCEEDED 101
#define WLAN_STATUS_MCCA_TRACK_LIMIT_EXCEEDED 102
#define WLAN_STATUS_DENIED_DUE_TO_SPECTRUM_MANAGEMENT 103
#define WLAN_STATUS_ASSOC_DENIED_NO_VHT 104
#define WLAN_STATUS_ENABLEMENT_DENIED 105
#define WLAN_STATUS_RESTRICTION_FROM_AUTHORIZED_GDB 106
#define WLAN_STATUS_AUTHORIZATION_DEENABLED 107
#define WLAN_STATUS_FILS_AUTHENTICATION_FAILURE 112
#define WLAN_STATUS_UNKNOWN_AUTHENTICATION_SERVER 113
/*****************************end ===>ieee802_11_defs.h*************************************/

/*****************************************start===>wpa_common.h*********************************/
struct wpa_ie_data {
	int proto;
	int pairwise_cipher;
	int group_cipher;
	int key_mgmt;
	int capabilities;
	size_t num_pmkid;
	const u8 *pmkid;
	int mgmt_group_cipher;
};
struct wpa_ie_hdr {
	u8 elem_id;
	u8 len;
	u8 oui[4]; /* 24-bit OUI followed by 8-bit OUI type */
	u8 version[2]; /* little endian */
} STRUCT_PACKED;

struct rsn_ie_hdr {
	u8 elem_id; /* WLAN_EID_RSN */
	u8 len;
	u8 version[2]; /* little endian */
} STRUCT_PACKED;

#define PMKID_LEN 16
#define PMK_LEN 32
#define PMK_LEN_SUITE_B_192 48
#define PMK_LEN_MAX 48
#define WPA_REPLAY_COUNTER_LEN 8
#define WPA_NONCE_LEN 32
#define WPA_KEY_RSC_LEN 8
#define WPA_GMK_LEN 32
#define WPA_GTK_MAX_LEN 32

static inline u32 WPA_GET_BE32(const u8 *a)
{
	return ((u32) a[0] << 24) | (a[1] << 16) | (a[2] << 8) | a[3];
}
#define RSN_SELECTOR_GET(a) WPA_GET_BE32((const u8 *) (a))

#define WPA_SELECTOR_LEN 4
#define WPA_VERSION 1
#define RSN_SELECTOR_LEN 4
#define RSN_VERSION 1
#define RSN_SELECTOR(a, b, c, d) \
	((((u32) (a)) << 24) | (((u32) (b)) << 16) | (((u32) (c)) << 8) | (u32) (d))
	
#define WPA_OUI_TYPE RSN_SELECTOR(0x00, 0x50, 0xf2, 1)
#define WPA_AUTH_KEY_MGMT_NONE RSN_SELECTOR(0x00, 0x50, 0xf2, 0)
#define WPA_AUTH_KEY_MGMT_UNSPEC_802_1X RSN_SELECTOR(0x00, 0x50, 0xf2, 1)
#define WPA_AUTH_KEY_MGMT_PSK_OVER_802_1X RSN_SELECTOR(0x00, 0x50, 0xf2, 2)
#define WPA_AUTH_KEY_MGMT_CCKM RSN_SELECTOR(0x00, 0x40, 0x96, 0)
#define WPA_CIPHER_SUITE_NONE RSN_SELECTOR(0x00, 0x50, 0xf2, 0)
#define WPA_CIPHER_SUITE_TKIP RSN_SELECTOR(0x00, 0x50, 0xf2, 2)
#define WPA_CIPHER_SUITE_CCMP RSN_SELECTOR(0x00, 0x50, 0xf2, 4)

#define RSN_AUTH_KEY_MGMT_UNSPEC_802_1X RSN_SELECTOR(0x00, 0x0f, 0xac, 1)
#define RSN_AUTH_KEY_MGMT_PSK_OVER_802_1X RSN_SELECTOR(0x00, 0x0f, 0xac, 2)
#define RSN_CIPHER_SUITE_CCMP RSN_SELECTOR(0x00, 0x0f, 0xac, 4)
#define RSN_CIPHER_SUITE_NONE RSN_SELECTOR(0x00, 0x0f, 0xac, 0)
#define RSN_CIPHER_SUITE_TKIP RSN_SELECTOR(0x00, 0x0f, 0xac, 2)
#define RSN_SELECTOR_PUT(a, val) WPA_PUT_BE32((u8 *) (a), (val))
/*****************************************end===>wpa_common.h*********************************/

/*****************************************start===>common.h*********************************/
#ifndef bswap_16
#define bswap_16(a) ((((u16) (a) << 8) & 0xff00) | (((u16) (a) >> 8) & 0xff))
#endif
#define le_to_host16(n) bswap_16(n)

#ifndef MAC2STR
#define MAC2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]
#define MACSTR "%02x:%02x:%02x:%02x:%02x:%02x"
#endif

static inline u16 WPA_GET_BE16(const u8 *a)
{
	return (a[0] << 8) | a[1];
}

static inline void WPA_PUT_BE16(u8 *a, u16 val)
{
	a[0] = val >> 8;
	a[1] = val & 0xff;
}

static inline u16 WPA_GET_LE16(const u8 *a)
{
	return (a[1] << 8) | a[0];
}

static inline void WPA_PUT_LE16(u8 *a, u16 val)
{
	a[1] = val >> 8;
	a[0] = val & 0xff;
}

static inline u32 WPA_GET_BE32(const u8 *a)
{
	return ((u32) a[0] << 24) | (a[1] << 16) | (a[2] << 8) | a[3];
}

static inline void WPA_PUT_BE32(u8 *a, u32 val)
{
	a[0] = (val >> 24) & 0xff;
	a[1] = (val >> 16) & 0xff;
	a[2] = (val >> 8) & 0xff;
	a[3] = val & 0xff;
}

static inline u32 WPA_GET_LE32(const u8 *a)
{
	return ((u32) a[3] << 24) | (a[2] << 16) | (a[1] << 8) | a[0];
}

static inline void WPA_PUT_LE32(u8 *a, u32 val)
{
	a[3] = (val >> 24) & 0xff;
	a[2] = (val >> 16) & 0xff;
	a[1] = (val >> 8) & 0xff;
	a[0] = val & 0xff;
}

#define SSID_MAX_LEN 32
#ifndef BIT
#define BIT(x) (1U << (x))
#endif
/* Parsed Information Elements */
#define MAX_NOF_MB_IES_SUPPORTED 5

struct mb_ies_info {
	struct {
		const u8 *ie;
		u8 ie_len;
	} ies[MAX_NOF_MB_IES_SUPPORTED];
	u8 nof_ies;
};
struct ieee802_11_elems {
	const u8 *ssid;
	const u8 *supp_rates;
	const u8 *ds_params;
	const u8 *challenge;
	const u8 *erp_info;
	const u8 *ext_supp_rates;
	const u8 *wpa_ie;
	const u8 *rsn_ie;
	const u8 *wmm; /* WMM Information or Parameter Element */
	const u8 *wmm_tspec;
	const u8 *wps_ie;
	const u8 *supp_channels;
	const u8 *mdie;
	const u8 *ftie;
	const u8 *timeout_int;
	const u8 *ht_capabilities;
	const u8 *ht_operation;
	const u8 *mesh_config;
	const u8 *mesh_id;
	const u8 *peer_mgmt;
	const u8 *vht_capabilities;
	const u8 *vht_operation;
	const u8 *vht_opmode_notif;
	const u8 *vendor_ht_cap;
	const u8 *vendor_vht;
	const u8 *p2p;
	const u8 *wfd;
	const u8 *link_id;
	const u8 *interworking;
	const u8 *qos_map_set;
	const u8 *hs20;
	const u8 *ext_capab;
	const u8 *bss_max_idle_period;
	const u8 *ssid_list;
	const u8 *osen;
	const u8 *mbo;
	const u8 *ampe;
	const u8 *mic;
	const u8 *pref_freq_list;
	const u8 *supp_op_classes;
	const u8 *rrm_enabled;
	const u8 *cag_number;
	const u8 *ap_csn;
	const u8 *fils_indic;
	const u8 *dils;
	const u8 *assoc_delay_info;
	const u8 *fils_req_params;
	const u8 *fils_key_confirm;
	const u8 *fils_session;
	const u8 *fils_hlp;
	const u8 *fils_ip_addr_assign;
	const u8 *key_delivery;
	const u8 *fils_wrapped_data;
	const u8 *fils_pk;
	const u8 *fils_nonce;

	u8 ssid_len;
	u8 supp_rates_len;
	u8 challenge_len;
	u8 ext_supp_rates_len;
	u8 wpa_ie_len;
	u8 rsn_ie_len;
	u8 wmm_len; /* 7 = WMM Information; 24 = WMM Parameter */
	u8 wmm_tspec_len;
	u8 wps_ie_len;
	u8 supp_channels_len;
	u8 mdie_len;
	u8 ftie_len;
	u8 mesh_config_len;
	u8 mesh_id_len;
	u8 peer_mgmt_len;
	u8 vendor_ht_cap_len;
	u8 vendor_vht_len;
	u8 p2p_len;
	u8 wfd_len;
	u8 interworking_len;
	u8 qos_map_set_len;
	u8 hs20_len;
	u8 ext_capab_len;
	u8 ssid_list_len;
	u8 osen_len;
	u8 mbo_len;
	u8 ampe_len;
	u8 mic_len;
	u8 pref_freq_list_len;
	u8 supp_op_classes_len;
	u8 rrm_enabled_len;
	u8 cag_number_len;
	u8 fils_indic_len;
	u8 dils_len;
	u8 fils_req_params_len;
	u8 fils_key_confirm_len;
	u8 fils_hlp_len;
	u8 fils_ip_addr_assign_len;
	u8 key_delivery_len;
	u8 fils_wrapped_data_len;
	u8 fils_pk_len;

	struct mb_ies_info mb_ies;
};

/*****************************************end===>common.h*********************************/

/****************************************start===>list.h***************************************/
#define dl_list_entry(item, type, member) \
	((type *) ((char *) item - offsetof(type, member)))

#define dl_list_for_each_safe(item, n, list, type, member) \
	for (item = dl_list_entry((list)->next, type, member), \
		     n = dl_list_entry(item->member.next, type, member); \
	     &item->member != (list); \
	     item = n, n = dl_list_entry(n->member.next, type, member))

static inline void dl_list_del(struct dl_list *item)
{
	item->next->prev = item->prev;
	item->prev->next = item->next;
	item->next = NULL;
	item->prev = NULL;
}
/***************************************end===>list.h******************************************/

/****************************************start===>eloop.h***************************************/
#define ELOOP_ALL_CTX (void *) -1
/***************************************end===>eloop.h******************************************/

/*****************************************start===>driver.h**********************************/
/**
 * union wpa_event_data - Additional data for wpa_supplicant_event() calls
 */
union wpa_event_data
{
	/**
	 * struct assoc_info - Data for EVENT_ASSOC and EVENT_ASSOCINFO events
	 *
	 * This structure is optional for EVENT_ASSOC calls and required for
	 * EVENT_ASSOCINFO calls. By using EVENT_ASSOC with this data, the
	 * driver interface does not need to generate separate EVENT_ASSOCINFO
	 * calls.
	 */
	struct assoc_info {
		/**
		 * reassoc - Flag to indicate association or reassociation
		 */
		int reassoc;

		/**
		 * req_ies - (Re)Association Request IEs
		 *
		 * If the driver generates WPA/RSN IE, this event data must be
		 * returned for WPA handshake to have needed information. If
		 * wpa_supplicant-generated WPA/RSN IE is used, this
		 * information event is optional.
		 *
		 * This should start with the first IE (fixed fields before IEs
		 * are not included).
		 */
		const u8 *req_ies;

		/**
		 * req_ies_len - Length of req_ies in bytes
		 */
		size_t req_ies_len;

		/**
		 * resp_ies - (Re)Association Response IEs
		 *
		 * Optional association data from the driver. This data is not
		 * required WPA, but may be useful for some protocols and as
		 * such, should be reported if this is available to the driver
		 * interface.
		 *
		 * This should start with the first IE (fixed fields before IEs
		 * are not included).
		 */
		const u8 *resp_ies;

		/**
		 * resp_ies_len - Length of resp_ies in bytes
		 */
		size_t resp_ies_len;

		/**
		 * resp_frame - (Re)Association Response frame
		 */
		const u8 *resp_frame;

		/**
		 * resp_frame_len - (Re)Association Response frame length
		 */
		size_t resp_frame_len;

		/**
		 * beacon_ies - Beacon or Probe Response IEs
		 *
		 * Optional Beacon/ProbeResp data: IEs included in Beacon or
		 * Probe Response frames from the current AP (i.e., the one
		 * that the client just associated with). This information is
		 * used to update WPA/RSN IE for the AP. If this field is not
		 * set, the results from previous scan will be used. If no
		 * data for the new AP is found, scan results will be requested
		 * again (without scan request). At this point, the driver is
		 * expected to provide WPA/RSN IE for the AP (if WPA/WPA2 is
		 * used).
		 *
		 * This should start with the first IE (fixed fields before IEs
		 * are not included).
		 */
		const u8 *beacon_ies;

		/**
		 * beacon_ies_len - Length of beacon_ies */
		size_t beacon_ies_len;

		/**
		 * freq - Frequency of the operational channel in MHz
		 */
		unsigned int freq;

		/**
		 * wmm_params - WMM parameters used in this association.
		 */
		struct wmm_params wmm_params;

		/**
		 * addr - Station address (for AP mode)
		 */
		const u8 *addr;

		/**
		 * The following is the key management offload information
		 * @authorized
		 * @key_replay_ctr
		 * @key_replay_ctr_len
		 * @ptk_kck
		 * @ptk_kek_len
		 * @ptk_kek
		 * @ptk_kek_len
		 */

		/**
		 * authorized - Status of key management offload,
		 * 1 = successful
		 */
		int authorized;

		/**
		 * key_replay_ctr - Key replay counter value last used
		 * in a valid EAPOL-Key frame
		 */
		const u8 *key_replay_ctr;

		/**
		 * key_replay_ctr_len - The length of key_replay_ctr
		 */
		size_t key_replay_ctr_len;

		/**
		 * ptk_kck - The derived PTK KCK
		 */
		const u8 *ptk_kck;

		/**
		 * ptk_kek_len - The length of ptk_kck
		 */
		size_t ptk_kck_len;

		/**
		 * ptk_kek - The derived PTK KEK
		 */
		const u8 *ptk_kek;

		/**
		 * ptk_kek_len - The length of ptk_kek
		 */
		size_t ptk_kek_len;

		/**
		 * subnet_status - The subnet status:
		 * 0 = unknown, 1 = unchanged, 2 = changed
		 */
		u8 subnet_status;
	} assoc_info;

	/**
	 * struct disassoc_info - Data for EVENT_DISASSOC events
	 */
	struct disassoc_info
    {
		/**
		 * addr - Station address (for AP mode)
		 */
		const u8 *addr;

		/**
		 * reason_code - Reason Code (host byte order) used in
		 *	Deauthentication frame
		 */
		u16 reason_code;

		/**
		 * ie - Optional IE(s) in Disassociation frame
		 */
		const u8 *ie;

		/**
		 * ie_len - Length of ie buffer in octets
		 */
		size_t ie_len;

		/**
		 * locally_generated - Whether the frame was locally generated
		 */
		int locally_generated;
	} disassoc_info;

	/**
	 * struct deauth_info - Data for EVENT_DEAUTH events
	 */
	struct deauth_info {
		/**
		 * addr - Station address (for AP mode)
		 */
		const u8 *addr;

		/**
		 * reason_code - Reason Code (host byte order) used in
		 *	Deauthentication frame
		 */
		u16 reason_code;

		/**
		 * ie - Optional IE(s) in Deauthentication frame
		 */
		const u8 *ie;

		/**
		 * ie_len - Length of ie buffer in octets
		 */
		size_t ie_len;

		/**
		 * locally_generated - Whether the frame was locally generated
		 */
		int locally_generated;
	} deauth_info;

	/**
	 * struct michael_mic_failure - Data for EVENT_MICHAEL_MIC_FAILURE
	 */
	struct michael_mic_failure {
		int unicast;
		const u8 *src;
	} michael_mic_failure;

	/**
	 * struct interface_status - Data for EVENT_INTERFACE_STATUS
	 */
	struct interface_status {
		unsigned int ifindex;
		char ifname[100];
		enum {
			EVENT_INTERFACE_ADDED, EVENT_INTERFACE_REMOVED
		} ievent;
	} interface_status;

	/**
	 * struct pmkid_candidate - Data for EVENT_PMKID_CANDIDATE
	 */
	struct pmkid_candidate {
		/** BSSID of the PMKID candidate */
		u8 bssid[ETH_ALEN];
		/** Smaller the index, higher the priority */
		int index;
		/** Whether RSN IE includes pre-authenticate flag */
		int preauth;
	} pmkid_candidate;

	/**
	 * struct stkstart - Data for EVENT_STKSTART
	 */
	struct stkstart {
		u8 peer[ETH_ALEN];
	} stkstart;

	/**
	 * struct tdls - Data for EVENT_TDLS
	 */
	struct tdls {
		u8 peer[ETH_ALEN];
		enum {
			TDLS_REQUEST_SETUP,
			TDLS_REQUEST_TEARDOWN,
			TDLS_REQUEST_DISCOVER,
		} oper;
		u16 reason_code; /* for teardown */
	} tdls;

	/**
	 * struct wnm - Data for EVENT_WNM
	 */
	struct wnm {
		u8 addr[ETH_ALEN];
		enum {
			WNM_OPER_SLEEP,
		} oper;
		enum {
			WNM_SLEEP_ENTER,
			WNM_SLEEP_EXIT
		} sleep_action;
		int sleep_intval;
		u16 reason_code;
		u8 *buf;
		u16 buf_len;
	} wnm;

	/**
	 * struct ft_ies - FT information elements (EVENT_FT_RESPONSE)
	 *
	 * During FT (IEEE 802.11r) authentication sequence, the driver is
	 * expected to use this event to report received FT IEs (MDIE, FTIE,
	 * RSN IE, TIE, possible resource request) to the supplicant. The FT
	 * IEs for the next message will be delivered through the
	 * struct wpa_driver_ops::update_ft_ies() callback.
	 */
	struct ft_ies {
		const u8 *ies;
		size_t ies_len;
		int ft_action;
		u8 target_ap[ETH_ALEN];
		/** Optional IE(s), e.g., WMM TSPEC(s), for RIC-Request */
		const u8 *ric_ies;
		/** Length of ric_ies buffer in octets */
		size_t ric_ies_len;
	} ft_ies;

	/**
	 * struct ibss_rsn_start - Data for EVENT_IBSS_RSN_START
	 */
	struct ibss_rsn_start {
		u8 peer[ETH_ALEN];
	} ibss_rsn_start;

	/**
	 * struct auth_info - Data for EVENT_AUTH events
	 */
	struct auth_info {
		u8 peer[ETH_ALEN];
		u8 bssid[ETH_ALEN];
		u16 auth_type;
		u16 auth_transaction;
		u16 status_code;
		const u8 *ies;
		size_t ies_len;
	} auth;

	/**
	 * struct assoc_reject - Data for EVENT_ASSOC_REJECT events
	 */
	struct assoc_reject {
		/**
		 * bssid - BSSID of the AP that rejected association
		 */
		const u8 *bssid;

		/**
		 * resp_ies - (Re)Association Response IEs
		 *
		 * Optional association data from the driver. This data is not
		 * required WPA, but may be useful for some protocols and as
		 * such, should be reported if this is available to the driver
		 * interface.
		 *
		 * This should start with the first IE (fixed fields before IEs
		 * are not included).
		 */
		const u8 *resp_ies;

		/**
		 * resp_ies_len - Length of resp_ies in bytes
		 */
		size_t resp_ies_len;

		/**
		 * status_code - Status Code from (Re)association Response
		 */
		u16 status_code;

		/**
		 * timed_out - Whether failure is due to timeout (etc.) rather
		 * than explicit rejection response from the AP.
		 */
		int timed_out;
	} assoc_reject;

	struct timeout_event {
		u8 addr[ETH_ALEN];
	} timeout_event;

	/**
	 * struct tx_status - Data for EVENT_TX_STATUS events
	 */
	struct tx_status {
		u16 type;
		u16 stype;
		const u8 *dst;
		const u8 *data;
		size_t data_len;
		int ack;
	} tx_status;

	/**
	 * struct rx_from_unknown - Data for EVENT_RX_FROM_UNKNOWN events
	 */
	struct rx_from_unknown {
		const u8 *bssid;
		const u8 *addr;
		int wds;
	} rx_from_unknown;

	/**
	 * struct rx_mgmt - Data for EVENT_RX_MGMT events
	 */
	struct rx_mgmt {
		const u8 *frame;
		size_t frame_len;
		u32 datarate;

		/**
		 * drv_priv - Pointer to store driver private BSS information
		 *
		 * If not set to NULL, this is used for comparison with
		 * hostapd_data->drv_priv to determine which BSS should process
		 * the frame.
		 */
		void *drv_priv;

		/**
		 * freq - Frequency (in MHz) on which the frame was received
		 */
		int freq;

		/**
		 * ssi_signal - Signal strength in dBm (or 0 if not available)
		 */
		int ssi_signal;
	} rx_mgmt;

	/**
	 * struct remain_on_channel - Data for EVENT_REMAIN_ON_CHANNEL events
	 *
	 * This is also used with EVENT_CANCEL_REMAIN_ON_CHANNEL events.
	 */
	struct remain_on_channel {
		/**
		 * freq - Channel frequency in MHz
		 */
		unsigned int freq;

		/**
		 * duration - Duration to remain on the channel in milliseconds
		 */
		unsigned int duration;
	} remain_on_channel;

	/**
	 * struct scan_info - Optional data for EVENT_SCAN_RESULTS events
	 * @aborted: Whether the scan was aborted
	 * @freqs: Scanned frequencies in MHz (%NULL = all channels scanned)
	 * @num_freqs: Number of entries in freqs array
	 * @ssids: Scanned SSIDs (%NULL or zero-length SSID indicates wildcard
	 *	SSID)
	 * @num_ssids: Number of entries in ssids array
	 * @external_scan: Whether the scan info is for an external scan
	 * @nl_scan_event: 1 if the source of this scan event is a normal scan,
	 * 	0 if the source of the scan event is a vendor scan
	 */
	struct scan_info {
		int aborted;
		const int *freqs;
		size_t num_freqs;
		struct wpa_driver_scan_ssid ssids[WPAS_MAX_SCAN_SSIDS];
		size_t num_ssids;
		int external_scan;
		int nl_scan_event;
	} scan_info;

	/**
	 * struct rx_probe_req - Data for EVENT_RX_PROBE_REQ events
	 */
	struct rx_probe_req {
		/**
		 * sa - Source address of the received Probe Request frame
		 */
		const u8 *sa;

		/**
		 * da - Destination address of the received Probe Request frame
		 *	or %NULL if not available
		 */
		const u8 *da;

		/**
		 * bssid - BSSID of the received Probe Request frame or %NULL
		 *	if not available
		 */
		const u8 *bssid;

		/**
		 * ie - IEs from the Probe Request body
		 */
		const u8 *ie;

		/**
		 * ie_len - Length of ie buffer in octets
		 */
		size_t ie_len;

		/**
		 * signal - signal strength in dBm (or 0 if not available)
		 */
		int ssi_signal;
	} rx_probe_req;

	/**
	 * struct new_sta - Data for EVENT_NEW_STA events
	 */
	struct new_sta {
		const u8 *addr;
	} new_sta;

	/**
	 * struct eapol_rx - Data for EVENT_EAPOL_RX events
	 */
	struct eapol_rx {
		const u8 *src;
		const u8 *data;
		size_t data_len;
	} eapol_rx;

	/**
	 * signal_change - Data for EVENT_SIGNAL_CHANGE events
	 */
	struct wpa_signal_info signal_change;

	/**
	 * struct best_channel - Data for EVENT_BEST_CHANNEL events
	 * @freq_24: Best 2.4 GHz band channel frequency in MHz
	 * @freq_5: Best 5 GHz band channel frequency in MHz
	 * @freq_overall: Best channel frequency in MHz
	 *
	 * 0 can be used to indicate no preference in either band.
	 */
	struct best_channel {
		int freq_24;
		int freq_5;
		int freq_overall;
	} best_chan;

	struct unprot_deauth {
		const u8 *sa;
		const u8 *da;
		u16 reason_code;
	} unprot_deauth;

	struct unprot_disassoc {
		const u8 *sa;
		const u8 *da;
		u16 reason_code;
	} unprot_disassoc;

	/**
	 * struct low_ack - Data for EVENT_STATION_LOW_ACK events
	 * @addr: station address
	 */
	struct low_ack {
		u8 addr[ETH_ALEN];
	} low_ack;

	/**
	 * struct ibss_peer_lost - Data for EVENT_IBSS_PEER_LOST
	 */
	struct ibss_peer_lost {
		u8 peer[ETH_ALEN];
	} ibss_peer_lost;

	/**
	 * struct driver_gtk_rekey - Data for EVENT_DRIVER_GTK_REKEY
	 */
	struct driver_gtk_rekey {
		const u8 *bssid;
		const u8 *replay_ctr;
	} driver_gtk_rekey;

	/**
	 * struct client_poll - Data for EVENT_DRIVER_CLIENT_POLL_OK events
	 * @addr: station address
	 */
	struct client_poll {
		u8 addr[ETH_ALEN];
	} client_poll;

	/**
	 * struct eapol_tx_status
	 * @dst: Original destination
	 * @data: Data starting with IEEE 802.1X header (!)
	 * @data_len: Length of data
	 * @ack: Indicates ack or lost frame
	 *
	 * This corresponds to hapd_send_eapol if the frame sent
	 * there isn't just reported as EVENT_TX_STATUS.
	 */
	struct eapol_tx_status {
		const u8 *dst;
		const u8 *data;
		int data_len;
		int ack;
	} eapol_tx_status;

	/**
	 * struct ch_switch
	 * @freq: Frequency of new channel in MHz
	 * @ht_enabled: Whether this is an HT channel
	 * @ch_offset: Secondary channel offset
	 * @ch_width: Channel width
	 * @cf1: Center frequency 1
	 * @cf2: Center frequency 2
	 */
	struct ch_switch {
		int freq;
		int ht_enabled;
		int ch_offset;
		enum chan_width ch_width;
		int cf1;
		int cf2;
	} ch_switch;

	/**
	 * struct connect_failed - Data for EVENT_CONNECT_FAILED_REASON
	 * @addr: Remote client address
	 * @code: Reason code for connection failure
	 */
	struct connect_failed_reason {
		u8 addr[ETH_ALEN];
		enum {
			MAX_CLIENT_REACHED,
			BLOCKED_CLIENT
		} code;
	} connect_failed_reason;

	/**
	 * struct dfs_event - Data for radar detected events
	 * @freq: Frequency of the channel in MHz
	 */
	struct dfs_event {
		int freq;
		int ht_enabled;
		int chan_offset;
		enum chan_width chan_width;
		int cf1;
		int cf2;
        int timeout;
	} dfs_event;

	/**
	 * survey_results - Survey result data for EVENT_SURVEY
	 * @freq_filter: Requested frequency survey filter, 0 if request
	 *	was for all survey data
	 * @survey_list: Linked list of survey data (struct freq_survey)
	 */
	struct survey_results {
		unsigned int freq_filter;
		struct dl_list survey_list; /* struct freq_survey */
	} survey_results;

	/**
	 * channel_list_changed - Data for EVENT_CHANNEL_LIST_CHANGED
	 * @initiator: Initiator of the regulatory change
	 * @type: Regulatory change type
	 * @alpha2: Country code (or "" if not available)
	 */
	struct channel_list_changed {
		enum reg_change_initiator initiator;
		enum reg_type type;
		char alpha2[3];
	} channel_list_changed;

	/**
	 * freq_range - List of frequency ranges
	 *
	 * This is used as the data with EVENT_AVOID_FREQUENCIES.
	 */
	struct wpa_freq_range_list freq_range;

	/**
	 * struct mesh_peer
	 *
	 * @peer: Peer address
	 * @ies: Beacon IEs
	 * @ie_len: Length of @ies
	 *
	 * Notification of new candidate mesh peer.
	 */
	struct mesh_peer {
		const u8 *peer;
		const u8 *ies;
		size_t ie_len;
	} mesh_peer;

	/**
	 * struct acs_selected_channels - Data for EVENT_ACS_CHANNEL_SELECTED
	 * @pri_channel: Selected primary channel
	 * @sec_channel: Selected secondary channel
	 * @vht_seg0_center_ch: VHT mode Segment0 center channel
	 * @vht_seg1_center_ch: VHT mode Segment1 center channel
	 * @ch_width: Selected Channel width by driver. Driver may choose to
	 *	change hostapd configured ACS channel width due driver internal
	 *	channel restrictions.
	 * hw_mode: Selected band (used with hw_mode=any)
	 */
	struct acs_selected_channels {
		u8 pri_channel;
		u8 sec_channel;
		u8 vht_seg0_center_ch;
		u8 vht_seg1_center_ch;
		u16 ch_width;
		enum hostapd_hw_mode hw_mode;
	} acs_selected_channels;

	/**
	 * struct p2p_lo_stop - Reason code for P2P Listen offload stop event
	 * @reason_code: Reason for stopping offload
	 *	P2P_LO_STOPPED_REASON_COMPLETE: Listen offload finished as
	 *	scheduled.
	 *	P2P_LO_STOPPED_REASON_RECV_STOP_CMD: Host requested offload to
	 *	be stopped.
	 *	P2P_LO_STOPPED_REASON_INVALID_PARAM: Invalid listen offload
	 *	parameters.
	 *	P2P_LO_STOPPED_REASON_NOT_SUPPORTED: Listen offload not
	 *	supported by device.
	 */
	struct p2p_lo_stop {
		enum {
			P2P_LO_STOPPED_REASON_COMPLETE = 0,
			P2P_LO_STOPPED_REASON_RECV_STOP_CMD,
			P2P_LO_STOPPED_REASON_INVALID_PARAM,
			P2P_LO_STOPPED_REASON_NOT_SUPPORTED,
		} reason_code;
	} p2p_lo_stop;
};

struct atheros_driver_data
{
	struct hostapd_data *hapd;		/* back pointer */

	char	iface[IFNAMSIZ + 1];
	int     ifindex;
	struct l2_packet_data *sock_xmit;	/* raw packet xmit socket */
	struct l2_packet_data *sock_recv;	/* raw packet recv socket */
	int	ioctl_sock;			/* socket for ioctl() use */
	struct netlink_data *netlink;
	int	we_version;
	int fils_en;			/* FILS enable/disable in driver */
	u8	acct_mac[ETH_ALEN];
	struct hostap_sta_driver_data acct_data;

	struct l2_packet_data *sock_raw; /* raw 802.11 management frames */
	struct wpabuf *wpa_ie;
//	struct wpabuf *wps_beacon_ie;
//	struct wpabuf *wps_probe_resp_ie;
	struct wpa_driver_capa capa;
	u8	own_addr[ETH_ALEN];
	int has_capability;
};

/*****************************************end===>driver.h**********************************/

/*****************************************end===>wpa_auth.h**********************************/
enum
{
	WPA_IE_OK, WPA_INVALID_IE, WPA_INVALID_GROUP, WPA_INVALID_PAIRWISE,
	WPA_INVALID_AKMP, WPA_NOT_ENABLED, WPA_ALLOC_FAIL,
	WPA_MGMT_FRAME_PROTECTION_VIOLATION, WPA_INVALID_MGMT_GROUP_CIPHER,
	WPA_INVALID_MDIE, WPA_INVALID_PROTO
};
struct wpa_auth_config
{
	int wpa;
	int wpa_key_mgmt;
	int wpa_pairwise;
	int wpa_group;
	int wpa_group_rekey;
	int wpa_strict_rekey;
	int wpa_gmk_rekey;
	int wpa_ptk_rekey;
	int rsn_pairwise;
	int rsn_preauth;
	int eapol_version;
	int peerkey;
	int identity_request_retry_interval;
	int wmm_enabled;
	int wmm_uapsd;
	int disable_pmksa_caching;
	int okc;
	int tx_status;
	int disable_gtk;
	int ap_mlme;
};

struct wpa_auth_callbacks
{
	void *ctx;
	void (*logger)(void *ctx, const u8 *addr, logger_level level,const char *txt);
	void (*disconnect)(void *ctx, const u8 *addr, u16 reason);
	int (*mic_failure_report)(void *ctx, const u8 *addr);
	void (*psk_failure_report)(void *ctx, const u8 *addr);
	void (*set_eapol)(void *ctx, const u8 *addr, wpa_eapol_variable var,int value);
	int (*get_eapol)(void *ctx, const u8 *addr, wpa_eapol_variable var);
	const u8 * (*get_psk)(void *ctx, const u8 *addr, const u8 *p2p_dev_addr,const u8 *prev_psk);
	int (*get_msk)(void *ctx, const u8 *addr, u8 *msk, size_t *len);
	int (*set_key)(void *ctx, int vlan_id, enum wpa_alg alg,const u8 *addr, int idx, u8 *key, size_t key_len);
	int (*get_seqnum)(void *ctx, const u8 *addr, int idx, u8 *seq);
	int (*send_eapol)(void *ctx, const u8 *addr, const u8 *data,size_t data_len, int encrypt);
	int (*for_each_sta)(void *ctx, int (*cb)(struct wpa_state_machine *sm,void *ctx), void *cb_ctx);
	int (*for_each_auth)(void *ctx, int (*cb)(struct wpa_authenticator *a,void *ctx), void *cb_ctx);
	int (*send_ether)(void *ctx, const u8 *dst, u16 proto, const u8 *data,size_t data_len);
};

/*****************************************end===>wpa_auth.h**********************************/

/*****************************************start===>defs.h**********************************/
#define WPA_PROTO_WPA BIT(0)
#define WPA_PROTO_RSN BIT(1)
#define WPA_CIPHER_NONE BIT(0)
#define WPA_CIPHER_WEP40 BIT(1)
#define WPA_CIPHER_WEP104 BIT(2)
#define WPA_CIPHER_TKIP BIT(3)
#define WPA_CIPHER_CCMP BIT(4)

#define WPA_AUTH_ALG_OPEN BIT(0)
#define WPA_AUTH_ALG_SHARED BIT(1)
#define WPA_AUTH_ALG_LEAP BIT(2)
#define WPA_AUTH_ALG_FT BIT(3)
#define WPA_AUTH_ALG_SAE BIT(4)
#define WPA_AUTH_ALG_FILS BIT(5)

#define WPA_KEY_MGMT_IEEE8021X BIT(0)
#define WPA_KEY_MGMT_PSK BIT(1)
#define WPA_KEY_MGMT_NONE BIT(2)
#define WPA_KEY_MGMT_IEEE8021X_NO_WPA BIT(3)
#define WPA_KEY_MGMT_WPA_NONE BIT(4)


enum wpa_alg
{
	WPA_ALG_NONE,
	WPA_ALG_WEP,
	WPA_ALG_TKIP,
	WPA_ALG_CCMP,
	WPA_ALG_IGTK,
	WPA_ALG_PMK,
	WPA_ALG_GCMP,
	WPA_ALG_SMS4,
	WPA_ALG_KRK,
	WPA_ALG_GCMP_256,
	WPA_ALG_CCMP_256,
	WPA_ALG_BIP_GMAC_128,
	WPA_ALG_BIP_GMAC_256,
	WPA_ALG_BIP_CMAC_256
};
/*****************************************start===>defs.h**********************************/

/*****************************************start===>wpa_auth_i.h**********************************/
/* per authenticator data */
struct wpa_authenticator
{
//	struct wpa_group *group;

	unsigned int dot11RSNAStatsTKIPRemoteMICFailures;
	u32 dot11RSNAAuthenticationSuiteSelected;
	u32 dot11RSNAPairwiseCipherSelected;
	u32 dot11RSNAGroupCipherSelected;
	u8 dot11RSNAPMKIDUsed[PMKID_LEN];
	u32 dot11RSNAAuthenticationSuiteRequested; /* FIX: update */
	u32 dot11RSNAPairwiseCipherRequested; /* FIX: update */
	u32 dot11RSNAGroupCipherRequested; /* FIX: update */
	unsigned int dot11RSNATKIPCounterMeasuresInvoked;
	unsigned int dot11RSNA4WayHandshakeFailures;

//	struct wpa_stsl_negotiation *stsl_negotiations;

	struct wpa_auth_config conf;
	struct wpa_auth_callbacks cb;

	u8 *wpa_ie;
	size_t wpa_ie_len;

	u8 addr[ETH_ALEN];

//	struct rsn_pmksa_cache *pmksa;
//	struct wpa_ft_pmk_cache *ft_pmk_cache;

	int identity_request_retry_interval;
};

struct wpa_state_machine
{
	struct wpa_authenticator *wpa_auth;
//	struct wpa_group *group;

	u8 addr[ETH_ALEN];
	u8 p2p_dev_addr[ETH_ALEN];

	enum {
		WPA_PTK_INITIALIZE, WPA_PTK_DISCONNECT, WPA_PTK_DISCONNECTED,
		WPA_PTK_AUTHENTICATION, WPA_PTK_AUTHENTICATION2,
		WPA_PTK_INITPMK, WPA_PTK_INITPSK, WPA_PTK_PTKSTART,
		WPA_PTK_PTKCALCNEGOTIATING, WPA_PTK_PTKCALCNEGOTIATING2,
		WPA_PTK_PTKINITNEGOTIATING, WPA_PTK_PTKINITDONE
	} wpa_ptk_state;

	enum {
		WPA_PTK_GROUP_IDLE = 0,
		WPA_PTK_GROUP_REKEYNEGOTIATING,
		WPA_PTK_GROUP_REKEYESTABLISHED,
		WPA_PTK_GROUP_KEYERROR
	} wpa_ptk_group_state;

	Boolean Init;
	Boolean DeauthenticationRequest;
	Boolean AuthenticationRequest;
	Boolean ReAuthenticationRequest;
	Boolean Disconnect;
	int TimeoutCtr;
	int GTimeoutCtr;
	Boolean TimeoutEvt;
	Boolean EAPOLKeyReceived;
	Boolean EAPOLKeyPairwise;
	Boolean EAPOLKeyRequest;
	Boolean MICVerified;
	Boolean GUpdateStationKeys;
	u8 ANonce[WPA_NONCE_LEN];
	u8 SNonce[WPA_NONCE_LEN];
	u8 alt_SNonce[WPA_NONCE_LEN];
	u8 alt_replay_counter[WPA_REPLAY_COUNTER_LEN];
	u8 PMK[PMK_LEN_MAX];
	unsigned int pmk_len;
	struct wpa_ptk PTK;
	Boolean PTK_valid;
	Boolean pairwise_set;
	int keycount;
	Boolean Pair;
	struct wpa_key_replay_counter {
		u8 counter[WPA_REPLAY_COUNTER_LEN];
		Boolean valid;
	} key_replay[RSNA_MAX_EAPOL_RETRIES],
		prev_key_replay[RSNA_MAX_EAPOL_RETRIES];
	Boolean PInitAKeys; /* WPA only, not in IEEE 802.11i */
	Boolean PTKRequest; /* not in IEEE 802.11i state machine */
	Boolean has_GTK;
	Boolean PtkGroupInit; /* init request for PTK Group state machine */

	u8 *last_rx_eapol_key; /* starting from IEEE 802.1X header */
	size_t last_rx_eapol_key_len;

	unsigned int changed:1;
	unsigned int in_step_loop:1;
	unsigned int pending_deinit:1;
	unsigned int started:1;
	unsigned int mgmt_frame_prot:1;
	unsigned int rx_eapol_key_secure:1;
	unsigned int update_snonce:1;
	unsigned int alt_snonce_valid:1;
	unsigned int is_wnmsleep:1;

	u8 req_replay_counter[WPA_REPLAY_COUNTER_LEN];
	int req_replay_counter_used;

	u8 *wpa_ie;
	size_t wpa_ie_len;

	enum {
		WPA_VERSION_NO_WPA = 0 /* WPA not used */,
		WPA_VERSION_WPA = 1 /* WPA / IEEE 802.11i/D3.0 */,
		WPA_VERSION_WPA2 = 2 /* WPA2 / IEEE 802.11i */
	} wpa;
	int pairwise; /* Pairwise cipher suite, WPA_CIPHER_* */
	int wpa_key_mgmt; /* the selected WPA_KEY_MGMT_* */
//	struct rsn_pmksa_cache_entry *pmksa;

	u32 dot11RSNAStatsTKIPLocalMICFailures;
	u32 dot11RSNAStatsTKIPRemoteMICFailures;


	int pending_1_of_4_timeout;


	int identity_request_retry_interval; 
};
enum
{
	WPA_VERSION_NO_WPA = 0 /* WPA not used */,
	WPA_VERSION_WPA = 1 /* WPA / IEEE 802.11i/D3.0 */,
	WPA_VERSION_WPA2 = 2 /* WPA2 / IEEE 802.11i */
} wpa;
/*****************************************end===>wpa_auth_i.h**********************************/

/*****************************************start===>sta_info.h**********************************/
/* STA flags */
#define WLAN_STA_AUTH BIT(0)
#define WLAN_STA_ASSOC BIT(1)
#define WLAN_STA_AUTHORIZED BIT(5)
#define WLAN_STA_PENDING_POLL BIT(6) /* pending activity poll not ACKed */
#define WLAN_STA_SHORT_PREAMBLE BIT(7)
#define WLAN_STA_PREAUTH BIT(8)
#define WLAN_STA_WMM BIT(9)
#define WLAN_STA_MFP BIT(10)
#define WLAN_STA_HT BIT(11)
#define WLAN_STA_WPS BIT(12)
#define WLAN_STA_MAYBE_WPS BIT(13)
#define WLAN_STA_WDS BIT(14)
#define WLAN_STA_ASSOC_REQ_OK BIT(15)
#define WLAN_STA_WPS2 BIT(16)
#define WLAN_STA_GAS BIT(17)
#define WLAN_STA_VHT BIT(18)
#define WLAN_STA_WNM_SLEEP_MODE BIT(19)
#define WLAN_STA_VHT_OPMODE_ENABLED BIT(20)
#define WLAN_STA_VENDOR_VHT BIT(21)
#define WLAN_STA_PENDING_FILS_ERP BIT(22)
#define WLAN_STA_PENDING_DISASSOC_CB BIT(29)
#define WLAN_STA_PENDING_DEAUTH_CB BIT(30)
#define WLAN_STA_NONERP BIT(31)
/*****************************************end===>sta_info.h**********************************/

/*****************************************start===>driver.h**********************************/
#define WPA_STA_AUTHORIZED BIT(0)
#define WPA_STA_WMM BIT(1)
#define WPA_STA_SHORT_PREAMBLE BIT(2)
#define WPA_STA_MFP BIT(3)
#define WPA_STA_TDLS_PEER BIT(4)
#define WPA_STA_AUTHENTICATED BIT(5)
#define WPA_STA_ASSOCIATED BIT(6)
/*****************************************end===>driver.h**********************************/

#endif



