#ifndef __HOSAT_TEST_H__
#define __HOSAT_TEST_H__

#ifndef IFNAMSIZ
#define IFNAMSIZ 16
#endif
struct ieee80211req_key {
	u_int8_t	ik_type;	/* key/cipher type */
	u_int8_t	ik_pad;
	u_int16_t	ik_keyix;	/* key index */
	u_int8_t	ik_keylen;	/* key length in bytes */
	u_int8_t	ik_flags;
/* NB: IEEE80211_KEY_XMIT and IEEE80211_KEY_RECV defined elsewhere */
#define	IEEE80211_KEY_DEFAULT	0x80	/* default xmit key */
	u_int8_t	ik_macaddr[IEEE80211_ADDR_LEN];
	u_int64_t	ik_keyrsc;	/* key receive sequence counter */
	u_int64_t	ik_keytsc;	/* key transmit sequence counter */
	u_int8_t	ik_keydata[IEEE80211_KEYBUF_SIZE+IEEE80211_MICBUF_SIZE];
} __packed;

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
    struct wpa_state_machine *wpa_sm;
	u16 auth_alg;
	u16 deauth_reason;
	u16 disassoc_reason;

};

struct hostapd_wpa_psk 
{
	struct hostapd_wpa_psk *next;
	int group;
	u8 psk[PMK_LEN];
	u8 addr[ETH_ALEN];
 };
 
struct hostapd_ssid {
	u8 ssid[SSID_MAX_LEN];
	size_t ssid_len;
	unsigned int ssid_set:1;
	unsigned int utf8_ssid:1;
	unsigned int wpa_passphrase_set:1;
	unsigned int wpa_psk_set:1;
	struct hostapd_wpa_psk *wpa_psk;
	char *wpa_passphrase;
 };

struct hostapd_bss_config
{
	char iface[IFNAMSIZ + 1];
	struct hostapd_ssid ssid;
	int auth_algs; /* bitfield of allowed IEEE 802.11 authentication
			* algorithms, WPA_AUTH_ALG_{OPEN,SHARED,LEAP} */

	int wpa; /* bitfield of WPA_PROTO_WPA, WPA_PROTO_RSN */
	int wpa_key_mgmt;
    int wpa_pairwise;
	int wpa_group;
	int wpa_group_rekey;
	int wpa_ptk_rekey;
	int rsn_pairwise;
    macaddr bssid;

};

struct hostapd_data
{
	struct hostapd_bss_config *conf;
	u8 own_addr[ETH_ALEN];
	int num_sta; /* number of entries in sta_list */
	struct sta_info *sta_list; /* STA info list head */
#define STA_HASH_SIZE 256
#define STA_HASH(sta) (sta[5])
	struct sta_info *sta_hash[STA_HASH_SIZE];
#define AID_WORDS ((2008 + 31) / 32)
	u32 sta_aid[AID_WORDS];
	struct wpa_authenticator *wpa_auth;

	const struct wpa_driver_ops *driver;
	void *drv_priv;
	struct l2_packet_data *l2;
	int tkip_countermeasures;

};

struct wpa_init_params
{
	void *global_priv;
	const u8 *bssid;
	const char *ifname;
	const char *driver_params;
	u8 *own_addr; /* buffer for writing own MAC address */
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
	int (*set_key)(const char *ifname, void *priv, enum wpa_alg alg,
		       const u8 *addr, int key_idx, int set_tx,
		       const u8 *seq, size_t seq_len,
		       const u8 *key, size_t key_len);
	void * (*hapd_init)(struct hostapd_data *hapd,struct wpa_init_params *params);
	void (*hapd_deinit)(void *priv);
//	int (*read_sta_data)(void *priv, struct hostap_sta_driver_data *data,const u8 *addr);
	int (*hapd_send_eapol)(void *priv, const u8 *addr, const u8 *data,size_t data_len, int encrypt,const u8 *own_addr, u32 flags);
	int (*sta_deauth)(void *priv, const u8 *own_addr, const u8 *addr,int reason);
	int (*sta_disassoc)(void *priv, const u8 *own_addr, const u8 *addr,int reason);
	int (*hapd_get_ssid)(void *priv, u8 *buf, int len);
	int (*hapd_set_ssid)(void *priv, const u8 *buf, int len);
    int (*sta_set_flags)(void *priv, const u8 *addr,unsigned int total_flags, unsigned int flags_or,unsigned int flags_and);
};



/***************************** start===>ieee802_11_defs.h*************************************/

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
	u_int8_t	im_ssid_len;	/* length of optional ssid */
	u_int16_t	im_reason;	/* 802.11 reason code */
	u_int16_t	im_seq;	        /* seq for auth */
	u_int8_t	im_macaddr[IEEE80211_ADDR_LEN];
	u_int8_t	im_ssid[IEEE80211_NWID_LEN];
	u_int8_t    im_optie[IEEE80211_MAX_OPT_IE];
	u_int16_t   im_optie_len;
//	struct      ieee80211req_fils_aad  fils_aad;
} __packed;

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

/*****************************************end===>wpa_common.h*********************************/

/*****************************************start===>common.h*********************************/

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

struct dl_list {
	struct dl_list *next;
	struct dl_list *prev;
};

static inline void dl_list_init(struct dl_list *list)
{
	list->next = list;
	list->prev = list;
}

static inline void dl_list_add(struct dl_list *list, struct dl_list *item)
{
	item->next = list->next;
	item->prev = list;
	list->next->prev = item;
	list->next = item;
}

static inline void dl_list_add_tail(struct dl_list *list, struct dl_list *item)
{
	dl_list_add(list->prev, item);
}

static inline void dl_list_del(struct dl_list *item)
{
	item->next->prev = item->prev;
	item->prev->next = item->next;
	item->next = NULL;
	item->prev = NULL;
}

/***************************************end===>list.h******************************************/

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
//		struct wmm_params wmm_params;

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
//		struct wpa_driver_scan_ssid ssids[WPAS_MAX_SCAN_SSIDS];
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
//	struct wpa_signal_info signal_change;

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
//		enum chan_width ch_width;
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
//		enum chan_width chan_width;
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
//		enum reg_change_initiator initiator;
//		enum reg_type type;
		char alpha2[3];
	} channel_list_changed;

	/**
	 * freq_range - List of frequency ranges
	 *
	 * This is used as the data with EVENT_AVOID_FREQUENCIES.
	 */
//	struct wpa_freq_range_list freq_range;

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
//		enum hostapd_hw_mode hw_mode;
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
//	struct hostap_sta_driver_data acct_data;

	struct l2_packet_data *sock_raw; /* raw 802.11 management frames */
//	struct wpabuf *wpa_ie;
//	struct wpabuf *wps_beacon_ie;
//	struct wpabuf *wps_probe_resp_ie;
//	struct wpa_driver_capa capa;
	u8	own_addr[ETH_ALEN];
	int has_capability;
};

/*****************************************end===>driver.h**********************************/

/*****************************************end===>wpa_auth.h**********************************/
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
//	void (*logger)(void *ctx, const u8 *addr, logger_level level,const char *txt);
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

struct wpa_ptk {
	u8 kck[WPA_KCK_MAX_LEN]; /* EAPOL-Key Key Confirmation Key (KCK) */
	u8 kek[WPA_KEK_MAX_LEN]; /* EAPOL-Key Key Encryption Key (KEK) */
	u8 tk[WPA_TK_MAX_LEN]; /* Temporal Key (TK) */
	size_t kck_len;
	size_t kek_len;
	size_t tk_len;
};

struct wpa_state_machine
{
	struct wpa_authenticator *wpa_auth;
//	struct wpa_group *group;

	u8 addr[ETH_ALEN];
	u8 p2p_dev_addr[ETH_ALEN];
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
	int pairwise; /* Pairwise cipher suite, WPA_CIPHER_* */
	int wpa_key_mgmt; /* the selected WPA_KEY_MGMT_* */
//	struct rsn_pmksa_cache_entry *pmksa;
	u32 dot11RSNAStatsTKIPLocalMICFailures;
	u32 dot11RSNAStatsTKIPRemoteMICFailures;
	int pending_1_of_4_timeout;
	int identity_request_retry_interval;
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
        
    enum {
		WPA_VERSION_NO_WPA = 0 /* WPA not used */,
		WPA_VERSION_WPA = 1 /* WPA / IEEE 802.11i/D3.0 */,
		WPA_VERSION_WPA2 = 2 /* WPA2 / IEEE 802.11i */
	} wpa;
};
/*****************************************end===>wpa_auth_i.h**********************************/
typedef long os_time_t;
typedef void (*eloop_timeout_handler)(void *eloop_data, void *user_ctx);

struct os_reltime {
	os_time_t sec;
	os_time_t usec;
};
struct eloop_timeout {
	struct dl_list list;
	struct os_reltime time;
	void *eloop_data;
	void *user_data;
	eloop_timeout_handler handler;
};
#endif



