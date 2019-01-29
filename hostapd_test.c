#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <string.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_ether.h>
#include <linux/wireless.h>
#include <unistd.h>
#include <errno.h>
//#include "ieee802_1x_defs.h"
//#include "common.h"
#include "hostapd_test.h"

#ifndef WPA_TYPES_DEFINED
#ifdef CONFIG_USE_INTTYPES_H
#include <inttypes.h>
#else
#include <stdint.h>
#endif

typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t u8;
typedef int64_t s64;
typedef int32_t s32;
typedef int16_t s16;
typedef int8_t s8;
#define WPA_TYPES_DEFINED
#endif /* !WPA_TYPES_DEFINED */

#define TRUE 1
#define FALSE 0

#define WLAN_SA_QUERY_TR_ID_LEN 2

struct ieee80211_mgmt {
	le16 frame_control;
	le16 duration;
	u8 da[6];
	u8 sa[6];
	u8 bssid[6];
	le16 seq_ctrl;
	union {
		struct {
			le16 auth_alg;
			le16 auth_transaction;
			le16 status_code;
			/* possibly followed by Challenge text */
			u8 variable[];
		} STRUCT_PACKED auth;
		struct {
			le16 reason_code;
			u8 variable[];
		} STRUCT_PACKED deauth;
		struct {
			le16 capab_info;
			le16 listen_interval;
			/* followed by SSID and Supported rates */
			u8 variable[];
		} STRUCT_PACKED assoc_req;
		struct {
			le16 capab_info;
			le16 status_code;
			le16 aid;
			/* followed by Supported rates */
			u8 variable[];
		} STRUCT_PACKED assoc_resp, reassoc_resp;
		struct {
			le16 capab_info;
			le16 listen_interval;
			u8 current_ap[6];
			/* followed by SSID and Supported rates */
			u8 variable[];
		} STRUCT_PACKED reassoc_req;
		struct {
			le16 reason_code;
			u8 variable[];
		} STRUCT_PACKED disassoc;
		struct {
			u8 timestamp[8];
			le16 beacon_int;
			le16 capab_info;
			/* followed by some of SSID, Supported rates,
			 * FH Params, DS Params, CF Params, IBSS Params, TIM */
			u8 variable[];
		} STRUCT_PACKED beacon;
                struct {
                        /* only variable items: SSID, Supported rates */
                        u8 variable[0];
                } STRUCT_PACKED probe_req;
		/* probe_req: only variable items: SSID, Supported rates */
		struct {
			u8 timestamp[8];
			le16 beacon_int;
			le16 capab_info;
			/* followed by some of SSID, Supported rates,
			 * FH Params, DS Params, CF Params, IBSS Params */
			u8 variable[];
		} STRUCT_PACKED probe_resp;
		struct {
			u8 category;
			union {
				struct {
					u8 action_code;
					u8 dialog_token;
					u8 status_code;
					u8 variable[];
				} STRUCT_PACKED wmm_action;
				struct{
					u8 action_code;
					u8 element_id;
					u8 length;
					u8 switch_mode;
					u8 new_chan;
					u8 switch_count;
				} STRUCT_PACKED chan_switch;
				struct {
					u8 action;
					u8 sta_addr[ETH_ALEN];
					u8 target_ap_addr[ETH_ALEN];
					u8 variable[]; /* FT Request */
				} STRUCT_PACKED ft_action_req;
				struct {
					u8 action;
					u8 sta_addr[ETH_ALEN];
					u8 target_ap_addr[ETH_ALEN];
					le16 status_code;
					u8 variable[]; /* FT Request */
				} STRUCT_PACKED ft_action_resp;
				struct {
					u8 action;
					u8 trans_id[WLAN_SA_QUERY_TR_ID_LEN];
				} STRUCT_PACKED sa_query_req;
				struct {
					u8 action; /* */
					u8 trans_id[WLAN_SA_QUERY_TR_ID_LEN];
				} STRUCT_PACKED sa_query_resp;
				struct {
					u8 action;
					u8 dialogtoken;
					u8 variable[];
				} STRUCT_PACKED wnm_sleep_req;
				struct {
					u8 action;
					u8 dialogtoken;
					le16 keydata_len;
					u8 variable[];
				} STRUCT_PACKED wnm_sleep_resp;
				struct {
					u8 action;
					u8 variable[];
				} STRUCT_PACKED public_action;
				struct {
					u8 action; /* 9 */
					u8 oui[3];
					/* Vendor-specific content */
					u8 variable[];
				} STRUCT_PACKED vs_public_action;
				struct {
					u8 action; /* 7 */
					u8 dialog_token;
					u8 req_mode;
					le16 disassoc_timer;
					u8 validity_interval;
					/* BSS Termination Duration (optional),
					 * Session Information URL (optional),
					 * BSS Transition Candidate List
					 * Entries */
					u8 variable[];
				} STRUCT_PACKED bss_tm_req;
				struct {
					u8 action; /* 8 */
					u8 dialog_token;
					u8 status_code;
					u8 bss_termination_delay;
					/* Target BSSID (optional),
					 * BSS Transition Candidate List
					 * Entries (optional) */
					u8 variable[];
				} STRUCT_PACKED bss_tm_resp;
				struct {
					u8 action; /* 6 */
					u8 dialog_token;
					u8 query_reason;
					/* BSS Transition Candidate List
					 * Entries (optional) */
					u8 variable[];
				} STRUCT_PACKED bss_tm_query;
				struct {
					u8 action; /* 15 */
					u8 variable[];
				} STRUCT_PACKED slf_prot_action;
				struct {
					u8 action;
					u8 variable[];
				} STRUCT_PACKED fst_action;
				struct {
					u8 action;
					u8 dialog_token;
					u8 variable[];
				} STRUCT_PACKED rrm;
			} u;
		} STRUCT_PACKED action;
	} u;
} STRUCT_PACKED;

struct netlink_config {
	void *ctx;
	void (*newlink_cb)(void *ctx, struct ifinfomsg *ifi, u8 *buf,size_t len);
	void (*dellink_cb)(void *ctx, struct ifinfomsg *ifi, u8 *buf,size_t len);
};

struct netlink_data {
	struct netlink_config *cfg;
	int sock;
};


struct atheros_driver_data {
//	struct hostapd_data *hapd;/* back pointer */

//	char	iface[IFNAMSIZ + 1];
//	int     ifindex;
//	struct l2_packet_data *sock_xmit;	/* raw packet xmit socket */
//	struct l2_packet_data *sock_recv;	/* raw packet recv socket */
//	int	ioctl_sock;			/* socket for ioctl() use */
//	struct netlink_data *netlink;
//	int	we_version;
//	int fils_en;			/* FILS enable/disable in driver */
//	u8	acct_mac[ETH_ALEN];
//	struct hostap_sta_driver_data acct_data;

//	struct l2_packet_data *sock_raw; /* raw 802.11 management frames */
//	struct wpabuf *wpa_ie;
//	struct wpabuf *wps_beacon_ie;
//	struct wpabuf *wps_probe_resp_ie;
//	struct wpa_driver_capa capa;
	u8	own_addr[ETH_ALEN];
	int has_capability;
};

int fd[2];

/**
 * wpa_printf - conditional printf
 * @level: priority level (MSG_*) of the message
 * @fmt: printf format string, followed by optional arguments
 *
 * This function is used to print conditional debugging and error messages. The
 * output may be directed to stdout, stderr, and/or syslog based on
 * configuration.
 *
 * Note: New line '\n' is added to the end of the text when printing to stdout.
 */
enum {MSG_EXCESSIVE, MSG_MSGDUMP, MSG_DEBUG, MSG_INFO, MSG_WARNING, MSG_ERROR};
int wpa_debug_level = MSG_INFO;
void wpa_printf(int level, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	if (level >= wpa_debug_level)
    {
		vprintf(fmt, ap);
		printf("\n");
	}
	va_end(ap);
}

void wpa_hexdump(int level, const char *title, const void *buf, size_t len)
{
	printf("%s - hexdump(len=%lu):", title, (unsigned long) len);
	if (buf == NULL)
    {
		printf(" [NULL]");
	} 
    else
    {
		for (i = 0; i < len; i++)
			printf(" %02x", buf[i]);
	}
	printf("\n");
}
void * os_zalloc(size_t size)
{
	return calloc(1, size);
}

void netlink_deinit(struct netlink_data *netlink)
{
	if (netlink == NULL)
		return;
	if (netlink->sock >= 0) 
    {
		close(netlink->sock);
	}
	free(netlink->cfg);
	free(netlink);
}

static void eloop_remove_timeout(struct eloop_timeout *timeout)
{
	dl_list_del(&timeout->list);
	free(timeout);
}

int eloop_cancel_timeout(eloop_timeout_handler handler,
			 void *eloop_data, void *user_data)
{
	struct eloop_timeout *timeout, *prev;
	int removed = 0;

	dl_list_for_each_safe(timeout, prev, &eloop.timeout,struct eloop_timeout, list) 
	{
		if (timeout->handler == handler &&
		    (timeout->eloop_data == eloop_data ||eloop_data == ELOOP_ALL_CTX) &&
		    (timeout->user_data == user_data ||user_data == ELOOP_ALL_CTX)) 
		{
			eloop_remove_timeout(timeout);
			removed++;
		}
	}
	return removed;
}

static inline int wpa_auth_set_key(struct wpa_authenticator *wpa_auth,int vlan_id,
				                enum wpa_alg alg, const u8 *addr, int idx,u8 *key, size_t key_len)
{
	if (wpa_auth->cb.set_key == NULL)
		return -1;
	return wpa_auth->cb.set_key(wpa_auth->cb.ctx, vlan_id, alg, addr, idx,key, key_len);
}
static void wpa_request_new_ptk(struct wpa_state_machine *sm)
{
	if (sm == NULL)
		return;

	sm->PTKRequest = TRUE;
	sm->PTK_valid = 0;
}
static void wpa_free_sta_sm(struct wpa_state_machine *sm)
{
	if (sm->GUpdateStationKeys)
    {
		sm->group->GKeyDoneStations--;
		sm->GUpdateStationKeys = FALSE;
	}
	free(sm->last_rx_eapol_key);
	free(sm->wpa_ie);
	free(sm);
}

static void wpa_rekey_ptk(void *eloop_ctx, void *timeout_ctx)
{
	struct wpa_authenticator *wpa_auth = eloop_ctx;
	struct wpa_state_machine *sm = timeout_ctx;

	wpa_request_new_ptk(sm);
	wpa_sm_step(sm);
}

void wpa_remove_ptk(struct wpa_state_machine *sm)
{
	sm->PTK_valid = FALSE;
	memset(&sm->PTK, 0, sizeof(sm->PTK));
	if (wpa_auth_set_key(sm->wpa_auth, 0, WPA_ALG_NONE, sm->addr, 0, NULL,0))
	{
	    wpa_printf(MSG_DEBUG,"RSN: PTK removal from the driver failed");
    }
	sm->pairwise_set = FALSE;
	eloop_cancel_timeout(wpa_rekey_ptk, sm->wpa_auth, sm);
}

void mlme_deletekeys_request(struct hostapd_data *hapd, struct sta_info *sta)
{
	wpa_printf(MSG_DEBUG,"MLME-DELETEKEYS.request(" MACSTR ")",MAC2STR(sta->addr));

	if (sta->wpa_sm)
		wpa_remove_ptk(sta->wpa_sm);
}

void mlme_disassociate_indication(struct hostapd_data *hapd,
				  struct sta_info *sta, u16 reason_code)
{
    wpa_printf(MSG_DEBUG,"MLME-DISASSOCIATE.indication(" MACSTR ", %d)",MAC2STR(sta->addr), reason_code);
	mlme_deletekeys_request(hapd, sta);
}

static void ap_sta_deauth_cb_timeout(void *eloop_ctx, void *timeout_ctx)
{
	struct hostapd_data *hapd = eloop_ctx;
	struct sta_info *sta = timeout_ctx;

	wpa_printf(MSG_DEBUG, "%s: Deauthentication callback for STA " MACSTR,hapd->conf->iface, MAC2STR(sta->addr));
	mlme_deauthenticate_indication(hapd, sta, sta->deauth_reason);
}

static void ap_sta_disassoc_cb_timeout(void *eloop_ctx, void *timeout_ctx)
{
	struct hostapd_data *hapd = eloop_ctx;
	struct sta_info *sta = timeout_ctx;

	wpa_printf(MSG_DEBUG, "%s: Disassociation callback for STA " MACSTR,hapd->conf->iface, MAC2STR(sta->addr));
	ap_sta_remove(hapd, sta);
	mlme_disassociate_indication(hapd, sta, sta->disassoc_reason);
}

void ap_sta_clear_disconnect_timeouts(struct hostapd_data *hapd,
				      struct sta_info *sta)
{
	if (eloop_cancel_timeout(ap_sta_deauth_cb_timeout, hapd, sta) > 0)
	{
	    wpa_printf(MSG_DEBUG,"%s: Removed ap_sta_deauth_cb_timeout timeout for "MACSTR,
                                                    hapd->conf->iface, MAC2STR(sta->addr));
    }
	if (eloop_cancel_timeout(ap_sta_disassoc_cb_timeout, hapd, sta) > 0)
	{
	    wpa_printf(MSG_DEBUG,"%s: Removed ap_sta_disassoc_cb_timeout timeout for "MACSTR,
			                                        hapd->conf->iface, MAC2STR(sta->addr));
    }
}

int hostapd_drv_sta_deauth(struct hostapd_data *hapd,
			   const u8 *addr, int reason)
{
	if (!hapd->driver || !hapd->driver->sta_deauth || !hapd->drv_priv)
		return 0;
	return hapd->driver->sta_deauth(hapd->drv_priv, hapd->own_addr, addr,
					reason);
}

/**
 * hostapd_new_assoc_sta - Notify that a new station associated with the AP
 * @hapd: Pointer to BSS data
 * @sta: Pointer to the associated STA data
 * @reassoc: 1 to indicate this was a re-association; 0 = first association
 *
 * This function will be called whenever a station associates with the AP. It
 * can be called from ieee802_11.c for drivers that export MLME to hostapd and
 * from drv_callbacks.c based on driver events for drivers that take care of
 * management frames (IEEE 802.11 authentication and association) internally.
 */
void hostapd_new_assoc_sta(struct hostapd_data *hapd, struct sta_info *sta,
			   int reassoc)
{
	if (hapd->tkip_countermeasures)
    {
		hostapd_drv_sta_deauth(hapd, sta->addr,WLAN_REASON_MICHAEL_MIC_FAILURE);
		return;
	}

//	hostapd_prune_associations(hapd, sta->addr);
	ap_sta_clear_disconnect_timeouts(hapd, sta);


	/* Start accounting here, if IEEE 802.1X and WPA are not used.
	 * IEEE 802.1X/WPA code will start accounting after the station has
	 * been authorized. */
	if (!hapd->conf->ieee802_1x && !hapd->conf->wpa && !hapd->conf->osen)
    {
		ap_sta_set_authorized(hapd, sta, 1);
		os_get_reltime(&sta->connected_time);
		accounting_sta_start(hapd, sta);
	}
    
	if (reassoc)
    {
		if (sta->auth_alg != WLAN_AUTH_FT &&
		    !(sta->flags & (WLAN_STA_WPS | WLAN_STA_MAYBE_WPS)))
		{
		    wpa_auth_sm_event(sta->wpa_sm, WPA_REAUTH);
        }
	}
    else
	{
	    wpa_auth_sta_associated(hapd->wpa_auth, sta->wpa_sm);
    }

}


/**
 * ieee802_11_parse_elems - Parse information elements in management frames
 * @start: Pointer to the start of IEs
 * @len: Length of IE buffer in octets
 * @elems: Data structure for parsed elements
 * @show_errors: Whether to show parsing errors in debug log
 * Returns: Parsing result
 */
typedef enum { ParseOK = 0, ParseUnknown = 1, ParseFailed = -1 } ParseRes;

ParseRes ieee802_11_parse_elems(const u8 *start, size_t len,
				            struct ieee802_11_elems *elems,int show_errors)
{
	size_t left = len;
	const u8 *pos = start;
	int unknown = 0;

	memset(elems, 0, sizeof(*elems));

	while (left >= 2)
    {
		u8 id, elen;

		id = *pos++;
		elen = *pos++;
		left -= 2;

		if (elen > left)
        {
			if (show_errors)
            {
				wpa_printf(MSG_DEBUG, "IEEE 802.11 element "
					   "parse failed (id=%d elen=%d ""left=%lu)",
					   id, elen, (unsigned long) left);
				wpa_hexdump(MSG_MSGDUMP, "IEs", start, len);
			}
			return ParseFailed;
		}

		switch (id)
        {
		case WLAN_EID_SSID:
			if (elen > SSID_MAX_LEN)
            {
				wpa_printf(MSG_DEBUG,"Ignored too long SSID element (elen=%u)",elen);
				break;
			}
			elems->ssid = pos;
			elems->ssid_len = elen;
			break;
		case WLAN_EID_SUPP_RATES:
			elems->supp_rates = pos;
			elems->supp_rates_len = elen;
			break;
		case WLAN_EID_DS_PARAMS:
			if (elen < 1)
				break;
			elems->ds_params = pos;
			break;
		case WLAN_EID_CF_PARAMS:
		case WLAN_EID_TIM:
			break;
		case WLAN_EID_CHALLENGE:
			elems->challenge = pos;
			elems->challenge_len = elen;
			break;
		case WLAN_EID_ERP_INFO:
			if (elen < 1)
				break;
			elems->erp_info = pos;
			break;
		case WLAN_EID_EXT_SUPP_RATES:
			elems->ext_supp_rates = pos;
			elems->ext_supp_rates_len = elen;
			break;
//		case WLAN_EID_VENDOR_SPECIFIC:
//			if (ieee802_11_parse_vendor_specific(pos, elen,elems,show_errors))
//				unknown++;
//			break;
		case WLAN_EID_RSN:
			elems->rsn_ie = pos;
			elems->rsn_ie_len = elen;
			break;
		case WLAN_EID_PWR_CAPABILITY:
			break;
		case WLAN_EID_SUPPORTED_CHANNELS:
			elems->supp_channels = pos;
			elems->supp_channels_len = elen;
			break;
		case WLAN_EID_MOBILITY_DOMAIN:
			if (elen < sizeof(struct rsn_mdie))
				break;
			elems->mdie = pos;
			elems->mdie_len = elen;
			break;
		case WLAN_EID_FAST_BSS_TRANSITION:
			if (elen < sizeof(struct rsn_ftie))
				break;
			elems->ftie = pos;
			elems->ftie_len = elen;
			break;
		case WLAN_EID_TIMEOUT_INTERVAL:
			if (elen != 5)
				break;
			elems->timeout_int = pos;
			break;
		case WLAN_EID_HT_CAP:
			if (elen < sizeof(struct ieee80211_ht_capabilities))
				break;
			elems->ht_capabilities = pos;
			break;
		case WLAN_EID_HT_OPERATION:
			if (elen < sizeof(struct ieee80211_ht_operation))
				break;
			elems->ht_operation = pos;
			break;
		case WLAN_EID_MESH_CONFIG:
			elems->mesh_config = pos;
			elems->mesh_config_len = elen;
			break;
		case WLAN_EID_MESH_ID:
			elems->mesh_id = pos;
			elems->mesh_id_len = elen;
			break;
		case WLAN_EID_PEER_MGMT:
			elems->peer_mgmt = pos;
			elems->peer_mgmt_len = elen;
			break;
		case WLAN_EID_VHT_CAP:
			if (elen < sizeof(struct ieee80211_vht_capabilities))
				break;
			elems->vht_capabilities = pos;
			break;
		case WLAN_EID_VHT_OPERATION:
			if (elen < sizeof(struct ieee80211_vht_operation))
				break;
			elems->vht_operation = pos;
			break;
		case WLAN_EID_VHT_OPERATING_MODE_NOTIFICATION:
			if (elen != 1)
				break;
			elems->vht_opmode_notif = pos;
			break;
		case WLAN_EID_LINK_ID:
			if (elen < 18)
				break;
			elems->link_id = pos;
			break;
		case WLAN_EID_INTERWORKING:
			elems->interworking = pos;
			elems->interworking_len = elen;
			break;
		case WLAN_EID_QOS_MAP_SET:
			if (elen < 16)
				break;
			elems->qos_map_set = pos;
			elems->qos_map_set_len = elen;
			break;
		case WLAN_EID_EXT_CAPAB:
			elems->ext_capab = pos;
			elems->ext_capab_len = elen;
			break;
		case WLAN_EID_BSS_MAX_IDLE_PERIOD:
			if (elen < 3)
				break;
			elems->bss_max_idle_period = pos;
			break;
		case WLAN_EID_SSID_LIST:
			elems->ssid_list = pos;
			elems->ssid_list_len = elen;
			break;
		case WLAN_EID_AMPE:
			elems->ampe = pos;
			elems->ampe_len = elen;
			break;
		case WLAN_EID_MIC:
			elems->mic = pos;
			elems->mic_len = elen;
			/* after mic everything is encrypted, so stop. */
			left = elen;
			break;
		case WLAN_EID_MULTI_BAND:
			if (elems->mb_ies.nof_ies >= MAX_NOF_MB_IES_SUPPORTED) {
				wpa_printf(MSG_MSGDUMP,
					   "IEEE 802.11 element parse ignored MB IE (id=%d elen=%d)",
					   id, elen);
				break;
			}

			elems->mb_ies.ies[elems->mb_ies.nof_ies].ie = pos;
			elems->mb_ies.ies[elems->mb_ies.nof_ies].ie_len = elen;
			elems->mb_ies.nof_ies++;
			break;
		case WLAN_EID_SUPPORTED_OPERATING_CLASSES:
			elems->supp_op_classes = pos;
			elems->supp_op_classes_len = elen;
			break;
		case WLAN_EID_RRM_ENABLED_CAPABILITIES:
			elems->rrm_enabled = pos;
			elems->rrm_enabled_len = elen;
			break;
		case WLAN_EID_CAG_NUMBER:
			elems->cag_number = pos;
			elems->cag_number_len = elen;
			break;
		case WLAN_EID_AP_CSN:
			if (elen < 1)
				break;
			elems->ap_csn = pos;
			break;
		case WLAN_EID_FILS_INDICATION:
			if (elen < 2)
				break;
			elems->fils_indic = pos;
			elems->fils_indic_len = elen;
			break;
		case WLAN_EID_DILS:
			if (elen < 2)
				break;
			elems->dils = pos;
			elems->dils_len = elen;
			break;
		case WLAN_EID_FRAGMENT:
			/* TODO */
			break;
//		case WLAN_EID_EXTENSION:
//			if (ieee802_11_parse_extension(pos, elen, elems,
//						       show_errors))
//				unknown++;
//			break;
		default:
			unknown++;
			if (!show_errors)
				break;
			wpa_printf(MSG_MSGDUMP, "IEEE 802.11 element parse "
				   "ignored unknown element (id=%d elen=%d)",
				   id, elen);
			break;
		}

		left -= elen;
		pos += elen;
	}

	if (left)
		return ParseFailed;

	return unknown ? ParseUnknown : ParseOK;
}
struct wpa_state_machine *wpa_auth_sta_init(struct wpa_authenticator *wpa_auth, const u8 *addr,
		  const u8 *p2p_dev_addr)
{
	struct wpa_state_machine *sm;

//	if (wpa_auth->group->wpa_group_state == WPA_GROUP_FATAL_FAILURE)
//		return NULL;

	sm = os_zalloc(sizeof(struct wpa_state_machine));
	if (sm == NULL)
		return NULL;
    memcpy(sm->addr, addr, ETH_ALEN);

	sm->wpa_auth = wpa_auth;
//	sm->group = wpa_auth->group;
//	wpa_group_get(sm->wpa_auth, sm->group);

	return sm;
}
static int rsn_selector_to_bitfield(const u8 *s)
{
	if (RSN_SELECTOR_GET(s) == RSN_CIPHER_SUITE_NONE)
		return WPA_CIPHER_NONE;
	if (RSN_SELECTOR_GET(s) == RSN_CIPHER_SUITE_TKIP)
		return WPA_CIPHER_TKIP;
	if (RSN_SELECTOR_GET(s) == RSN_CIPHER_SUITE_CCMP)
		return WPA_CIPHER_CCMP;

    return 0;
}



u32 wpa_cipher_to_suite(int proto, int cipher)
{
	if (cipher & WPA_CIPHER_CCMP)
		return (proto == WPA_PROTO_RSN ?
			RSN_CIPHER_SUITE_CCMP : WPA_CIPHER_SUITE_CCMP);
	if (cipher & WPA_CIPHER_TKIP)
		return (proto == WPA_PROTO_RSN ?
			RSN_CIPHER_SUITE_TKIP : WPA_CIPHER_SUITE_TKIP);
	if (cipher & WPA_CIPHER_NONE)
		return (proto == WPA_PROTO_RSN ?
			RSN_CIPHER_SUITE_NONE : WPA_CIPHER_SUITE_NONE);
	return 0;
}

static int wpa_selector_to_bitfield(const u8 *s)
{
	if (RSN_SELECTOR_GET(s) == WPA_CIPHER_SUITE_NONE)
		return WPA_CIPHER_NONE;
	if (RSN_SELECTOR_GET(s) == WPA_CIPHER_SUITE_TKIP)
		return WPA_CIPHER_TKIP;
	if (RSN_SELECTOR_GET(s) == WPA_CIPHER_SUITE_CCMP)
		return WPA_CIPHER_CCMP;
	return 0;
}
static int wpa_key_mgmt_to_bitfield(const u8 *s)
{
	if (RSN_SELECTOR_GET(s) == WPA_AUTH_KEY_MGMT_UNSPEC_802_1X)
		return WPA_KEY_MGMT_IEEE8021X;
	if (RSN_SELECTOR_GET(s) == WPA_AUTH_KEY_MGMT_PSK_OVER_802_1X)
		return WPA_KEY_MGMT_PSK;
	if (RSN_SELECTOR_GET(s) == WPA_AUTH_KEY_MGMT_NONE)
		return WPA_KEY_MGMT_WPA_NONE;
	return 0;
}
int wpa_pick_pairwise_cipher(int ciphers, int none_allowed)
{

	if (ciphers & WPA_CIPHER_CCMP)
		return WPA_CIPHER_CCMP;
	if (ciphers & WPA_CIPHER_TKIP)
		return WPA_CIPHER_TKIP;
	if (none_allowed && (ciphers & WPA_CIPHER_NONE))
		return WPA_CIPHER_NONE;
	return -1;
}
int wpa_parse_wpa_ie_wpa(const u8 *wpa_ie, size_t wpa_ie_len,
			 struct wpa_ie_data *data)
{
	const struct wpa_ie_hdr *hdr;
	const u8 *pos;
	int left;
	int i, count;

	memset(data, 0, sizeof(*data));
	data->proto = WPA_PROTO_WPA;
	data->pairwise_cipher = WPA_CIPHER_TKIP;
	data->group_cipher = WPA_CIPHER_TKIP;
	data->key_mgmt = WPA_KEY_MGMT_IEEE8021X;
	data->capabilities = 0;
	data->pmkid = NULL;
	data->num_pmkid = 0;
	data->mgmt_group_cipher = 0;

	if (wpa_ie_len < sizeof(struct wpa_ie_hdr))
    {
		wpa_printf(MSG_DEBUG, "%s: ie len too short %lu",__func__, (unsigned long) wpa_ie_len);
		return -1;
	}

	hdr = (const struct wpa_ie_hdr *) wpa_ie;

	if (hdr->elem_id != WLAN_EID_VENDOR_SPECIFIC ||
	    hdr->len != wpa_ie_len - 2 ||
	    RSN_SELECTOR_GET(hdr->oui) != WPA_OUI_TYPE ||
	    WPA_GET_LE16(hdr->version) != WPA_VERSION) 
	{
		wpa_printf(MSG_DEBUG, "%s: malformed ie or unknown version",__func__);
		return -2;
	}

	pos = (const u8 *) (hdr + 1);
	left = wpa_ie_len - sizeof(*hdr);

	if (left >= WPA_SELECTOR_LEN)
    {
		data->group_cipher = wpa_selector_to_bitfield(pos);
		pos += WPA_SELECTOR_LEN;
		left -= WPA_SELECTOR_LEN;
	} 
    else if (left > 0)
    {
		wpa_printf(MSG_DEBUG, "%s: ie length mismatch, %u too much",__func__, left);
		return -3;
	}

	if (left >= 2)
    {
		data->pairwise_cipher = 0;
		count = WPA_GET_LE16(pos);
		pos += 2;
		left -= 2;
		if (count == 0 || count > left / WPA_SELECTOR_LEN)
        {
			wpa_printf(MSG_DEBUG, "%s: ie count botch (pairwise), "
				   "count %u left %u", __func__, count, left);
			return -4;
		}
		for (i = 0; i < count; i++)
        {
			data->pairwise_cipher |= wpa_selector_to_bitfield(pos);
			pos += WPA_SELECTOR_LEN;
			left -= WPA_SELECTOR_LEN;
		}
	} 
    else if (left == 1)
    {
		wpa_printf(MSG_DEBUG, "%s: ie too short (for key mgmt)",__func__);
		return -5;
	}

	if (left >= 2)
    {
		data->key_mgmt = 0;
		count = WPA_GET_LE16(pos);
		pos += 2;
		left -= 2;
		if (count == 0 || count > left / WPA_SELECTOR_LEN)
        {
			wpa_printf(MSG_DEBUG, "%s: ie count botch (key mgmt), "
				   "count %u left %u", __func__, count, left);
			return -6;
		}
		for (i = 0; i < count; i++)
        {
			data->key_mgmt |= wpa_key_mgmt_to_bitfield(pos);
			pos += WPA_SELECTOR_LEN;
			left -= WPA_SELECTOR_LEN;
		}
	} 
    else if (left == 1)
    {
		wpa_printf(MSG_DEBUG, "%s: ie too short (for capabilities)",__func__);
		return -7;
	}

	if (left >= 2)
    {
		data->capabilities = WPA_GET_LE16(pos);
		pos += 2;
		left -= 2;
	}

	if (left > 0)
    {
		wpa_hexdump(MSG_DEBUG,"wpa_parse_wpa_ie_wpa: ignore trailing bytes",pos, left);
	}

	return 0;
}

/**
 * wpa_parse_wpa_ie_rsn - Parse RSN IE
 * @rsn_ie: Buffer containing RSN IE
 * @rsn_ie_len: RSN IE buffer length (including IE number and length octets)
 * @data: Pointer to structure that will be filled in with parsed data
 * Returns: 0 on success, <0 on failure
 */
int wpa_parse_wpa_ie_rsn(const u8 *rsn_ie, size_t rsn_ie_len,struct wpa_ie_data *data)
{
    const u8 *pos;
	int left;
	int i, count;

	memset(data, 0, sizeof(*data));
	data->proto = WPA_PROTO_RSN;
	data->pairwise_cipher = WPA_CIPHER_CCMP;
	data->group_cipher = WPA_CIPHER_CCMP;
	data->key_mgmt = WPA_KEY_MGMT_IEEE8021X;
	data->capabilities = 0;
	data->pmkid = NULL;
	data->num_pmkid = 0;
    data->mgmt_group_cipher = 0;
    if (rsn_ie_len == 0)
    {
		return -1;
	}
	if (rsn_ie_len < sizeof(struct rsn_ie_hdr))
    {
		wpa_printf(MSG_DEBUG, "%s: ie len too short %lu",__func__, (unsigned long) rsn_ie_len);
		return -1;
	}
    const struct rsn_ie_hdr *hdr;

	hdr = (const struct rsn_ie_hdr *) rsn_ie;

	if (hdr->elem_id != WLAN_EID_RSN ||hdr->len != rsn_ie_len - 2 ||
		    WPA_GET_LE16(hdr->version) != RSN_VERSION)
    {
		wpa_printf(MSG_DEBUG, "%s: malformed ie or unknown version",__func__);
		return -2;
	}

	pos = (const u8 *) (hdr + 1);
	left = rsn_ie_len - sizeof(*hdr);
	if (left >= RSN_SELECTOR_LEN)
    {
		data->group_cipher = rsn_selector_to_bitfield(pos);
		if (!(data->group_cipher == WPA_CIPHER_CCMP || data->group_cipher == WPA_CIPHER_TKIP))
        {
			wpa_printf(MSG_DEBUG,"%s: invalid group cipher 0x%x (%08x)",
				            __func__, data->group_cipher,WPA_GET_BE32(pos));
			return -1;
		}
		pos += RSN_SELECTOR_LEN;
		left -= RSN_SELECTOR_LEN;
	}
    else if (left > 0)
    {
		wpa_printf(MSG_DEBUG, "%s: ie length mismatch, %u too much",__func__, left);
		return -3;
	}
    if (left >= 2)
    {
    	data->pairwise_cipher = 0;
    	count = WPA_GET_LE16(pos);
    	pos += 2;
    	left -= 2;
    	if (count == 0 || count > left / RSN_SELECTOR_LEN)
        {
    		wpa_printf(MSG_DEBUG, "%s: ie count botch (pairwise), ""count %u left %u", __func__, count, left);
    		return -4;
    	}
    	for (i = 0; i < count; i++)
        {
    		data->pairwise_cipher |= rsn_selector_to_bitfield(pos);
    		pos += RSN_SELECTOR_LEN;
    		left -= RSN_SELECTOR_LEN;
    	}
	}
    else if (left == 1)
    {
		wpa_printf(MSG_DEBUG, "%s: ie too short (for key mgmt)",__func__);
		return -5;
	}
    
    if (left >= 2)
    {
    	data->key_mgmt = 0;
    	count = WPA_GET_LE16(pos);
    	pos += 2;
    	left -= 2;
    	if (count == 0 || count > left / RSN_SELECTOR_LEN)
        {
    		wpa_printf(MSG_DEBUG, "%s: ie count botch (key mgmt), "
    			            "count %u left %u", __func__, count, left);
    		return -6;
    	}
    	for (i = 0; i < count; i++)
        {
            if(RSN_SELECTOR_GET(pos) == RSN_AUTH_KEY_MGMT_PSK_OVER_802_1X)
    		    data->key_mgmt |= WPA_KEY_MGMT_PSK;
                
    		pos += RSN_SELECTOR_LEN;
    		left -= RSN_SELECTOR_LEN;
    	}
	}
    else if (left == 1)
    {
		wpa_printf(MSG_DEBUG, "%s: ie too short (for capabilities)",__func__);
		return -7;
	}

	if (left >= 2)
    {
		data->capabilities = WPA_GET_LE16(pos);
		pos += 2;
		left -= 2;
	}

	if (left >= 2)
    {
		u16 num_pmkid = WPA_GET_LE16(pos);
		pos += 2;
		left -= 2;
		if (num_pmkid > (unsigned int) left / PMKID_LEN)
        {
			wpa_printf(MSG_DEBUG, "%s: PMKID underflow ""(num_pmkid=%u left=%d)",__func__, num_pmkid, left);
			data->num_pmkid = 0;
			return -9;
		}
        else
        {
			data->num_pmkid = num_pmkid;
			data->pmkid = pos;
			pos += data->num_pmkid * PMKID_LEN;
			left -= data->num_pmkid * PMKID_LEN;
		}
	}

	if (left > 0)
    {
		wpa_hexdump(MSG_DEBUG,"wpa_parse_wpa_ie_rsn: ignore trailing bytes",pos, left);
	}

    return 0;
}
u32 hostapd_sta_flags_to_drv(u32 flags)
{
	int res = 0;
	if (flags & WLAN_STA_AUTHORIZED)
		res |= WPA_STA_AUTHORIZED;
	if (flags & WLAN_STA_WMM)
		res |= WPA_STA_WMM;
	if (flags & WLAN_STA_SHORT_PREAMBLE)
		res |= WPA_STA_SHORT_PREAMBLE;
	if (flags & WLAN_STA_MFP)
		res |= WPA_STA_MFP;
	if (flags & WLAN_STA_AUTH)
		res |= WPA_STA_AUTHENTICATED;
	if (flags & WLAN_STA_ASSOC)
		res |= WPA_STA_ASSOCIATED;
	return res;
}

static int
set80211priv(struct atheros_driver_data *drv, int op, void *data, int len)
{
	struct iwreq iwr;
	int do_inline = len < IFNAMSIZ;

	/* Certain ioctls must use the non-inlined method */
	if (op == IEEE80211_IOCTL_SET_APPIEBUF || op == IEEE80211_IOCTL_FILTERFRAME)
		do_inline = 0;

	memset(&iwr, 0, sizeof(iwr));
	strlcpy(iwr.ifr_name, drv->iface, IFNAMSIZ);
	if (do_inline)
    {
		/*
		 * Argument data fits inline; put it there.
		 */
		memcpy(iwr.u.name, data, len);
	}
    else
    {
		/*
		 * Argument data too big for inline transfer; setup a
		 * parameter block instead; the kernel will transfer
		 * the data for the driver.
		 */
		iwr.u.data.pointer = data;
		iwr.u.data.length = len;
	}

	if (ioctl(drv->ioctl_sock, op, &iwr) < 0)
    {
		wpa_printf(MSG_DEBUG, "atheros: %s: %s: ioctl op=0x%x ""ath0 len=%d failed: %d (%s)",
                                        __func__, drv->iface, op,len, errno, strerror(errno));
		return -1;
	}
	return 0;
}
static const char *ether_sprintf(const u8 *addr)
{
	static char buf[sizeof(MACSTR)];

	if (addr != NULL)
		snprintf(buf, sizeof(buf), MACSTR, MAC2STR(addr));
	else
		snprintf(buf, sizeof(buf), MACSTR, 0, 0, 0, 0, 0, 0);
	return buf;
}
static int atheros_set_sta_authorized(void *priv, const u8 *addr, int authorized)
{
	struct atheros_driver_data *drv = priv;
	struct ieee80211req_mlme mlme;
	int ret;

	wpa_printf(MSG_DEBUG, "%s: addr=%s authorized=%d",__func__, ether_sprintf(addr), authorized);

	if (authorized)
		mlme.im_op = IEEE80211_MLME_AUTHORIZE;
	else
		mlme.im_op = IEEE80211_MLME_UNAUTHORIZE;
	mlme.im_reason = 0;
	memcpy(mlme.im_macaddr, addr, IEEE80211_ADDR_LEN);
	ret = set80211priv(drv, IEEE80211_IOCTL_SETMLME, &mlme, sizeof(mlme));
	if (ret < 0)
    {
		wpa_printf(MSG_DEBUG, "%s: Failed to %sauthorize STA " MACSTR,
			   __func__, authorized ? "" : "un", MAC2STR(addr));
	}

	return ret;
}
static int
atheros_sta_set_flags(void *priv, const u8 *addr,
		      unsigned int total_flags, unsigned int flags_or,
		      unsigned int flags_and)
{
	/* For now, only support setting Authorized flag */
	if (flags_or & WPA_STA_AUTHORIZED)
		return atheros_set_sta_authorized(priv, addr, 1);
	if (!(flags_and & WPA_STA_AUTHORIZED))
		return atheros_set_sta_authorized(priv, addr, 0);
	return 0;
}

int hostapd_sta_set_flags(struct hostapd_data *hapd, u8 *addr,
			  int total_flags, int flags_or, int flags_and)
{
	if (hapd->driver == NULL || hapd->driver->sta_set_flags == NULL)
		return 0;
	return hapd->driver->sta_set_flags(hapd->drv_priv, addr, total_flags,flags_or, flags_and);
}
int hostapd_set_sta_flags(struct hostapd_data *hapd, struct sta_info *sta)
{
	int set_flags, total_flags, flags_and, flags_or;
	total_flags = hostapd_sta_flags_to_drv(sta->flags);
	set_flags = WPA_STA_SHORT_PREAMBLE | WPA_STA_WMM | WPA_STA_MFP;
	if ((!hapd->conf->wpa) && sta->flags & WLAN_STA_AUTHORIZED)
	{
	    set_flags |= WPA_STA_AUTHORIZED;
    }
	flags_or = total_flags & set_flags;
	flags_and = total_flags | ~set_flags;
	return hostapd_sta_set_flags(hapd, sta->addr, total_flags,flags_or, flags_and);
}
void sm_WPA_PTK_PTKSTART_Enter(struct wpa_state_machine *sm, int global)
{
	u8 buf[2 + RSN_SELECTOR_LEN + PMKID_LEN], *pmkid = NULL;
	size_t pmkid_len = 0;

/****** SM_ENTRY_MA(WPA_PTK, PTKSTART, wpa_ptk); ******************/
if (!global || sm->wpa_ptk_state != WPA_PTK_PTKSTART) 
{
    sm->changed = TRUE;
}
sm->wpa_ptk_state = WPA_PTK_PTKSTART;
/***********************************************************************************/
	sm->PTKRequest = FALSE;
	sm->TimeoutEvt = FALSE;
	sm->alt_snonce_valid = FALSE;

	sm->TimeoutCtr++;
	if (sm->TimeoutCtr > (int) dot11RSNAConfigPairwiseUpdateCount)
    {
		/* No point in sending the EAPOL-Key - we will disconnect
		 * immediately following this. */
		return;
	}

	wpa_printf(MSG_DEBUG,"sending 1/4 msg of 4-Way Handshake");
#ifdef GJF
	/*
	 * TODO: Could add PMKID even with WPA2-PSK, but only if there is only
	 * one possible PSK for this STA.
	 */
	if (sm->wpa == WPA_VERSION_WPA2)
	{
		pmkid = buf;
		pmkid_len = 2 + RSN_SELECTOR_LEN + PMKID_LEN;
		pmkid[0] = WLAN_EID_VENDOR_SPECIFIC;
		pmkid[1] = RSN_SELECTOR_LEN + PMKID_LEN;
		RSN_SELECTOR_PUT(&pmkid[2], RSN_KEY_DATA_PMKID);
		if (sm->pmksa)
        {
			os_memcpy(&pmkid[2 + RSN_SELECTOR_LEN],
				  sm->pmksa->pmkid, PMKID_LEN);
		} 
        else if (wpa_key_mgmt_suite_b(sm->wpa_key_mgmt))
        {
			/* No KCK available to derive PMKID */
			pmkid = NULL;
		} 
        else 
        {
			/*
			 * Calculate PMKID since no PMKSA cache entry was
			 * available with pre-calculated PMKID.
			 */
			rsn_pmkid(sm->PMK, sm->pmk_len, sm->wpa_auth->addr,sm->addr, &pmkid[2 + RSN_SELECTOR_LEN],
				        wpa_key_mgmt_sha256(sm->wpa_key_mgmt));
		}
	}
	wpa_send_eapol(sm->wpa_auth, sm,WPA_KEY_INFO_ACK | WPA_KEY_INFO_KEY_TYPE, NULL,sm->ANonce, pmkid, pmkid_len, 0, 0);
#endif
}
int wpa_validate_wpa_ie(struct wpa_authenticator *wpa_auth,
			struct wpa_state_machine *sm,
			const u8 *wpa_ie, size_t wpa_ie_len,
			const u8 *mdie, size_t mdie_len)
{
	struct wpa_ie_data data;
	int ciphers, key_mgmt, res, version;
	u32 selector;
	size_t i;
	const u8 *pmkid = NULL;

	if (wpa_auth == NULL || sm == NULL)
		return WPA_NOT_ENABLED;

	if (wpa_ie == NULL || wpa_ie_len < 1)
		return WPA_INVALID_IE;

	if (wpa_ie[0] == WLAN_EID_RSN)
		version = WPA_PROTO_RSN;
	else
		version = WPA_PROTO_WPA;
    
    if (!(wpa_auth->conf.wpa & version))
    {
		wpa_printf(MSG_DEBUG, "Invalid WPA proto (%d) from " MACSTR,version, MAC2STR(sm->addr));
		return WPA_INVALID_PROTO;
	}
	if (version == WPA_PROTO_RSN)
    {
		res = wpa_parse_wpa_ie_rsn(wpa_ie, wpa_ie_len, &data);

		selector = RSN_AUTH_KEY_MGMT_UNSPEC_802_1X;
		if (data.key_mgmt & WPA_KEY_MGMT_PSK)
			selector = RSN_AUTH_KEY_MGMT_PSK_OVER_802_1X;
		wpa_auth->dot11RSNAAuthenticationSuiteSelected = selector;

		selector = wpa_cipher_to_suite(WPA_PROTO_RSN,data.pairwise_cipher);
		if (!selector)
			selector = RSN_CIPHER_SUITE_CCMP;
		wpa_auth->dot11RSNAPairwiseCipherSelected = selector;

		selector = wpa_cipher_to_suite(WPA_PROTO_RSN,data.group_cipher);
		if (!selector)
			selector = RSN_CIPHER_SUITE_CCMP;
		wpa_auth->dot11RSNAGroupCipherSelected = selector;
	}
    else
    {
		res = wpa_parse_wpa_ie_wpa(wpa_ie, wpa_ie_len, &data);

		selector = WPA_AUTH_KEY_MGMT_UNSPEC_802_1X;
		if (data.key_mgmt & WPA_KEY_MGMT_IEEE8021X)
			selector = WPA_AUTH_KEY_MGMT_UNSPEC_802_1X;
		else if (data.key_mgmt & WPA_KEY_MGMT_PSK)
			selector = WPA_AUTH_KEY_MGMT_PSK_OVER_802_1X;
		wpa_auth->dot11RSNAAuthenticationSuiteSelected = selector;

		selector = wpa_cipher_to_suite(WPA_PROTO_WPA,data.pairwise_cipher);
		if (!selector)
			selector = RSN_CIPHER_SUITE_TKIP;
		wpa_auth->dot11RSNAPairwiseCipherSelected = selector;

		selector = wpa_cipher_to_suite(WPA_PROTO_WPA,data.group_cipher);
		if (!selector)
			selector = WPA_CIPHER_SUITE_TKIP;
		wpa_auth->dot11RSNAGroupCipherSelected = selector;
	}
    if (res)
    {
		wpa_printf(MSG_DEBUG, "Failed to parse WPA/RSN IE from "MACSTR " (res=%d)", MAC2STR(sm->addr), res);
		wpa_hexdump(MSG_DEBUG, "WPA/RSN IE", wpa_ie, wpa_ie_len);
		return WPA_INVALID_IE;
	}
	key_mgmt = data.key_mgmt & wpa_auth->conf.wpa_key_mgmt;
	if (!key_mgmt)
    {
		wpa_printf(MSG_DEBUG, "Invalid WPA key mgmt (0x%x) from "MACSTR, data.key_mgmt, MAC2STR(sm->addr));
		return WPA_INVALID_AKMP;
	}
    sm->wpa_key_mgmt = WPA_KEY_MGMT_PSK;
    if (version == WPA_PROTO_RSN)
		ciphers = data.pairwise_cipher & wpa_auth->conf.rsn_pairwise;
	else
		ciphers = data.pairwise_cipher & wpa_auth->conf.wpa_pairwise;
    
	if (!ciphers)
    {
		wpa_printf(MSG_DEBUG, "Invalid %s pairwise cipher (0x%x) "
			   "from " MACSTR,version == WPA_PROTO_RSN ? "RSN" : "WPA",
			   data.pairwise_cipher, MAC2STR(sm->addr));
		return WPA_INVALID_PAIRWISE;
	}
    sm->pairwise = wpa_pick_pairwise_cipher(ciphers, 0);
	if (sm->pairwise < 0)
		return WPA_INVALID_PAIRWISE;
    
    if (wpa_ie[0] == WLAN_EID_RSN)
		sm->wpa = WPA_VERSION_WPA2;
	else
		sm->wpa = WPA_VERSION_WPA;
    
	sm->pmksa = NULL;

	if (sm->wpa_ie == NULL || sm->wpa_ie_len < wpa_ie_len)
    {
		free(sm->wpa_ie);
		sm->wpa_ie = malloc(wpa_ie_len);
		if (sm->wpa_ie == NULL)
			return WPA_ALLOC_FAIL;
	}
	memcpy(sm->wpa_ie, wpa_ie, wpa_ie_len);
	sm->wpa_ie_len = wpa_ie_len;
	if(wpa_auth->conf.identity_request_retry_interval)
    {
		sm->identity_request_retry_interval = wpa_auth->conf.identity_request_retry_interval; 
	}

	return WPA_IE_OK;

}
int hostapd_notif_assoc(struct hostapd_data *hapd, const u8 *addr,
			const u8 *req_ies, size_t req_ies_len, int reassoc)
{
	struct sta_info *sta;
	int new_assoc, res;
	struct ieee802_11_elems elems;
	const u8 *ie;
	size_t ielen;
    u16 reason = WLAN_REASON_UNSPECIFIED;
	u16 status = WLAN_STATUS_SUCCESS;

	if (addr == NULL)
    {
		wpa_printf(MSG_DEBUG,"hostapd_notif_assoc: Skip event with no address");
		return -1;
	}
    ieee802_11_parse_elems(req_ies, req_ies_len, &elems, 0);
    if (elems.wps_ie)
    {
		ie = elems.wps_ie - 2;
		ielen = elems.wps_ie_len + 2;
		wpa_printf(MSG_DEBUG, "STA included WPS IE in (Re)AssocReq");
	}
    else if (elems.rsn_ie)
    {
		ie = elems.rsn_ie - 2;
		ielen = elems.rsn_ie_len + 2;
		wpa_printf(MSG_DEBUG, "STA included RSN IE in (Re)AssocReq");
	}
    else if (elems.wpa_ie)
    {
		ie = elems.wpa_ie - 2;
		ielen = elems.wpa_ie_len + 2;
		wpa_printf(MSG_DEBUG, "STA included WPA IE in (Re)AssocReq");
	}
    else
    {
		ie = NULL;
		ielen = 0;
		wpa_printf(MSG_DEBUG,"STA did not include WPS/RSN/WPA IE in (Re)AssocReq");
	}
    
//	sta = ap_get_sta(hapd, addr);
//	if (sta)
//    {
//		ap_sta_no_session_timeout(hapd, sta);
//		accounting_sta_stop(hapd, sta);

//		/*
//		 * Make sure that the previously registered inactivity timer
//		 * will not remove the STA immediately.
//		 */
//		sta->timeout_next = STA_NULLFUNC;
//	}
//    else
//    {
//		sta = ap_sta_add(hapd, addr);
//		if (sta == NULL)
//        {
//			hostapd_drv_sta_disassoc(hapd, addr,WLAN_REASON_DISASSOC_AP_BUSY);
//			return -1;
//		}
//	}


	if (hapd->conf->wpa)
    {
		if (ie == NULL || ielen == 0)
        {
        	wpa_printf(MSG_DEBUG, "No WPA/RSN IE from STA");
			return -1;
		}
        if (sta->wpa_sm == NULL)
        	sta->wpa_sm = wpa_auth_sta_init(hapd->wpa_auth,sta->addr,NULL);
        if (sta->wpa_sm == NULL)
        {
        	wpa_printf(MSG_ERROR,"Failed to initialize WPA state machine");
        	return -1;
        }
    
        res = wpa_validate_wpa_ie(hapd->wpa_auth, sta->wpa_sm,ie, ielen,elems.mdie, elems.mdie_len);
    	if (res != WPA_IE_OK)
        {
    		wpa_printf(MSG_DEBUG,"WPA/RSN information element rejected? (res %u)",res);
    		wpa_hexdump(MSG_DEBUG, "IE", ie, ielen);
    		if (res == WPA_INVALID_GROUP)
            {
    			reason = WLAN_REASON_GROUP_CIPHER_NOT_VALID;
    			status = WLAN_STATUS_GROUP_CIPHER_NOT_VALID;
    		}
            else if (res == WPA_INVALID_PAIRWISE)
            {
    			reason = WLAN_REASON_PAIRWISE_CIPHER_NOT_VALID;
    			status = WLAN_STATUS_PAIRWISE_CIPHER_NOT_VALID;
    		}
            else if (res == WPA_INVALID_AKMP)
            {
    			reason = WLAN_REASON_AKMP_NOT_VALID;
    			status = WLAN_STATUS_AKMP_NOT_VALID;
    		}
            else
            {
    			reason = WLAN_REASON_INVALID_IE;
    			status = WLAN_STATUS_INVALID_IE;
    		}
    		goto fail;
        }
   }

    new_assoc = (sta->flags & WLAN_STA_ASSOC) == 0;
	sta->flags |= WLAN_STA_AUTH | WLAN_STA_ASSOC;
	sta->flags &= ~WLAN_STA_WNM_SLEEP_MODE;

	hostapd_set_sta_flags(hapd, sta);


//	wpa_auth_sm_event(sta->wpa_sm, WPA_ASSOC);

	sta->wpa_sm->PTK_valid = FALSE;
	memset(&(sta->wpa_sm->PTK), 0, sizeof(sta->wpa_sm->PTK));
	wpa_remove_ptk(sm);
	if (sta->wpa_sm->in_step_loop)
    {
		/*
		 * wpa_sm_step() is already running - avoid recursive call to
		 * it by making the existing loop process the new update.
		 */
		sta->wpa_sm->changed = TRUE;
		return 0;
	}
	wpa_sm_step(sta->wpa_sm);
	hostapd_new_assoc_sta(hapd, sta, !new_assoc);

	ieee802_1x_notify_port_enabled(sta->eapol_sm, 1);

    return 0;
fail:
	hostapd_drv_sta_disassoc(hapd, sta->addr, reason);
	ap_free_sta(hapd, sta);
	return -1;
}

static inline void drv_event_assoc(void *ctx, const u8 *addr, const u8 *ie,size_t ielen, int reassoc)
{
	union wpa_event_data event;
	memset(&event, 0, sizeof(event));
	event.assoc_info.reassoc = reassoc;
	event.assoc_info.req_ies = ie;
	event.assoc_info.req_ies_len = ielen;
	event.assoc_info.addr = addr;
    
    hostapd_notif_assoc(hapd, event->assoc_info.addr,
       		    event->assoc_info.req_ies,
        		event->assoc_info.req_ies_len,
    		    event->assoc_info.reassoc);

}
static void atheros_raw_receive(void *ctx, const u8 *src_addr, const u8 *buf,size_t len)
{
	struct atheros_driver_data *drv = ctx;
	const struct ieee80211_mgmt *mgmt;
	union wpa_event_data event;
	u16 fc, stype;
	int ielen;
	const u8 *iebuf;

	if (len < IEEE80211_HDRLEN)
		return;

	mgmt = (const struct ieee80211_mgmt *) buf;

	fc = le_to_host16(mgmt->frame_control);

	if (WLAN_FC_GET_TYPE(fc) != WLAN_FC_TYPE_MGMT)
		return;

	stype = WLAN_FC_GET_STYPE(fc);

	wpa_printf(MSG_DEBUG, "%s: subtype 0x%x len %d", __func__, stype,(int) len);


	if (memcmp(drv->own_addr, mgmt->bssid, ETH_ALEN) != 0)
    {
		wpa_printf(MSG_DEBUG, "%s: BSSID does not match - ignore",__func__);
		return;
	}

	switch (stype)
    {
	case WLAN_FC_STYPE_ASSOC_REQ:
		if (len < IEEE80211_HDRLEN + sizeof(mgmt->u.assoc_req))
			break;
		ielen = len - (IEEE80211_HDRLEN + sizeof(mgmt->u.assoc_req));
		iebuf = mgmt->u.assoc_req.variable;
		drv_event_assoc(drv->hapd, mgmt->sa, iebuf, ielen, 0);
		break;
	case WLAN_FC_STYPE_REASSOC_REQ:
		if (len < IEEE80211_HDRLEN + sizeof(mgmt->u.reassoc_req))
			break;
		ielen = len - (IEEE80211_HDRLEN + sizeof(mgmt->u.reassoc_req));
		iebuf = mgmt->u.reassoc_req.variable;
		drv_event_assoc(drv->hapd, mgmt->sa, iebuf, ielen, 1);
		break;
	case WLAN_FC_STYPE_AUTH:
//		if (len < IEEE80211_HDRLEN + sizeof(mgmt->u.auth))
//			break;
//		os_memset(&event, 0, sizeof(event));
//		os_memcpy(event.auth.peer, mgmt->sa, ETH_ALEN);
//		os_memcpy(event.auth.bssid, mgmt->bssid, ETH_ALEN);
//		event.auth.auth_type = le_to_host16(mgmt->u.auth.auth_alg);
//		event.auth.status_code =
//			le_to_host16(mgmt->u.auth.status_code);
//		event.auth.auth_transaction =
//			le_to_host16(mgmt->u.auth.auth_transaction);
//		event.auth.ies = mgmt->u.auth.variable;
//		event.auth.ies_len = len - IEEE80211_HDRLEN -
//			sizeof(mgmt->u.auth);
//		wpa_supplicant_event(drv->hapd, EVENT_AUTH, &event);
		break;
	default:
		break;
	}
}


static void
atheros_wireless_event_wireless_custom(struct atheros_driver_data *drv,
				       char *custom, char *end)
{
#define MGMT_FRAM_TAG_SIZE 30 /* hardcoded in driver */
	printf("Custom wireless event: '%s'\n", custom);

    if (strncmp(custom, "Manage.assoc_req ", 17) == 0)
    {
		/* Format: "Manage.assoc_req <frame len>" | zero padding |
		 * frame */
		int len = atoi(custom + 17);
		if (len < 0 || MGMT_FRAM_TAG_SIZE + len > end - custom)
        {
			printf("Invalid Manage.assoc_req event length %d",len);
			return;
		}
		atheros_raw_receive(drv, NULL,(u8 *) custom + MGMT_FRAM_TAG_SIZE, len);
    }
    else
    {
        printf("Unsupport event!\n");
    }
}

static void atheros_wireless_event_wireless(struct atheros_driver_data *drv,
				char *data, unsigned int len)
{
	struct iw_event iwe_buf, *iwe = &iwe_buf;
	char *pos, *end, *custom, *buf;

	pos = data;
	end = data + len;

	while ((size_t) (end - pos) >= IW_EV_LCP_LEN)
    {
		/* Event data may be unaligned, so make a local, aligned copy
		 * before processing. */
		memcpy(&iwe_buf, pos, IW_EV_LCP_LEN);
		printf("Wireless event: cmd=0x%x len=%d",iwe->cmd, iwe->len);
		if (iwe->len <= IW_EV_LCP_LEN || iwe->len > end - pos)
			return;

		custom = pos + IW_EV_POINT_LEN;
		if (/*drv->we_version > 18*/ TRUE &&
		    (iwe->cmd == IWEVMICHAELMICFAILURE ||
		     iwe->cmd == IWEVASSOCREQIE ||
		     iwe->cmd == IWEVCUSTOM))
		{
			/* WE-19 removed the pointer from struct iw_point */
			char *dpos = (char *) &iwe_buf.u.data.length;
			int dlen = dpos - (char *) &iwe_buf;
			memcpy(dpos, pos + IW_EV_LCP_LEN,sizeof(struct iw_event) - dlen);
		} 
        else 
        {
			memcpy(&iwe_buf, pos, sizeof(struct iw_event));
			custom += IW_EV_POINT_OFF;
		}

		switch (iwe->cmd) 
        {
		case IWEVEXPIRED:
            printf("\n===GJF=== %s:drv_event_disassoc!\n",__func__);
//			drv_event_disassoc(drv->hapd,(u8 *) iwe->u.addr.sa_data);
			break;
		case IWEVREGISTERED:
            printf("\n===GJF=== %s:atheros_new_sta!\n",__func__);
//			atheros_new_sta(drv, (u8 *) iwe->u.addr.sa_data);
			break;
		case IWEVASSOCREQIE:
			/* Driver hack.. Use IWEVASSOCREQIE to bypass
			 * IWEVCUSTOM size limitations. Need to handle this
			 * just like IWEVCUSTOM.
			 */
		case IWEVCUSTOM:
            printf("\n===GJF=== %s:IWEVASSOCREQIE | IWEVCUSTOM!\n",__func__);
			if (iwe->u.data.length > end - custom)
				return;
			buf = malloc(iwe->u.data.length + 1);
			if (buf == NULL)
				return;		/* XXX */
			memcpy(buf, custom, iwe->u.data.length);
			buf[iwe->u.data.length] = '\0';

			if (iwe->u.data.flags != 0) {
				atheros_wireless_event_atheros_custom(
					drv, (int) iwe->u.data.flags,
					buf, len);
			} else {
				atheros_wireless_event_wireless_custom(
					drv, buf, buf + iwe->u.data.length);
			}
			free(buf);
			break;
		}

		pos += iwe->len;
	}
}

static void atheros_wireless_event_rtm_newlink(void *ctx,
				   struct ifinfomsg *ifi, u8 *buf, size_t len)
{
	struct atheros_driver_data *drv = ctx;
	int attrlen, rta_len;
	struct rtattr *attr;

	if (ifi->ifi_index != drv->ifindex)
		return;

	attrlen = len;
	attr = (struct rtattr *) buf;

	rta_len = RTA_ALIGN(sizeof(struct rtattr));
	while (RTA_OK(attr, attrlen))
    {
		if (attr->rta_type == IFLA_WIRELESS) 
        {
			atheros_wireless_event_wireless(drv, ((char *) attr) + rta_len,attr->rta_len - rta_len);
		}
		attr = RTA_NEXT(attr, attrlen);
	}
}
                   
static void netlink_receive_link(struct netlink_data *netlink,
				 void (*cb)(void *ctx, struct ifinfomsg *ifi,u8 *buf, size_t len),
				 struct nlmsghdr *h)
{
	if (cb == NULL || NLMSG_PAYLOAD(h, 0) < sizeof(struct ifinfomsg))
		return;
	cb(netlink->cfg->ctx, NLMSG_DATA(h),
	   (u8 *) NLMSG_DATA(h) + NLMSG_ALIGN(sizeof(struct ifinfomsg)),
	   NLMSG_PAYLOAD(h, sizeof(struct ifinfomsg)));
}
                 
static void netlink_receive(int sock, void *eloop_ctx, void *sock_ctx)
{
	struct netlink_data *netlink = eloop_ctx;
	char buf[8192];
	int left;
	struct sockaddr_nl from;
	socklen_t fromlen;
	struct nlmsghdr *h;
	int max_events = 10;

try_again:
	fromlen = sizeof(from);
	left = recvfrom(sock, buf, sizeof(buf), MSG_DONTWAIT,(struct sockaddr *) &from, &fromlen);
	if (left < 0)
    {
		if (errno != EINTR && errno != EAGAIN)
			printf("netlink: recvfrom failed: %s",strerror(errno));
		return;
	}

	h = (struct nlmsghdr *) buf;
	while (NLMSG_OK(h, left))
    {
		switch (h->nlmsg_type) 
        {
		case RTM_NEWLINK:
			netlink_receive_link(netlink, netlink->cfg->newlink_cb,h);
			break;
		case RTM_DELLINK:
			netlink_receive_link(netlink, netlink->cfg->dellink_cb,h);
			break;
		}

		h = NLMSG_NEXT(h, left);
	}

	if (left > 0) 
    {
		printf("netlink: %d extra bytes in the end of netlink message", left);
	}

	if (--max_events > 0) 
    {
		/*
		 * Try to receive all events in one eloop call in order to
		 * limit race condition on cases where AssocInfo event, Assoc
		 * event, and EAPOL frames are received more or less at the
		 * same time. We want to process the event messages first
		 * before starting EAPOL processing.
		 */
		goto try_again;
	}
}

struct netlink_data * netlink_init(struct netlink_config *cfg)
{
	struct netlink_data *netlink;
	struct sockaddr_nl local;

	netlink = os_zalloc(sizeof(*netlink));
	if (netlink == NULL)
		return NULL;

	netlink->sock = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (netlink->sock < 0)
    {
		printf("netlink: Failed to open netlink socket: %s\n", strerror(errno));
		netlink_deinit(netlink);
		return NULL;
	}

	memset(&local, 0, sizeof(local));
	local.nl_family = AF_NETLINK;
	local.nl_groups = RTMGRP_LINK;
	if (bind(netlink->sock, (struct sockaddr *) &local, sizeof(local)) < 0)
	{
		printf("netlink: Failed to bind netlink socket: %s\n", strerror(errno));
		netlink_deinit(netlink);
		return NULL;
	}

//	eloop_register_read_sock(netlink->sock, netlink_receive, netlink,
//				 NULL);

	netlink->cfg = cfg;

	return netlink;
}


struct l2_packet_data * l2_packet_init(
	const char *ifname, const u8 *own_addr, unsigned short protocol,
	void (*rx_callback)(void *ctx, const u8 *src_addr,
			    const u8 *buf, size_t len),
	void *rx_callback_ctx, int l2_hdr)
{
	struct l2_packet_data *l2;
	struct ifreq ifr;
	struct sockaddr_ll ll;

	l2 = os_zalloc(sizeof(struct l2_packet_data));
	if (l2 == NULL)
		return NULL;
	strlcpy(l2->ifname, ifname, sizeof(l2->ifname));
	l2->rx_callback = rx_callback;
	l2->rx_callback_ctx = rx_callback_ctx;
	l2->l2_hdr = l2_hdr;

	l2->fd = socket(PF_PACKET, l2_hdr ? SOCK_RAW : SOCK_DGRAM,htons(protocol));
	if (l2->fd < 0)
    {
		wpa_printf(MSG_ERROR, "%s: socket(PF_PACKET): %s",__func__, strerror(errno));
		free(l2);
		return NULL;
	}
	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, l2->ifname, sizeof(ifr.ifr_name));
	if (ioctl(l2->fd, SIOCGIFINDEX, &ifr) < 0)
    {
		wpa_printf(MSG_ERROR, "%s: ioctl[SIOCGIFINDEX]: %s",__func__, strerror(errno));
		close(l2->fd);
		free(l2);
		return NULL;
	}
	l2->ifindex = ifr.ifr_ifindex;

	memset(&ll, 0, sizeof(ll));
	ll.sll_family = PF_PACKET;
	ll.sll_ifindex = ifr.ifr_ifindex;
	ll.sll_protocol = htons(protocol);
	if (bind(l2->fd, (struct sockaddr *) &ll, sizeof(ll)) < 0)
    {
		wpa_printf(MSG_ERROR, "%s: bind[PF_PACKET]: %s",__func__, strerror(errno));
		close(l2->fd);
		free(l2);
		return NULL;
	}

	if (ioctl(l2->fd, SIOCGIFHWADDR, &ifr) < 0)
    {
		wpa_printf(MSG_ERROR, "%s: ioctl[SIOCGIFHWADDR]: %s",__func__, strerror(errno));
		close(l2->fd);
		free(l2);
		return NULL;
	}
	memcpy(l2->own_addr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
	return l2;
}
void l2_packet_deinit(struct l2_packet_data *l2)
{
	if (l2 == NULL)
		return;

	if (l2->fd >= 0)
    {
//		eloop_unregister_read_sock(l2->fd);
        fd[1] = -1;
		close(l2->fd);
	}
	free(l2);
}
static int
atheros_wireless_event_init(struct atheros_driver_data *drv)
{
	struct netlink_config *cfg;

    drv->we_version = 0;
	cfg = os_zalloc(sizeof(*cfg));
	if (cfg == NULL)
		return -1;
	cfg->ctx = drv;
	cfg->newlink_cb = atheros_wireless_event_rtm_newlink;
	drv->netlink = netlink_init(cfg);
	if (drv->netlink == NULL)
    {
		free(cfg);
		return -1;
	}

	return 0;
}

static void *
atheros_init(struct hostapd_data *hapd, struct wpa_init_params *params)
{
	struct atheros_driver_data *drv;
	struct ifreq ifr;
	struct iwreq iwr;
//	char brname[IFNAMSIZ];

	drv = os_zalloc(sizeof(struct atheros_driver_data));
	if (drv == NULL)
    {
		wpa_printf(MSG_INFO,"Could not allocate memory for atheros driver data");
		return NULL;
	}

	drv->hapd = hapd;
	drv->ioctl_sock = socket(PF_INET, SOCK_DGRAM, 0);
	if (drv->ioctl_sock < 0) 
    {
		wpa_printf(MSG_ERROR, "socket[PF_INET,SOCK_DGRAM]: %s",strerror(errno));
		goto bad;
	}
	memcpy(drv->iface, params->ifname, sizeof(drv->iface));

	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, drv->iface, sizeof(ifr.ifr_name));
	if (ioctl(drv->ioctl_sock, SIOCGIFINDEX, &ifr) != 0) 
    {
		wpa_printf(MSG_ERROR, "ioctl(SIOCGIFINDEX): %s",strerror(errno));
		goto bad;
	}
	drv->ifindex = ifr.ifr_ifindex;

	drv->sock_xmit = l2_packet_init(drv->iface, NULL, ETH_P_PAE,NULL, drv, 1);
	if (drv->sock_xmit == NULL)
		goto bad;
    
	memcpy(params->own_addr, drv->sock_xmit->own_addr,ETH_ALEN);
	memcpy(drv->own_addr, params->own_addr, ETH_ALEN);

    drv->sock_recv = drv->sock_xmit;

	memset(&iwr, 0, sizeof(iwr));
	strlcpy(iwr.ifr_name, drv->iface, IFNAMSIZ);

	iwr.u.mode = IW_MODE_MASTER;

	if (ioctl(drv->ioctl_sock, SIOCSIWMODE, &iwr) < 0)
    {
		wpa_printf(MSG_ERROR,"Could not set interface to master mode! ioctl[SIOCSIWMODE]: %s",strerror(errno));
		goto bad;
	}

	/* mark down during setup */
//	linux_set_iface_flags(drv->ioctl_sock, drv->iface, 0);
//	atheros_set_privacy(drv, 0); /* default to no privacy */

	if (atheros_wireless_event_init(drv))
		goto bad;

	/* Read FILS capability from driver */
//	atheros_read_fils_cap(drv);

	return drv;
bad:
	if (drv->sock_raw)
		l2_packet_deinit(drv->sock_raw);
	if (drv->sock_recv != NULL && drv->sock_recv != drv->sock_xmit)
		l2_packet_deinit(drv->sock_recv);
	if (drv->sock_xmit != NULL)
		l2_packet_deinit(drv->sock_xmit);
	if (drv->ioctl_sock >= 0)
		close(drv->ioctl_sock);
    
	free(drv);
	return NULL;
}

char default_bssid[6]={00,0x90,0x4C,0x88,0x88,0x89};
char default_ifname[32]="ath0";
int main(int argc,char **argv)
{
    fd_set readfds;
    int maxfd;
    struct timeval tv;
    struct atheros_driver_data *drv;
    
    wpa_debug_level = MSG_EXCESSIVE;
    struct hostapd_data hapd;
    memset(hapd,0,sizeof(hapd));
	struct wpa_init_params params;
    memset(hapd,0,sizeof(params));
    
	params.bssid = default_bssid;
	params.ifname =default_ifname;
    memset(&params, 0, sizeof(params));
	params.own_addr = hapd->own_addr;
    
    drv = atheros_init(hapd,&params);
    fd[0] = drv->netlink->sock;
    fd[1] = drv->sock_xmit->fd;
    


    while(1) 
    { 
        FD_ZERO(&readfds); //每次循环都要清空集合，否则不能检测描述符变化
        tv.tv_sec = 1;
        tv.tv_usec = 500;
        if(fd[0] == -1 && fd[1] != -1)
        {
            maxfd = fd[1];
            FD_SET(fd[1],&readfds)); //添加描述符 

        }
        else if(fd[0] != -1 && fd[1] == -1)
        {
             maxfd = fd[0];
             FD_SET(fd[0],&readfds)); //添加描述符 
        }
        else if(fd[0] != -1 && fd[1] != -1)
        {
            maxfd = (fd[0] > fd[1]) ? fd[0] : fd[1];
            FD_SET(fd[0],&readfds)); //添加描述符 
            FD_SET(fd[1],&readfds)); //添加描述符 
        }
        else
        {
            printf("描述符初始化失败，结束程序\n");
            return;
        }

         switch( select(maxfd+1,&readfds,NULL,NULL,&tv))   //select使用 
         { 
             case -1: 
             {
                    perror ("select");
                    exit(-1);
                    break; //select错误，退出程序 
             }
             case 0:
             {
                    printf("select time out!\n");
                    break; //再次轮询
             }
             default: 
                   if(FD_ISSET(drv->netlink->sock,&readfds)) //测试sock是否可读，即是否网络上有数据
                   { 
                        netlink_receive(drv->netlink->sock,drv->netlink,NULL);
                   }
                   else if(FD_ISSET(drv->sock_xmit->fd,&readfds))
                   {
                        l2_packet_receive();
                   }
           }// end switch 
    }//end while 
    return 0;
}
