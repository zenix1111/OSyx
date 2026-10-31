/*
 * Wi-Fi control for OSyx on top of OpenBSD net80211: joining a network
 * (through the same ioctls ifconfig(8) uses: nwid, wpaprotos, wpakey) and
 * a text status with the scan results for user space.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
#include <osyx_bsd.h>
#include <sys/queue.h>
#include <sys/tree.h>
#include <net/if_media.h>
#include <crypto/md5.h>
#include <crypto/sha1.h>
#include <crypto/sha2.h>
#include <crypto/hmac.h>
#include <net80211/ieee80211.h>
#include <net80211/ieee80211_var.h>
#include <net80211/ieee80211_ioctl.h>

/* True for interfaces that net80211 attached. */
int osyx_bsd_is_wireless(struct ifnet *ifp)
{
	return ifp->if_output == ieee80211_output;
}

/* PBKDF2-HMAC-SHA1, as ifconfig(8) derives the WPA PSK (4096 rounds, 32 bytes). */
static void pbkdf2_sha1(const char *pass, const uint8_t *salt, size_t salt_len, uint8_t out[32])
{
	size_t plen = strlen(pass);
	for (uint32_t block = 1; block <= 2; block++) {
		uint8_t u[SHA1_DIGEST_LENGTH], t[SHA1_DIGEST_LENGTH], cnt[4];
		HMAC_SHA1_CTX ctx;
		cnt[0] = block >> 24; cnt[1] = block >> 16; cnt[2] = block >> 8; cnt[3] = block;
		HMAC_SHA1_Init(&ctx, (const uint8_t *)pass, plen);
		HMAC_SHA1_Update(&ctx, salt, salt_len);
		HMAC_SHA1_Update(&ctx, cnt, 4);
		HMAC_SHA1_Final(u, &ctx);
		memcpy(t, u, sizeof(t));
		for (int i = 1; i < 4096; i++) {
			HMAC_SHA1_Init(&ctx, (const uint8_t *)pass, plen);
			HMAC_SHA1_Update(&ctx, u, sizeof(u));
			HMAC_SHA1_Final(u, &ctx);
			for (size_t j = 0; j < sizeof(t); j++)
				t[j] ^= u[j];
		}
		size_t off = (block - 1) * SHA1_DIGEST_LENGTH;
		size_t n = 32 - off < SHA1_DIGEST_LENGTH ? 32 - off : SHA1_DIGEST_LENGTH;
		memcpy(out + off, t, n);
		explicit_bzero(u, sizeof(u));
		explicit_bzero(t, sizeof(t));
	}
}

/*
 * Joins `ssid`; with a passphrase (8..63 characters) as WPA2/WPA-Personal,
 * without one as an open network. Returns 0 or an errno.
 */
int osyx_bsd_wifi_join(struct ifnet *ifp, const uint8_t *ssid, size_t ssid_len, const char *pass)
{
	struct ifreq ifr;
	struct ieee80211_nwid nwid;
	int e;

	if (ssid_len > IEEE80211_NWID_LEN)
		return EINVAL;
	if (pass != NULL && pass[0] != 0 && (strlen(pass) < 8 || strlen(pass) > 63))
		return EINVAL;
	/* net80211 then logs authentication, association and the handshake. */
	ifp->if_flags |= IFF_DEBUG;
	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, ifp->if_xname, sizeof(ifr.ifr_name));
	memset(&nwid, 0, sizeof(nwid));
	nwid.i_len = (uint8_t)ssid_len;
	memcpy(nwid.i_nwid, ssid, ssid_len);
	ifr.ifr_data = (caddr_t)&nwid;
	e = ifp->if_ioctl(ifp, SIOCS80211NWID, (caddr_t)&ifr);
	if (e != 0 && e != ENETRESET)
		return e;
	if (pass != NULL && pass[0] != 0) {
		struct ieee80211_wpaparams wpa;
		memset(&wpa, 0, sizeof(wpa));
		strlcpy(wpa.i_name, ifp->if_xname, sizeof(wpa.i_name));
		wpa.i_enabled = 1;
		wpa.i_protos = IEEE80211_WPA_PROTO_WPA2 | IEEE80211_WPA_PROTO_WPA1;
		wpa.i_akms = IEEE80211_WPA_AKM_PSK;
		wpa.i_ciphers = IEEE80211_WPA_CIPHER_CCMP | IEEE80211_WPA_CIPHER_TKIP;
		wpa.i_groupcipher = IEEE80211_WPA_CIPHER_CCMP;
		e = ifp->if_ioctl(ifp, SIOCS80211WPAPARMS, (caddr_t)&wpa);
		if (e != 0 && e != ENETRESET)
			return e;
		struct ieee80211_wpapsk psk;
		memset(&psk, 0, sizeof(psk));
		strlcpy(psk.i_name, ifp->if_xname, sizeof(psk.i_name));
		psk.i_enabled = 1;
		pbkdf2_sha1(pass, ssid, ssid_len, psk.i_psk);
		e = ifp->if_ioctl(ifp, SIOCS80211WPAPSK, (caddr_t)&psk);
		explicit_bzero(&psk, sizeof(psk));
		if (e != 0 && e != ENETRESET)
			return e;
	} else {
		/* Drop the previous WPA settings before joining an open network. */
		struct ieee80211_wpaparams wpa;
		struct ieee80211_wpapsk psk;
		memset(&wpa, 0, sizeof(wpa));
		strlcpy(wpa.i_name, ifp->if_xname, sizeof(wpa.i_name));
		e = ifp->if_ioctl(ifp, SIOCS80211WPAPARMS, (caddr_t)&wpa);
		if (e != 0 && e != ENETRESET)
			return e;
		memset(&psk, 0, sizeof(psk));
		strlcpy(psk.i_name, ifp->if_xname, sizeof(psk.i_name));
		e = ifp->if_ioctl(ifp, SIOCS80211WPAPSK, (caddr_t)&psk);
		if (e != 0 && e != ENETRESET)
			return e;
	}
	/*
	 * The driver restarts a running interface for the new settings
	 * (ENETRESET); one that a failed attempt left stopped is started here.
	 */
	if ((ifp->if_flags & (IFF_UP | IFF_RUNNING)) != (IFF_UP | IFF_RUNNING)) {
		ifp->if_flags |= IFF_UP;
		memset(&ifr, 0, sizeof(ifr));
		strlcpy(ifr.ifr_name, ifp->if_xname, sizeof(ifr.ifr_name));
		e = ifp->if_ioctl(ifp, SIOCSIFFLAGS, (caddr_t)&ifr);
		if (e != 0)
			return e;
	}
	return 0;
}

static const char *state_name(enum ieee80211_state s)
{
	switch (s) {
	case IEEE80211_S_INIT: return "init";
	case IEEE80211_S_SCAN: return "scanning";
	case IEEE80211_S_AUTH: return "authenticating";
	case IEEE80211_S_ASSOC: return "associating";
	case IEEE80211_S_RUN: return "connected";
	default: return "unknown";
	}
}

static void put_essid(char *buf, size_t cap, size_t *len, const uint8_t *essid, int n)
{
	for (int i = 0; i < n && *len + 1 < cap; i++) {
		uint8_t c = essid[i];
		/* Tabs and newlines separate fields and lines. */
		buf[(*len)++] = (c < 0x20 || c == 0x7f) ? '?' : (char)c;
	}
}

/*
 * Status text: "state S", "ssid X", "bssid aa:..", "channel N", "keys
 * yes|no" for the current association, then one "net\tSSID\tRSSI\tCHANNEL\tSECURITY" line
 * per network seen in scans. Returns the length written.
 */
size_t osyx_bsd_wifi_status(struct ifnet *ifp, char *buf, size_t cap)
{
	struct ieee80211com *ic = (struct ieee80211com *)ifp;
	struct ieee80211_node *ni;
	size_t len = 0;
	if (cap == 0)
		return 0;
	len += snprintf(buf + len, cap - len, "interface %s\nstate %s\n", ifp->if_xname,
	    (ifp->if_flags & IFF_RUNNING) ? state_name(ic->ic_state) : "down");
	if (len >= cap)
		return cap - 1;
	if (ic->ic_state == IEEE80211_S_RUN && ic->ic_bss != NULL) {
		ni = ic->ic_bss;
		len += snprintf(buf + len, cap - len, "ssid ");
		put_essid(buf, cap, &len, ni->ni_essid, ni->ni_esslen);
		len += snprintf(buf + len, cap - len, "\nbssid %s\nchannel %u\nrssi %u\n", ether_sprintf(ni->ni_bssid),
		    ieee80211_chan2ieee(ic, ni->ni_chan), ni->ni_rssi);
		/* "keys no" while associated: the WPA handshake has not finished
		 * (an open network needs none). */
		int keys = ni->ni_port_valid || !(ic->ic_flags & IEEE80211_F_RSNON);
		len += snprintf(buf + len, cap - len, "keys %s\n", keys ? "yes" : "no");
	}
	RBT_FOREACH(ni, ieee80211_tree, &ic->ic_tree) {
		if (len + 80 >= cap)
			break;
		if (ni->ni_esslen == 0)
			continue;
		len += snprintf(buf + len, cap - len, "net\t");
		put_essid(buf, cap, &len, ni->ni_essid, ni->ni_esslen);
		const char *sec = ni->ni_rsnprotos ? "wpa" : (ni->ni_capinfo & IEEE80211_CAPINFO_PRIVACY) ? "wep" : "open";
		len += snprintf(buf + len, cap - len, "\t%u\t%u\t%s\n", ni->ni_rssi, ieee80211_chan2ieee(ic, ni->ni_chan), sec);
	}
	if (len >= cap)
		len = cap - 1;
	buf[len] = 0;
	return len;
}
