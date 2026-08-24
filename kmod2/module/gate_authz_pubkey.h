/*
 * gate_authz_pubkey.h — the vendor's public key (X.509 cert, DER) embedded into
 * the module for signed-allow-list verification (gate_require_sig=1).
 *
 * THIS IS A PLACEHOLDER (length 0).  With a zero-length key, signed mode fails
 * safe — every allow-list is rejected (deny-all).  To enable signed mode:
 *
 *   1. Generate the vendor keypair + self-signed cert (ONCE, keep the key secret):
 *        kmod2/tools/authz-keygen.sh   ->  authz_priv.pem (secret) + authz_cert.der
 *   2. Regenerate this header from the cert:
 *        kmod2/tools/authz-embed-pubkey.sh authz_cert.der > kmod2/module/gate_authz_pubkey.h
 *   3. Rebuild the module.  Sign each deployment's allow-list with authz_priv.pem:
 *        kmod2/tools/authz-sign.sh authz_priv.pem authz_cert.pem /etc/authorized_apps.txt
 *      (produces /etc/authorized_apps.txt.p7s), then insmod with gate_require_sig=1.
 *
 * The private key never ships; the client gets only the module (public key) and
 * a signed list, so they can neither forge a new list nor edit the existing one.
 */
#ifndef ANTIREVFS_GATE_AUTHZ_PUBKEY_H
#define ANTIREVFS_GATE_AUTHZ_PUBKEY_H

/* DER-encoded X.509 certificate carrying the vendor RSA public key. */
static const unsigned char antirev_authz_cert_der[] = {
	/* placeholder — no key embedded; run authz-embed-pubkey.sh to fill this */
	0x00
};
/* Real length is emitted by authz-embed-pubkey.sh; 0 here disables signed mode. */
static const unsigned int antirev_authz_cert_der_len = 0;

#endif /* ANTIREVFS_GATE_AUTHZ_PUBKEY_H */
