#include "s2n_ocsp.h"
#include "s2n_ocsp_struct.h"
#include "utils/s2n_safety.h"

/* file that contains all functions used only in OCSP_basic_verify
 * OCSP_basic_verify checks that the stapled ocsp response CAN be verified, not that it has been verified.
 * */
static int ocsp_find_signer(X509 **psigner, OCSP_BASICRESP *bs, STACK_OF(X509) *certs, unsigned long *flags);
static int ocsp_find_signer_sk(STACK_OF(X509) *certs, OCSP_RESPID *id, X509 **signer);

static int ocsp_signer_verify(OCSP_BASICRESP *bs, X509 *signer, unsigned long flags);
static int ocsp_assign_untrusted(STACK_OF(X509) **untrusted, OCSP_BASICRESP *bs,
    STACK_OF(X509) *certs, unsigned long flags);
static int ocsp_assign_chain(STACK_OF(X509) **chain, X509_STORE *st, X509 *signer, STACK_OF(X509) *untrusted);

static int ocsp_check_issuer(OCSP_BASICRESP *bs, STACK_OF(X509) *chain, unsigned long flags);
static int ocsp_check_ids(STACK_OF(OCSP_SINGLERESP) *sresp, OCSP_CERTID **ret);
static int ocsp_match_issuerid(X509 *cert, OCSP_CERTID *cid, STACK_OF(OCSP_SINGLERESP) *sresp);
static int ocsp_check_delegated(X509 *x);

#define OCSP_BASICRESP_verify(a,r,d) ASN1_item_verify(ASN1_ITEM_rptr(OCSP_RESPDATA),\
        (a)->signatureAlgorithm,(a)->signature,(a)->tbsResponseData,r)

#define IS_OCSP_FLAG_SET(flags, query) (flags & query)

/**
 * Ensures `x` is not an error, otherwise the function will execute `cleanup`, then`BAIL` with `error`
 */
#define GUARD_CLEANUP(x, cleanup, error)   do {if ( !((x) >= S2N_SUCCESS) ) { GUARD(cleanup); BAIL_POSIX(error); }} while (0)

static int basic_verify_cleanup(STACK_OF(X509) *chain, OCSP_BASICRESP *bs, STACK_OF(X509) *certs, STACK_OF(X509) *untrusted);

#define S2N_MISMATCH 1

/* main verification function, checks that the stapled ocsp response CAN be verified, not that it has been verified. */
int OCSP_basic_verify(OCSP_BASICRESP *bs, STACK_OF(X509) *certs, X509_STORE *st, unsigned long flags)
{
    ENSURE_POSIX_REF(bs);
    ENSURE_POSIX_REF(certs);
    ENSURE_POSIX_REF(st);
    X509 *signer = NULL;
    STACK_OF(X509) *chain = NULL;
    STACK_OF(X509) *untrusted = NULL;

    /* returns success if signer found in stack of certs or bs->certs */
    GUARD_CLEANUP(ocsp_find_signer(&signer, bs, certs, &flags), basic_verify_cleanup(chain, bs, certs, untrusted), S2N_ERR_VERIFY_SIGNATURE);

    /* returns success if public key in signer matches basic response */
    GUARD_CLEANUP(ocsp_signer_verify(bs, signer, flags), basic_verify_cleanup(chain, bs, certs, untrusted), S2N_ERR_VERIFY_SIGNATURE);

    /* find certificate chain from not yet trusted stack and try verifying
     * if OCSP_NOVERIFY flag is set, then the function returns success*/
    if (!IS_OCSP_FLAG_SET(flags, OCSP_NOVERIFY)) {
        /* assign value to untrusted stack */
        GUARD_CLEANUP(ocsp_assign_untrusted(&untrusted, bs, certs, flags), basic_verify_cleanup(chain, bs, certs, untrusted), S2N_ERR_ALLOC);

        /*  do checks on ctx store and assign value to chain */
        GUARD_CLEANUP(ocsp_assign_chain(&chain, st, signer, untrusted), basic_verify_cleanup(chain, bs, certs, untrusted), S2N_ERR_CERT_NOT_VALIDATED);

        /* if NOCHECKS is on, then we skip over the checks, otherwise we check the chain (OCSP_NOCHECKS means we don't have to check issuer) */
        if (!IS_OCSP_FLAG_SET(flags, OCSP_NOCHECKS)) {
        /* At this point we have a valid certificate chain need to verify it against the OCSP issuer criteria.  */
        GUARD_CLEANUP(ocsp_check_issuer(bs, chain, flags), basic_verify_cleanup(chain, bs, certs, untrusted), S2N_ERR_CERT_NOT_VALIDATED);
        }
    }
    printf("s2n-ocsp verify integration success\n");
    GUARD(basic_verify_cleanup(chain, bs, certs, untrusted));
    return S2N_SUCCESS;
}

    /* cleanup function meant only for use in 'OCSP_basic_verify' function */
static int basic_verify_cleanup(STACK_OF(X509) *chain, OCSP_BASICRESP *bs, STACK_OF(X509) *certs, STACK_OF(X509) *untrusted)
{
    sk_X509_pop_free(chain, X509_free);
    if (bs->certs && certs) {
        sk_X509_free(untrusted);
    }
    return S2N_SUCCESS;
}

/* returns success if signer found in stack of certs or bs->certs */
static int ocsp_find_signer(X509 **psigner, OCSP_BASICRESP *bs,
                            STACK_OF(X509) *certs, unsigned long *flags)
{
    ENSURE_POSIX_REF(psigner);
    ENSURE_POSIX_REF(bs);
    ENSURE_POSIX_REF(certs);
    ENSURE_POSIX_REF(flags);

    X509 *signer = NULL;
    OCSP_RESPID *rid = bs->tbsResponseData->responderId;
    if (ocsp_find_signer_sk(certs, rid, &signer) == S2N_SUCCESS) {
        *psigner = signer;
        /* if the signer certificate was found in certs and the flags contain OCSP_TRUSTOTHER, we turn on OCSP_NOVERIFY */
        if(IS_OCSP_FLAG_SET(*flags, OCSP_TRUSTOTHER)) {
            *flags |= OCSP_NOVERIFY;
        }
        return S2N_SUCCESS;
    }
    /* search the certificates the responder may have included in bs unless the flags contain OCSP_NOINTERN */
    if (!IS_OCSP_FLAG_SET(*flags, OCSP_NOINTERN) &&
    (ocsp_find_signer_sk(bs->certs, rid, &signer) == S2N_SUCCESS))
    {
        *psigner = signer;
        return S2N_SUCCESS;
    }
    /* Maybe lookup from store if by subject name */

    *psigner = NULL;
    return S2N_FAILURE;
}



/* used by above function ocsp_find_signer, success if signer is found in stack of certs, failure if not found */
static int ocsp_find_signer_sk(STACK_OF(X509) *certs, OCSP_RESPID *id, X509 **signer)
{
    ENSURE_POSIX_REF(certs);
    ENSURE_POSIX_REF(id);
    ENSURE_POSIX_REF(signer);

    unsigned char tmphash[SHA_DIGEST_LENGTH], *keyhash;
    X509 *x = NULL;

    /* Easy if lookup by name */
    if (id->type == V_OCSP_RESPID_NAME) {
        ENSURE_POSIX_REF(*signer = X509_find_by_subject(certs, id->value.byName));
        return S2N_SUCCESS;
    }

    /* Lookup by key hash */
    /* If key hash isn't SHA1 length then forget it */
    if (id->value.byKey->length != SHA_DIGEST_LENGTH) {
        return S2N_FAILURE;
    }
    keyhash = id->value.byKey->data;
    /* Calculate hash of each key and compare */
    for (size_t i = 0; i < sk_X509_num(certs); i++) {
        x = sk_X509_value(certs, i);
        ENSURE_POSIX_REF(x);
        /* X509 OpenSSL function, returns 1 or more on success, 0 or below on failure */
        ENSURE_POSIX(X509_pubkey_digest(x, EVP_sha1(), tmphash, NULL) > 0, S2N_ERR_INVALID_CERT_STATE);
        if (memcmp(keyhash, tmphash, SHA_DIGEST_LENGTH) == S2N_SUCCESS) {
            *signer = x;
            return S2N_SUCCESS;
        }
    }
    return S2N_FAILURE;
}

/* returns success if public key in signer matches basic response */
static int ocsp_signer_verify(OCSP_BASICRESP *bs, X509 *signer, unsigned long flags)
{
    /* checks the signature of bs and fails on error unless the flags contain OCSP_NOSIGS */
    if (!IS_OCSP_FLAG_SET(flags, OCSP_NOSIGS)) {
        EVP_PKEY *skey;
        skey = X509_get_pubkey(signer);
        ENSURE_POSIX(skey != NULL, S2N_ERR_INVALID_CERT_STATE);

        /* ASN1 OpenSSL function, returns 1 or more on success, 0 or below on failure */
        ENSURE_POSIX(OCSP_BASICRESP_verify(bs, skey, 0) > 0, S2N_ERR_VERIFY_SIGNATURE);
    }
    return S2N_SUCCESS;
}

/* assign value to untrusted stack */
static int ocsp_assign_untrusted(STACK_OF(X509) **untrusted, OCSP_BASICRESP *bs,
    STACK_OF(X509) *certs, unsigned long flags)
{
    /* all certificates in cert and in bs are considered as untrusted certificates
     * of the validation path for the signer certificate unless the OCSP_NOCHAIN flag is set */
    if(IS_OCSP_FLAG_SET(flags, OCSP_NOCHAIN)) {
        *untrusted = NULL;
    } else if (bs->certs && certs) {
        *untrusted = sk_X509_dup(bs->certs);
        for (size_t i = 0; i < sk_X509_num(certs); i++) {
            ENSURE_POSIX(sk_X509_push(*untrusted, sk_X509_value(certs, i)) > 0, S2N_ERR_ALLOC);
        }
    } else if (certs != NULL) {
        *untrusted = certs;
    } else {
        *untrusted = bs->certs;
    }
    return S2N_SUCCESS;
}

/* assign value to chain */
static int ocsp_assign_chain(STACK_OF(X509) **chain, X509_STORE *st, X509 *signer, STACK_OF(X509) *untrusted)
{
    /* create ctx store */
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    ENSURE_POSIX_REF(ctx);

    /* Do checks on ctx store */
    /* X509 OpenSSL functions, returns 1 or more on success, 0 or below on failure */
    ENSURE_POSIX(X509_STORE_CTX_init(ctx, st, signer, untrusted) > 0, S2N_ERR_CERT_NOT_VALIDATED);
    ENSURE_POSIX(X509_STORE_CTX_set_purpose(ctx, X509_PURPOSE_OCSP_HELPER) > 0, S2N_ERR_CERT_NOT_VALIDATED);
    ENSURE_POSIX(X509_verify_cert(ctx) > 0, S2N_ERR_CERT_NOT_VALIDATED);

    /* get certificate chain from ctx store */
    ENSURE_POSIX_REF(*chain = X509_STORE_CTX_get1_chain(ctx));

    X509_STORE_CTX_free(ctx);
    return S2N_SUCCESS;
}

/* returns success on check success, S2N_FAILURE on failure */
static int ocsp_check_issuer(OCSP_BASICRESP *bs, STACK_OF(X509) *chain, unsigned long flags)
{
    ENSURE_POSIX_REF(bs);
    ENSURE_POSIX_REF(chain);
    STACK_OF(OCSP_SINGLERESP) *sresp;

    X509 *signer = NULL, *x = NULL, *sca = NULL;
    OCSP_CERTID *caid = NULL;
    sresp = bs->tbsResponseData->responses;

    /* X509 OpenSSL function, returns 1 or more on success, 0 or below on failure */
    ENSURE_POSIX(sk_X509_num(chain) > 0, S2N_ERR_NO_CERT_FOUND);

    /* See if the issuer IDs match, If ID mismatch or other error then return  */
    GUARD(ocsp_check_ids(sresp, &caid));

    signer = sk_X509_value(chain, 0);
    ENSURE_POSIX_REF(signer);
    /* Check to see if OCSP responder CA matches request CA */
    if (sk_X509_num(chain) > 1) {
        ENSURE_POSIX_REF(sca = sk_X509_value(chain, 1));
        /* If fatal error we break and fail
         * If valid match, we do some checks then finish,
         * If mismatch we continue to search */
        int issuer_match_ret = ocsp_match_issuerid(sca, caid, sresp);
        ENSURE_POSIX(issuer_match_ret >= 0, S2N_ERR_CERT_NOT_VALIDATED);
        if(issuer_match_ret == S2N_SUCCESS){
            /* We have a match, if extensions OK then success */
            GUARD(ocsp_check_delegated(signer));
            return S2N_SUCCESS;
        }
    }


    /* Otherwise check if OCSP request signed directly by request CA */
    int issuer_match_ret = ocsp_match_issuerid(signer, caid, sresp);
    /* If fatal error we break and fail
    * If valid match, we return success,
    * If mismatch we continue to do some other checks */
    ENSURE_POSIX(issuer_match_ret >= 0, S2N_ERR_CERT_NOT_VALIDATED);
    if(issuer_match_ret == S2N_SUCCESS) {
        return S2N_SUCCESS;
    }
    /* Easy case: explicitly trusted. Get root CA and let caller check for explicit trust themselves
    * if flags do not contain OCSP_NOEXPLICIT the function checks for explicit trust for OCSP signing in the root CA certificate. */
    ENSURE_POSIX(!IS_OCSP_FLAG_SET(flags, OCSP_NOEXPLICIT), S2N_ERR_CERT_NOT_VALIDATED);

    ENSURE_POSIX_REF(x = sk_X509_value(chain, sk_X509_num(chain) - 1));
    ENSURE_POSIX(X509_check_trust(x, NID_OCSP_sign, 0) == X509_TRUST_TRUSTED, S2N_ERR_CERT_NOT_VALIDATED);
    return S2N_SUCCESS;
}

/* S2N_MISMATCH on just a mismatch  S2N_SUCCESS on match, S2N_FAILURE on failure */
static int ocsp_match_issuerid(X509 *cert, OCSP_CERTID *cid, STACK_OF(OCSP_SINGLERESP) *sresp)
{
    ENSURE_POSIX_REF(cert);

    /* If only one ID to match then do it, otherwise goto whole list
     * cid will be NULL when it reaches end of SINGLERESP list */
    if(cid) {
        const EVP_MD *dgst = NULL;
        const X509_NAME *iname = NULL;
        int mdlen;
        unsigned char md[EVP_MAX_MD_SIZE];
        ENSURE_POSIX_REF(dgst = EVP_get_digestbyobj(cid->hashAlgorithm->algorithm));

        mdlen = EVP_MD_size(dgst);
        ENSURE_POSIX(mdlen >= 0, S2N_ERR_CERT_TYPE_UNSUPPORTED);
        iname = X509_get_subject_name(cert);

        ENSURE_POSIX(X509_NAME_digest(iname, dgst, md, NULL) > 0, S2N_ERR_CERT_NOT_VALIDATED);

        /* ensure length is the same, if not the same it's a mismatch */
        if((cid->issuerNameHash->length != mdlen) || (cid->issuerKeyHash->length != mdlen)) {
            return S2N_MISMATCH;
        }
        /* ensure that memcmp equals 0, if not, it's a mismatch */
        if(memcmp(md, cid->issuerNameHash->data, mdlen) != S2N_SUCCESS) {
            return S2N_MISMATCH;
        }
        /* X509 OpenSSL function, returns 1 or more on success, 0 or below on failure */
        ENSURE_POSIX(X509_pubkey_digest(cert, dgst, md, NULL) > 0, S2N_ERR_CERT_TYPE_UNSUPPORTED);
        /* ensure that memcmp equals 0, if not, it's a mismatch */
        if(memcmp(md, cid->issuerKeyHash->data, mdlen) != S2N_SUCCESS) {
            return S2N_MISMATCH;
        }

        return S2N_SUCCESS;
    } else {
        /* We have to match the whole lot */
        OCSP_CERTID *tmpid = NULL;
        for (size_t i = 0; i < sk_OCSP_SINGLERESP_num(sresp); i++) {
        tmpid = sk_OCSP_SINGLERESP_value(sresp, i)->certId;
        GUARD(ocsp_match_issuerid(cert, tmpid, NULL));
        }
        return S2N_SUCCESS;
    }
}

/*
 * Check the issuer certificate IDs for equality. If there is a mismatch with
 * the same algorithm then there's no point trying to match any certificates
 * against the issuer. If the issuer IDs all match then we just need to check
 * equality against one of them.
 */
static int ocsp_check_ids(STACK_OF(OCSP_SINGLERESP) *sresp, OCSP_CERTID **ret)
{
    ENSURE_POSIX_REF(sresp);
    ENSURE_POSIX_REF(ret);

    OCSP_CERTID *tmpid = NULL, *cid = NULL;
    int idcount;

    idcount = sk_OCSP_SINGLERESP_num(sresp);
    ENSURE_POSIX(idcount > 0, S2N_ERR_CERT_NOT_VALIDATED);

    cid = sk_OCSP_SINGLERESP_value(sresp, 0)->certId;
    ENSURE_POSIX_REF(cid);
    *ret = NULL;

    for (size_t i = 1; i < idcount; i++) {
        ENSURE_POSIX_REF(tmpid = sk_OCSP_SINGLERESP_value(sresp, i)->certId);
        /* Check to see if IDs match, if match, skip over this case */
        if(OCSP_id_issuer_cmp(cid, tmpid)) {
            /* check if algorithm is a match, if it is, the IDs truly don't match and we return a failure */
            ENSURE_POSIX(!OBJ_cmp(tmpid->hashAlgorithm->algorithm, cid->hashAlgorithm->algorithm),
                S2N_ERR_CERT_NOT_VALIDATED);
            /* If algorithm mismatch OpenSSL let's the caller deal with it and
             * returns a postive number, so we still return SUCCESS */
            return S2N_SUCCESS;
        }
    }
    /* All IDs match: only need to check one ID */
    *ret = cid;
    return S2N_SUCCESS;
}


static int ocsp_check_delegated(X509 *x)
{
    ENSURE_POSIX_REF(x);
    ENSURE_POSIX((X509_get_extension_flags(x) & EXFLAG_XKUSAGE) && (X509_get_extended_key_usage(x) & XKU_OCSP_SIGN),
                 S2N_ERR_CERT_NOT_VALIDATED);
    return S2N_SUCCESS;
}