#include "s2n_ocsp.h"
#include "s2n_ocsp_struct.h"
#include "utils/s2n_safety.h"

/* OCSP_RESPONSE functions */
/* get ocsp response status from OCSP_RESPONSE structure */
int OCSP_response_status(OCSP_RESPONSE *resp, int64_t *resp_status)
{
    int64_t status;
    ENSURE_POSIX_REF(resp);
    ENSURE_POSIX_REF(resp_status);
    status = ASN1_ENUMERATED_get(resp->responseStatus);
    ENSURE_POSIX(0 <= status, S2N_ERR_INTEGER_OVERFLOW);
    *resp_status = status;
    return S2N_SUCCESS;
}


int OCSP_response_get1_basic(OCSP_RESPONSE *resp, OCSP_BASICRESP **basic_resp)
{
    OCSP_RESPBYTES *rb = resp->responseBytes;
    ENSURE_POSIX_REF(rb);
    ENSURE_POSIX_REF(basic_resp);
    ENSURE_POSIX((OBJ_obj2nid(rb->responseType) == NID_id_pkix_OCSP_basic), S2N_ERR_DECODE_CERTIFICATE);
    *basic_resp = ASN1_item_unpack(rb->response, ASN1_ITEM_rptr(OCSP_BASICRESP));
    ENSURE_POSIX_REF(*basic_resp);
    return S2N_SUCCESS;
}


/* FUNCTIONS FOR OCSP_BASICRESP */

/* Return number of OCSP_SINGLERESP responses present in a basic response. */
int OCSP_resp_count(OCSP_BASICRESP *bs, int *count)
{
    ENSURE_POSIX_REF(bs);
    ENSURE_POSIX_REF(count);
    *count = sk_OCSP_SINGLERESP_num(bs->tbsResponseData->responses);
    ENSURE_POSIX(*count != -1, S2N_ERR_NULL);
    return S2N_SUCCESS;
}

int OCSP_resp_get0(OCSP_BASICRESP *bs, int idx, OCSP_SINGLERESP **single_resp)
{
    int resp_count;
    ENSURE_POSIX_REF(bs);
    ENSURE_POSIX_REF(single_resp);
    GUARD(OCSP_resp_count(bs, &resp_count));
    ENSURE_POSIX(0 <= idx && idx < resp_count ,S2N_ERR_ARRAY_INDEX_OOB);
    *single_resp = sk_OCSP_SINGLERESP_value(bs->tbsResponseData->responses, idx);
    ENSURE_POSIX_REF(*single_resp);
    return S2N_SUCCESS;
}

int OCSP_resp_get0_certs(const OCSP_BASICRESP *bs, STACK_OF(X509) **bs_certs)
{
    ENSURE_POSIX_REF(bs);
    ENSURE_POSIX_REF(bs->certs);
    ENSURE_POSIX_REF(bs_certs);
    *bs_certs = bs->certs;
    return S2N_SUCCESS;
}

int OCSP_basic_add1_cert(OCSP_BASICRESP *bs, X509 *cert)
{
    ENSURE_POSIX_REF(bs);
    /* checks if bs->certs is NULL and initializes bs->certs if it is NULL (breaks to error if not initialisable) */
    if (bs->certs == NULL) {
        bs->certs = sk_X509_new_null();
        ENSURE_POSIX_REF(bs->certs);
    }
    ENSURE_POSIX_REF(cert);
    /* check if below or equal to 0, OpenSSL functions return 1 or more on success, 0 or below on failure */
    ENSURE_POSIX(sk_X509_push(bs->certs, cert) > 0,S2N_ERR_SIZE_MISMATCH);
    ENSURE_POSIX( X509_up_ref(cert) > 0, S2N_ERR_SIZE_MISMATCH);
    return S2N_SUCCESS;
}

int OCSP_resp_find_status(OCSP_BASICRESP *bs, OCSP_CERTID *id, int *status,
                          int *reason,
                          ASN1_GENERALIZEDTIME **revtime,
                          ASN1_GENERALIZEDTIME **thisupd,
                          ASN1_GENERALIZEDTIME **nextupd)
{
    ENSURE_POSIX_REF(bs);
    ENSURE_POSIX_REF(id);
    ENSURE_POSIX_REF(status);
    ENSURE_POSIX_REF(reason);
    ENSURE_POSIX_REF(revtime);
    ENSURE_POSIX_REF(thisupd);
    ENSURE_POSIX_REF(nextupd);

    OCSP_SINGLERESP *single;
    int idx;
    GUARD(OCSP_resp_find(bs, id, -1, &idx));
    ENSURE_POSIX(idx >= 0, S2N_ERR_CERT_NOT_VALIDATED);
    GUARD(OCSP_resp_get0(bs, idx, &single));
    GUARD(OCSP_single_get0_status(single, status, reason, revtime, thisupd, nextupd));
    return S2N_SUCCESS;
}

int OCSP_resp_find(OCSP_BASICRESP *bs, OCSP_CERTID *id, int last, int *found_idx)
{
    ENSURE_POSIX_REF(bs);
    ENSURE_POSIX_REF(id);
    ENSURE_POSIX_REF(found_idx);


    STACK_OF(OCSP_SINGLERESP) *sresp;
    OCSP_SINGLERESP *single;
    *found_idx = -1;
    if (last < 0) {
        last = 0;
    }
    else {
        last++;
    }
    sresp = bs->tbsResponseData->responses;
    ENSURE_POSIX_REF(sresp);
    for (size_t i = last; i < sk_OCSP_SINGLERESP_num(sresp); i++) {
        single = sk_OCSP_SINGLERESP_value(sresp, i);
        ENSURE_POSIX_REF(single);
        if (!OCSP_id_cmp(id, single->certId)) {
            *found_idx = i;
            return S2N_SUCCESS;
        }
    }
    return S2N_SUCCESS;
}

/* FUNCTIONS FOR OCSP_SINGLERESP */
/*
* Extract status information from an OCSP_SINGLERESP structure. Note: the
* revtime and reason values are only set if the certificate status is
* revoked. Returns numerical value of status.
*/
int OCSP_single_get0_status(OCSP_SINGLERESP *single,int *status, int *reason,
                            ASN1_GENERALIZEDTIME **revtime,
                            ASN1_GENERALIZEDTIME **thisupd,
                            ASN1_GENERALIZEDTIME **nextupd)
{
    ENSURE_POSIX_REF(single);
    ENSURE_POSIX_REF(status);
    ENSURE_POSIX_REF(reason);
    ENSURE_POSIX_REF(revtime);
    ENSURE_POSIX_REF(thisupd);
    ENSURE_POSIX_REF(nextupd);

    OCSP_CERTSTATUS *cst;
    cst = single->certStatus;
    *status = cst->type;
    if (*status == V_OCSP_CERTSTATUS_REVOKED) {
        OCSP_REVOKEDINFO *rev = cst->value.revoked;
        ENSURE_POSIX_REF(rev);
        /* time values assigned are allowed to be NULL if certificate fields are empty */
        ENSURE_POSIX_REF(*revtime = rev->revocationTime);
        if (rev->revocationReason) {
            *reason = ASN1_ENUMERATED_get(rev->revocationReason);
        }
        else {
            *reason = CRL_REASON_NONE;
        }
    }
    /* time values assigned are allowed to be NULL if certificate fields are empty */
    *thisupd = single->thisUpdate;
    *nextupd = single->nextUpdate;
    return S2N_SUCCESS;
}

/* FUNCTIONS FOR OCSP_CERTID */
/* uses memcmp way within, 0 on equal, other values mean larger or smaller */
int OCSP_id_issuer_cmp(const OCSP_CERTID *a, const OCSP_CERTID *b)
{
    ENSURE_POSIX_REF(a);
    ENSURE_POSIX_REF(b);
    int ret = OBJ_cmp(a->hashAlgorithm->algorithm, b->hashAlgorithm->algorithm);
    if(ret != 0) return ret;
    ret = ASN1_OCTET_STRING_cmp(a->issuerNameHash, b->issuerNameHash);
    if(ret != 0) return ret;
    ret = ASN1_OCTET_STRING_cmp(a->issuerKeyHash, b->issuerKeyHash);
    return ret;
}

/* uses memcmp way within, 0 on equal, other values mean larger or smaller */
int OCSP_id_cmp(const OCSP_CERTID *a, const OCSP_CERTID *b)
{
    ENSURE_POSIX_REF(a);
    ENSURE_POSIX_REF(b);
    int ret = OCSP_id_issuer_cmp(a, b);
    if (ret != 0) return ret;
    ret = ASN1_INTEGER_cmp(a->serialNumber, b->serialNumber);
    return ret;
}

int OCSP_cert_to_id(const EVP_MD *dgst, X509 *subject, X509 *issuer, OCSP_CERTID **new_certid)
{
    ENSURE_POSIX_REF(issuer);
    ENSURE_POSIX_REF(new_certid);

    const X509_NAME *iname;
    const ASN1_INTEGER *serial;
    ASN1_BIT_STRING *ikey;
    if (dgst == NULL) {
        dgst = EVP_sha1();
    }
    if (subject != NULL) {
        iname = X509_get_issuer_name(subject);
        serial = X509_get_serialNumber(subject);
    } else {
        iname = X509_get_subject_name(issuer);
        serial = NULL;
    }
    ikey = X509_get0_pubkey_bitstr(issuer);
    ENSURE_POSIX_REF(iname);
    ENSURE_POSIX_REF(ikey);
    GUARD(OCSP_cert_id_new(dgst, iname, ikey, serial, new_certid));
    return S2N_SUCCESS;
}


#define ENSURE_CERTID_CLEANUP(condition, cleanup, error)   do {if ( !(condition)) { GUARD(cleanup); BAIL_POSIX(error); }} while (0)
static int OCSP_cert_id_new_cleanup(OCSP_CERTID *cid){
    OCSP_CERTID_free(cid);
    return S2N_SUCCESS;
}

int OCSP_cert_id_new(const EVP_MD *dgst,
                     const X509_NAME *issuerName,
                     const ASN1_BIT_STRING *issuerKey,
                     const ASN1_INTEGER *serialNumber,
                     OCSP_CERTID **new_certid)
{
    ENSURE_POSIX_REF(dgst);
    ENSURE_POSIX_REF(issuerName);
    ENSURE_POSIX_REF(issuerKey);
    ENSURE_POSIX_REF(serialNumber);
    ENSURE_POSIX_REF(new_certid);

    int nid;
    unsigned int i;
    X509_ALGOR *alg;
    OCSP_CERTID *cid = NULL;
    unsigned char md[EVP_MAX_MD_SIZE];

    ENSURE_CERTID_CLEANUP( (cid = OCSP_CERTID_new()) != NULL, OCSP_cert_id_new_cleanup(cid) , S2N_ERR_DECODE_CERTIFICATE);
    alg = cid->hashAlgorithm;
    ASN1_OBJECT_free(alg->algorithm);
    ENSURE_CERTID_CLEANUP( (nid = EVP_MD_type(dgst)) != NID_undef, OCSP_cert_id_new_cleanup(cid) , S2N_ERR_DECODE_CERTIFICATE);

    ENSURE_CERTID_CLEANUP( 0 < X509_ALGOR_set0(alg, OBJ_nid2obj(nid), V_ASN1_NULL, NULL), OCSP_cert_id_new_cleanup(cid) , S2N_ERR_DECODE_CERTIFICATE);
    ENSURE_CERTID_CLEANUP( X509_NAME_digest(issuerName, dgst, md, &i), OCSP_cert_id_new_cleanup(cid) , S2N_ERR_DECODE_CERTIFICATE);
    ENSURE_CERTID_CLEANUP( ASN1_OCTET_STRING_set(cid->issuerNameHash, md, i), OCSP_cert_id_new_cleanup(cid) , S2N_ERR_DECODE_CERTIFICATE);

    /* Calculate the issuerKey hash, excluding tag and length */
    ENSURE_CERTID_CLEANUP( EVP_Digest(issuerKey->data, issuerKey->length, md, &i, dgst, NULL), OCSP_cert_id_new_cleanup(cid) , S2N_ERR_DECODE_CERTIFICATE);
    ENSURE_CERTID_CLEANUP( ASN1_OCTET_STRING_set(cid->issuerKeyHash, md, i), OCSP_cert_id_new_cleanup(cid) , S2N_ERR_DECODE_CERTIFICATE);
    ENSURE_CERTID_CLEANUP( EVP_Digest(issuerKey->data, issuerKey->length, md, &i, dgst, NULL), OCSP_cert_id_new_cleanup(cid) , S2N_ERR_DECODE_CERTIFICATE);

    if (serialNumber != NULL) {
        ENSURE_CERTID_CLEANUP( ASN1_STRING_copy(cid->serialNumber, serialNumber) != 0, OCSP_cert_id_new_cleanup(cid) , S2N_ERR_DECODE_CERTIFICATE);
    }
    *new_certid = cid;
    return S2N_SUCCESS;
}
