#include "anircd.h"

#ifdef SSL_GNUTLS

gnutls_certificate_credentials_t x509_cred;
gnutls_priority_t priority_cache;
static gnutls_dh_params_t dh_params;

/*
void gnutls_certificate_send_x509_rdn_sequence(  	gnutls_session_t    	
session,
  	int   	status);
status=1	so CA not necessary
*/
static int generate_dh_params(void)
{
	gnutls_dh_params_init(&dh_params);
	gnutls_dh_params_generate2(dh_params, DH_BITS);
	return(0);
}

int init_SSL(char *key_file)
{
	gcry_control(GCRYCTL_ENABLE_QUICK_RANDOM, 0);
	gnutls_global_init();
	gnutls_certificate_allocate_credentials(&x509_cred);
	gnutls_certificate_set_x509_key_file(x509_cred, key_file, key_file, GNUTLS_X509_FMT_PEM);
	generate_dh_params();
	gnutls_priority_init(&priority_cache, "NORMAL", NULL);
	gnutls_certificate_set_dh_params(x509_cred, dh_params);
	return(1);
}
#endif
