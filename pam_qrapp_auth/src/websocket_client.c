#include <stdio.h>
#include <string.h>
#include <libwebsockets.h>
#include <openssl/ssl.h>
#include "websocket_client.h"
#include <security/pam_appl.h>
#include <syslog.h>
#include <signal.h>
#include "utils.h"
#include "base64.h"
#include "string_crypt.h"
#include "pam_qrapp_auth.h"
#include "gen_qrcode.h"

#include "ws_constants.h"

static struct lws_context *context;
static int interrupted, port = WS_REMOTE_PORT, options = 0,sig_int_interrupted;
static const char *url = "/dev", *ads = WS_REMOTE_ADDRESS, *iface = NULL;
char *base64_string;

struct app_logic_data {
    char *username;
    char *authkey;
    char sha_code_hex[(SHA_DIGEST_LENGTH * 2) + 3];
    char *challenge_text;
    int current_action;
	pam_handle_t *pamh;
	char *qr_encoded_text;
};

enum {
    SEND_WS_ASK_CON_ID,
    READ_WS_CONNECTION_ID,
    SEND_WS_EXPECT_AUTH,
    READ_WS_AUTH_VERIFIED,
    SEND_WS_CHALLENGE_TEXT,
    READ_WS_CHALLENGE_TEXT
};

struct app_logic_data ws_applogic = {0};

int pam_login_status = PAM_SUCCESS;

const char *ws_com_strings[]={
    "{\"action\":\"getconid\"}",
    "connectionid:",
    "{\"authkey\" : \"%s\", \"username\" : \"%s\",\"action\" : \"expectauth\"}",
    "authVerified:true",
    "{\"action\":\"verifyauth\",\"challengeText\":\"%s\",\"authkey\":\"%s\"}",
    "authverified:"
};

static const struct lws_extension extensions[] = {
	{
		"permessage-deflate",
		lws_extension_callback_pm_deflate,
		"permessage-deflate"
		 "; client_no_context_takeover"
		 "; client_max_window_bits"
	},
	{ NULL, NULL, NULL /* terminator */ }
};

static const struct lws_protocol_vhost_options pvo_iface = {
	NULL,
	NULL,
	"iface",		/* pvo name */
	(void *)&iface	/* pvo value */
};

static const struct lws_protocol_vhost_options pvo_ads = {
	&pvo_iface,
	NULL,
	"ads",		/* pvo name */
	(void *)&ads	/* pvo value */
};

static const struct lws_protocol_vhost_options pvo_url = {
	&pvo_ads,
	NULL,
	"url",		/* pvo name */
	(void *)&url	/* pvo value */
};

static const struct lws_protocol_vhost_options pvo_options = {
	&pvo_url,
	NULL,
	"options",		/* pvo name */
	(void *)&options	/* pvo value */
};

static const struct lws_protocol_vhost_options pvo_port = {
	&pvo_options,
	NULL,
	"port",		/* pvo name */
	(void *)&port	/* pvo value */
};

static const struct lws_protocol_vhost_options pvo_interrupted = {
	&pvo_port,
	NULL,
	"interrupted",		/* pvo name */
	(void *)&interrupted	/* pvo value */
};

static const struct lws_protocol_vhost_options pvo = {
	NULL,		/* "next" pvo linked-list */
	&pvo_interrupted,	/* "child" pvo linked-list */
	"wsrxtx",	/* protocol name we belong to on this vhost */
	""		/* ignored */
};

static struct lws_protocols protocols[] = {
    {
        "wsrxtx",
        ws_callback,
        sizeof(struct per_session_data_size),
        1024,
        0,
        NULL,
        0
    },
    { NULL, NULL, 0, 0, 0, NULL, 0 }
};

static int websocket_write_back(struct lws *wsi_in, const char *str, int str_size_in) 
{
    if (str == NULL || wsi_in == NULL)
        return -1;

    int n;
    int len;
    char *out = NULL;

    if (str_size_in < 1) 
        len = strlen(str);
    else
        len = str_size_in;

    out = (char *)malloc(sizeof(char)*(LWS_SEND_BUFFER_PRE_PADDING + len + LWS_SEND_BUFFER_POST_PADDING));
    //* setup the buffer*/
    memcpy (out + LWS_SEND_BUFFER_PRE_PADDING, str, len );
    //* write out*/
    n = lws_write(wsi_in, out + LWS_SEND_BUFFER_PRE_PADDING, len, LWS_WRITE_TEXT);
    //* free the buffer*/
    free(out);

    return n;
}

/* static void
schedule_callback(struct lws *wsi, int reason, int secs)
{
    
	lws_timed_callback_vh_protocol(lws_get_vhost(wsi),
		lws_get_protocol(wsi), reason, secs);
} */

static void
connect_client(struct lws_sorted_usec_list *sul)
{
    struct vhd_minimal_client_echo *vhd =
		lws_container_of(sul, struct vhd_minimal_client_echo, sul);
	struct lws_client_connect_info i;
	char host[128];

	lws_snprintf(host, sizeof(host), "%s:%u", *vhd->ads, *vhd->port);

	memset(&i, 0, sizeof(i));

	i.context = vhd->context;
	//i.port = *vhd->port;
    i.port = *vhd->port;
	i.address = *vhd->ads;
	i.path = *vhd->url;
	i.host = host;
	i.origin = host;
	i.ssl_connection = LCCSCF_USE_SSL | LCCSCF_ALLOW_SELFSIGNED | LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK | LCCSCF_PIPELINE;
    //i.ssl_connection = 0;
	if ((*vhd->options) & 2)
		i.ssl_connection |= LCCSCF_USE_SSL;
	i.vhost = vhd->vhost;
	i.iface = *vhd->iface;
	//i.protocol = ;
	i.pwsi = &vhd->client_wsi;

	//lwsl_user("connecting to %s:%d/%s\n", i.address, i.port, i.path);

    log_message(LOG_INFO,ws_applogic.pamh,"About to create connection %s",host);

	//return !lws_client_connect_via_info(&i);

    if (!lws_client_connect_via_info(&i))
		lws_sul_schedule(vhd->context, 0, &vhd->sul,
				 connect_client, 10 * LWS_US_PER_SEC);
}

void handle_incoming_ws_message(struct lws *wsi,const char *msg)
{
    char temp_text[150];
    char *temp_ptr=NULL;

    log_message(LOG_INFO,ws_applogic.pamh,"incoming message : %s",msg);

    if(strcmp(msg,"ok") == 0 || strcmp(msg,"OK")==0){
        return;
    }

    switch (ws_applogic.current_action)
    {
    case READ_WS_CONNECTION_ID:
        {
            char *con_id=strstr(msg,ws_com_strings[READ_WS_CONNECTION_ID]);
            int length = strlen(ws_com_strings[READ_WS_CONNECTION_ID]);
            
            if(!con_id){
                pam_login_status=PAM_AUTH_ERR;
                interrupted=1;
                return;
            }

            con_id+=length;
            log_message(LOG_DEBUG,ws_applogic.pamh,"strstr is %s",con_id);
            string_crypt(ws_applogic.sha_code_hex, con_id);

            sprintf(temp_text,"qrauth:%s:%s",ws_applogic.authkey,ws_applogic.sha_code_hex);

            char *qr_encoded_text=get_qrcode_string(temp_text);
            ws_applogic.qr_encoded_text=qr_encoded_text;

            conv_info(ws_applogic.pamh,"\nSSH Auth via QR Code\n\n");
            conv_info(ws_applogic.pamh, ws_applogic.qr_encoded_text);
            //conv_info(ws_applogic.pamh, "\n\nUse Mobile SSH QR Auth App to Authentiate SSh Login\n\n");

            log_message(LOG_INFO,ws_applogic.pamh,"Use Mobile App to Scan \n %s",ws_applogic.qr_encoded_text);
            log_message(LOG_INFO,ws_applogic.pamh,"%s",temp_text);


            ws_applogic.current_action=READ_WS_AUTH_VERIFIED;

            sprintf(temp_text,ws_com_strings[SEND_WS_EXPECT_AUTH],ws_applogic.authkey,ws_applogic.username);
            websocket_write_back(wsi,temp_text,-1);

            conv_read(ws_applogic.pamh,"\n\nUse Mobile SSH QR Auth App to Authentiate SSh Login and Press Enter\n\n",PAM_PROMPT_ECHO_ON);

        }
        break;
    case READ_WS_AUTH_VERIFIED:
        {
            if(strcmp(msg,ws_com_strings[READ_WS_AUTH_VERIFIED]) == 0)
            {
                char random_string[11];
                get_random_string(random_string,10);
                int len = Base64encode_len(10);
                Base64encode(temp_text,random_string,len);

                temp_text[len]='\0';

                ws_applogic.challenge_text=(char*)malloc(strlen(temp_text)+1);

                strcpy(ws_applogic.challenge_text,temp_text);
                ws_applogic.current_action=READ_WS_CHALLENGE_TEXT;

                sprintf(temp_text,ws_com_strings[SEND_WS_CHALLENGE_TEXT],ws_applogic.challenge_text,ws_applogic.authkey);

                websocket_write_back(wsi,temp_text,-1);

            }
            else
            {
                pam_login_status=PAM_AUTH_ERR;
                interrupted=1;
                return;
            }
        }
        break;
    
    case READ_WS_CHALLENGE_TEXT:
        {
            char *challenge_text = strstr(msg,ws_com_strings[READ_WS_CHALLENGE_TEXT]);
            int len = strlen(ws_com_strings[READ_WS_CHALLENGE_TEXT]);

            if(challenge_text){
                challenge_text+=len;
                
                if(strcmp(challenge_text,ws_applogic.challenge_text) == 0){
                    pam_login_status=PAM_SUCCESS;
                    interrupted=1;
                    return;
                }
                else {

                    pam_login_status=PAM_AUTH_ERR;
                    interrupted=1;
                    return;
                }
            }
            else{
                pam_login_status=PAM_AUTH_ERR;
                interrupted=1;
                return;
            }

        }
        break;
    
    default:
        break;
    }

    //fflush(stdin);

}

static int 
ws_callback(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len)
{
    struct per_session_data_size *pss =
			(struct per_session_data_size *)user;
	struct vhd_minimal_client_echo *vhd = (struct vhd_minimal_client_echo *)
			lws_protocol_vh_priv_get(lws_get_vhost(wsi),
				lws_get_protocol(wsi));
	const struct msg *pmsg;
	struct msg amsg;
	int n, m, flags;

    log_message(LOG_INFO,ws_applogic.pamh,"reason is  %d",reason);

    switch (reason)
    {
        case LWS_CALLBACK_PROTOCOL_INIT:
            vhd = lws_protocol_vh_priv_zalloc(lws_get_vhost(wsi),
				lws_get_protocol(wsi),
				sizeof(struct vhd_minimal_client_echo));
            if (!vhd)
                return -1;
            
            vhd->context = lws_get_context(wsi);
		    vhd->vhost = lws_get_vhost(wsi);

            /* get the pointer to "interrupted" we were passed in pvo */
            vhd->interrupted = (int *)lws_pvo_search(
                (const struct lws_protocol_vhost_options *)in,
                "interrupted")->value;
            vhd->port = (int *)lws_pvo_search(
                (const struct lws_protocol_vhost_options *)in,
                "port")->value;
            vhd->options = (int *)lws_pvo_search(
                (const struct lws_protocol_vhost_options *)in,
                "options")->value;
            vhd->ads = (const char **)lws_pvo_search(
                (const struct lws_protocol_vhost_options *)in,
                "ads")->value;
            vhd->url = (const char **)lws_pvo_search(
                (const struct lws_protocol_vhost_options *)in,
                "url")->value;
            vhd->iface = (const char **)lws_pvo_search(
                (const struct lws_protocol_vhost_options *)in,
                "iface")->value;

            connect_client(&vhd->sul);
            
            break;
        case LWS_CALLBACK_CLIENT_ESTABLISHED:
            //websocket_write_back(wsi,"Hello from client",-1);
            log_message(LOG_INFO,ws_applogic.pamh,"Client connection established");
            ws_applogic.current_action=READ_WS_CONNECTION_ID;
            websocket_write_back(wsi,ws_com_strings[SEND_WS_ASK_CON_ID],-1);
            break;

        case LWS_CALLBACK_CLIENT_RECEIVE:
             //printf("[Main Service] Client recvived:%s\n", (char *)in);
             handle_incoming_ws_message(wsi,(char *)in);
             break;
        
        case LWS_CALLBACK_WSI_DESTROY:
            interrupted = 1;
            break;
    
        default:
            //printf("Yet to be implemented ! %d",reason);
            //log_message(LOG_INFO,ws_applogic.pamh,"yet to be implemented %d",reason);
            if(reason ==1){
                log_message(LOG_INFO,ws_applogic.pamh,"reason %s",(char *)in);
            }
            break;
    }

    //fflush(stdout);

    return 0;
}

void sigint_handler(int sig)
{
    sig_int_interrupted=1;
	//interrupted = 1;
}

int auth_via_websocket(char *username,pam_handle_t *pamh)
{
    struct lws_context_creation_info info,con;
    char random_string[11];
    
    //get random string
    get_random_string(random_string,10);

    //convert random string to base64 coz input string is coming from /dev/urandom and may contain binary chars
    const int encoded_length = Base64encode_len(10);
    base64_string=(char *)malloc(encoded_length+1);
    Base64encode(base64_string,random_string,10);

    base64_string[encoded_length]='\0';

    ws_applogic.username=username;
    ws_applogic.authkey=base64_string;
    ws_applogic.current_action=SEND_WS_ASK_CON_ID;
    ws_applogic.pamh=pamh;

    //lws_set_log_level(LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE | LLL_INFO,lwsl_emit_syslog);


    memset(&info, 0, sizeof info);
    
    info.port = CONTEXT_PORT_NO_LISTEN;
	info.protocols = protocols;
	info.pvo = &pvo;

    info.extensions = extensions;
    info.pt_serv_buf_size = 32 * 1024;
    /* #if defined(LWS_WITH_TLS)
	info.options |= LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
    #endif */
	info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT |
		       LWS_SERVER_OPTION_VALIDATE_UTF8;

    
    info.options |= LWS_SERVER_OPTION_H2_JUST_FIX_WINDOW_UPDATE_OVERFLOW;

    info.fd_limit_per_thread = 1 + 1 + 1;

    signal(SIGINT, sigint_handler);

    context = lws_create_context(&info);

    if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}


    while (!lws_service(context, 50) && !interrupted);

    lws_context_destroy(context);

    log_message(LOG_INFO,pamh,"out of loop now, interrupted is %d %d",interrupted,pam_login_status);

    //free up memory
    free(ws_applogic.authkey);
    free(ws_applogic.challenge_text);
    free(ws_applogic.qr_encoded_text);

    return pam_login_status;
}