#include <netinet/in.h>
#include <unistd.h>
#include <math.h>

#include "ndpi_typedefs.h"
#include "ndpi_patricia_typedefs.h"
#include "ndpi_includes.h"
#include "ndpi_typedefs.h"
#include "ndpi_main.h"
#include "ahocorasick.h"
#include "bpf.h"
#include "ndpi_util.h"
#include "ndpi_api.h"
#include "uthash.h"
#include "libcache.h"
#include "inc_generated/ndpi_content_match.h"
#include "inc_generated/ndpi_dga_match.h"
#include <llprint.h>
#include <cos_debug.h>

struct flow_id_stats {
  u_int32_t flow_id;
  UT_hash_handle hh;   /* makes this structure hashable */
};

struct packet_id_stats {
  u_int32_t packet_id;
  UT_hash_handle hh;   /* makes this structure hashable */
};

struct payload_stats {
  u_int8_t *pattern;
  u_int8_t pattern_len;
  u_int16_t num_occurrencies;
  struct flow_id_stats *flows;
  struct packet_id_stats *packets;
  UT_hash_handle hh;   /* makes this structure hashable */
};

#ifndef min
#define min(a,b)				\
  ({ __typeof__ (a) _a = (a);			\
    __typeof__ (b) _b = (b);			\
    _a < _b ? _a : _b; })
#endif

static void free_ptree_data(void *data) {
  ;
}

/**
 * \brief Calculate the difference betwen two times (result = a - b)
 * \param a First time value
 * \param b Second time value
 * \param result The difference between the two time values
 * \return none
 */
void
ndpi_timer_sub(const pkt_timeval *a,
               const pkt_timeval *b,
               pkt_timeval *result)
{
  result->tv_sec = (unsigned long long)a->tv_sec - (unsigned long long)b->tv_sec;
  result->tv_usec = (unsigned long long)a->tv_usec - (unsigned long long)b->tv_usec;
  if(result->tv_usec < 0) {
    --result->tv_sec;
    result->tv_usec += 1000000;
  }
}

/**
 * \brief Calculate the milliseconds representation of a timeval.
 * \param ts Timeval
 * \return unsigned int (64bit) - Milliseconds
 */
u_int64_t
ndpi_timeval_to_milliseconds(pkt_timeval ts)
{
  u_int64_t sec = ts.tv_sec;
  u_int64_t usec = ts.tv_usec;
  return usec / 1000 + sec * 1000;
}

unsigned int
ndpi_timer_lt(const pkt_timeval *a,
              const pkt_timeval *b)
{
  return (a->tv_sec == b->tv_sec) ?
    (a->tv_usec < b->tv_usec):(a->tv_sec < b->tv_sec);
}

/**
 * \brief Calculate the microseconds representation of a timeval.
 * \param ts Timeval
 * \return unsigned int (64bit) - Microseconds
 */
u_int64_t
ndpi_timeval_to_microseconds(pkt_timeval ts)
{
  u_int64_t sec = ts.tv_sec;
  u_int64_t usec = ts.tv_usec;
  return usec + sec * 1000 * 1000;;
}

u_int8_t plen2slot(u_int16_t plen) {
  /*
     Slots [32 bytes lenght]
     0..31, 32..63 ...
  */

  if(plen > PLEN_MAX)
    return(PLEN_NUM_BINS-1);
  else
    return(plen/PLEN_BIN_LEN);
}

static inline uint8_t flow_is_proto(struct ndpi_flow_struct *flow, u_int16_t p) {
  return((flow->detected_protocol_stack[0] == p) || (flow->detected_protocol_stack[1] == p));
}

static int ndpi_default_ports_tree_node_t_cmp(const void *a, const void *b) {
  ndpi_default_ports_tree_node_t *fa = (ndpi_default_ports_tree_node_t *) a;
  ndpi_default_ports_tree_node_t *fb = (ndpi_default_ports_tree_node_t *) b;

  //printf("[NDPI] %s(%d, %d)\n", __FUNCTION__, fa->default_port, fb->default_port);

  return((fa->default_port == fb->default_port) ? 0 : ((fa->default_port < fb->default_port) ? -1 : 1));
}

static ndpi_default_ports_tree_node_t *ndpi_get_guessed_protocol_id(struct ndpi_detection_module_struct *ndpi_str,
                                                                    u_int8_t proto, u_int16_t sport, u_int16_t dport) {
  ndpi_default_ports_tree_node_t node;

  if(sport && dport) {
    const void *ret;

    node.default_port = dport; /* Check server port first */
    ret = ndpi_tfind(&node, (proto == IPPROTO_TCP) ? (void *) &ndpi_str->tcpRoot : (void *) &ndpi_str->udpRoot,
		     ndpi_default_ports_tree_node_t_cmp);

    if(ret == NULL) {
      node.default_port = sport;
      ret = ndpi_tfind(&node, (proto == IPPROTO_TCP) ? (void *) &ndpi_str->tcpRoot : (void *) &ndpi_str->udpRoot,
		       ndpi_default_ports_tree_node_t_cmp);
    }

    if(ret)
      return(*(ndpi_default_ports_tree_node_t **) ret);
  }

  return(NULL);
}

struct payload_stats *pstats = NULL;
u_int32_t max_packet_payload_dissection = 128;

#define VLAN 0x8100
#define MPLS_UNI 0x8847
#define MPLS_MULTI 0x8848
#define PPPoE 0x8864
#define SNAP 0xaa
#define BSTP 0x42 /* Bridge Spanning Tree Protocol */
#define ETTA_MIN_OCTETS 4000

#define BSTP                   0x42     /* Bridge Spanning Tree Protocol */
#define LINKTYPE_LINUX_SLL2 276

/* Keep last 32 packets */
#define DATA_ANALUYSIS_SLIDING_WINDOW    32
#define NUM_PARAMETERS_BD_LOGREG 464
#define MC_BINS_LEN 10
#define MC_BINS_TIME 10
#define MC_BIN_SIZE_TIME 50
#define MC_BIN_SIZE_LEN 150
#define MAX_BIN_LEN 1500
#define NUM_BD_VALUES 256
#define NDPI_TIMESTAMP_LEN       64
#define NUM_PARAMETERS_SPLT_LOGREG 208

/* mask for FCF */
#define	WIFI_DATA                        0x2    /* 0000 0010 */
#define FCF_TYPE(fc)     (((fc) >> 2) & 0x3)    /* 0000 0011 = 0x3 */
#define FCF_SUBTYPE(fc)  (((fc) >> 4) & 0xF)    /* 0000 1111 = 0xF */
#define FCF_TO_DS(fc)        ((fc) & 0x0100)
#define FCF_FROM_DS(fc)      ((fc) & 0x0200)

/* mask for Bad FCF presence */
#define BAD_FCS                         0x50    /* 0101 0000 */

#define GTP_U_V1_PORT                  2152
#define NDPI_CAPWAP_DATA_PORT          5247
#define TZSP_PORT                      37008

#ifndef DLT_LINUX_SLL
#define DLT_LINUX_SLL  113
#endif

#define XGRAMS_C 26
static int ndpi_xgrams_inited = 0;
static unsigned int bigrams_bitmap[(XGRAMS_C*XGRAMS_C+31)/32];
static unsigned int imposible_bigrams_bitmap[(XGRAMS_C*XGRAMS_C+31)/32];
static unsigned int trigrams_bitmap[(XGRAMS_C*XGRAMS_C*XGRAMS_C+31)/32];
u_int ndpi_verbose_dga_detection = 0;

static u_int32_t flow_id = 0;
u_int32_t max_num_packets_per_flow      = 10; /* ETTA requires min 10 pkts for record. */
ndpi_custom_dga_predict_fctn ndpi_dga_function = NULL;

u_int8_t enable_protocol_guess = 0, enable_payload_analyzer = 0, num_bin_clusters = 0, extcap_exit = 0;
u_int8_t human_readeable_string_len = 5;
u_int8_t max_num_udp_dissected_pkts = 24, max_num_tcp_dissected_pkts = 80;
int malloc_size_stats = 0;
u_int16_t min_pattern_len = 4;

u_int16_t max_pattern_len = 8;
u_int8_t enable_doh_dot_detection = 0;

static const u_int8_t ndpi_domain_level_automat[4][4]= {
  /* symbol,'.','-',inc */
  { 2,1,2,0 }, // start state
  { 2,0,0,0 }, // first char is '.'; disable .. or .-
  { 2,3,2,0 }, // part of domain name
  { 2,0,0,1 }  // next level domain name; disable .. or .-
};

/* nDPI structs */
struct ndpi_detection_module_struct *module;
struct ndpi_workflow *workflow;
uint32_t current_ndpi_memory = 0, max_ndpi_memory = 0;
static u_int8_t quiet_mode = 0;
static u_int16_t decode_tunnels = 0;
static FILE *results_file = NULL;
static struct timeval begin, end;
u_int8_t verbose = 0, enable_flow_stats = 0;

static uint32_t destination = (uint16_t)-1;

/* pcap stucts */
const uint16_t MAX_SNAPLEN = (uint16_t)-1;

static void *(*_ndpi_flow_malloc)(size_t size);
static void (*_ndpi_flow_free)(void *ptr);

static void *(*_ndpi_malloc)(size_t size);
static void (*_ndpi_free)(void *ptr);

static volatile long int ndpi_tot_allocated_memory;

static ndpi_risk_info ndpi_known_risks[] = {
  { NDPI_NO_RISK,                               NDPI_RISK_LOW,    CLIENT_FAIR_RISK_PERCENTAGE, NDPI_NO_ACCOUNTABILITY  },
  { NDPI_URL_POSSIBLE_XSS,                      NDPI_RISK_SEVERE, CLIENT_HIGH_RISK_PERCENTAGE, NDPI_CLIENT_ACCOUNTABLE },
  { NDPI_URL_POSSIBLE_SQL_INJECTION,            NDPI_RISK_SEVERE, CLIENT_HIGH_RISK_PERCENTAGE, NDPI_CLIENT_ACCOUNTABLE },
  { NDPI_URL_POSSIBLE_RCE_INJECTION,            NDPI_RISK_SEVERE, CLIENT_HIGH_RISK_PERCENTAGE, NDPI_CLIENT_ACCOUNTABLE },
  { NDPI_BINARY_APPLICATION_TRANSFER,           NDPI_RISK_SEVERE, CLIENT_FAIR_RISK_PERCENTAGE, NDPI_CLIENT_ACCOUNTABLE },
  { NDPI_KNOWN_PROTOCOL_ON_NON_STANDARD_PORT,   NDPI_RISK_MEDIUM, CLIENT_FAIR_RISK_PERCENTAGE, NDPI_SERVER_ACCOUNTABLE },
  { NDPI_TLS_SELFSIGNED_CERTIFICATE,            NDPI_RISK_HIGH,   CLIENT_HIGH_RISK_PERCENTAGE, NDPI_SERVER_ACCOUNTABLE },
  { NDPI_TLS_OBSOLETE_VERSION,                  NDPI_RISK_HIGH,   CLIENT_HIGH_RISK_PERCENTAGE, NDPI_CLIENT_ACCOUNTABLE },
  { NDPI_TLS_WEAK_CIPHER,                       NDPI_RISK_HIGH,   CLIENT_HIGH_RISK_PERCENTAGE, NDPI_CLIENT_ACCOUNTABLE },
  { NDPI_TLS_CERTIFICATE_EXPIRED,               NDPI_RISK_HIGH,   CLIENT_LOW_RISK_PERCENTAGE,  NDPI_SERVER_ACCOUNTABLE },
  { NDPI_TLS_CERTIFICATE_MISMATCH,              NDPI_RISK_HIGH,   CLIENT_FAIR_RISK_PERCENTAGE, NDPI_SERVER_ACCOUNTABLE },
  { NDPI_HTTP_SUSPICIOUS_USER_AGENT,            NDPI_RISK_HIGH,   CLIENT_HIGH_RISK_PERCENTAGE, NDPI_CLIENT_ACCOUNTABLE },
  { NDPI_HTTP_NUMERIC_IP_HOST,                  NDPI_RISK_LOW,    CLIENT_FAIR_RISK_PERCENTAGE, NDPI_CLIENT_ACCOUNTABLE },
  { NDPI_HTTP_SUSPICIOUS_URL,                   NDPI_RISK_HIGH,   CLIENT_HIGH_RISK_PERCENTAGE, NDPI_CLIENT_ACCOUNTABLE },
  { NDPI_HTTP_SUSPICIOUS_HEADER,                NDPI_RISK_HIGH,   CLIENT_HIGH_RISK_PERCENTAGE, NDPI_CLIENT_ACCOUNTABLE },
  { NDPI_TLS_NOT_CARRYING_HTTPS,                NDPI_RISK_LOW,    CLIENT_FAIR_RISK_PERCENTAGE, NDPI_CLIENT_ACCOUNTABLE },
  { NDPI_SUSPICIOUS_DGA_DOMAIN,                 NDPI_RISK_HIGH,   CLIENT_HIGH_RISK_PERCENTAGE, NDPI_CLIENT_ACCOUNTABLE },
  { NDPI_MALFORMED_PACKET,                      NDPI_RISK_LOW,    CLIENT_FAIR_RISK_PERCENTAGE, NDPI_CLIENT_ACCOUNTABLE },
  { NDPI_SSH_OBSOLETE_CLIENT_VERSION_OR_CIPHER, NDPI_RISK_HIGH,   CLIENT_HIGH_RISK_PERCENTAGE, NDPI_CLIENT_ACCOUNTABLE },
  { NDPI_SSH_OBSOLETE_SERVER_VERSION_OR_CIPHER, NDPI_RISK_MEDIUM, CLIENT_LOW_RISK_PERCENTAGE,  NDPI_SERVER_ACCOUNTABLE },
  { NDPI_SMB_INSECURE_VERSION,                  NDPI_RISK_HIGH,   CLIENT_HIGH_RISK_PERCENTAGE, NDPI_CLIENT_ACCOUNTABLE },
  { NDPI_TLS_SUSPICIOUS_ESNI_USAGE,             NDPI_RISK_MEDIUM, CLIENT_FAIR_RISK_PERCENTAGE, NDPI_CLIENT_ACCOUNTABLE },
  { NDPI_UNSAFE_PROTOCOL,                       NDPI_RISK_LOW,    CLIENT_FAIR_RISK_PERCENTAGE, NDPI_BOTH_ACCOUNTABLE   },
  { NDPI_DNS_SUSPICIOUS_TRAFFIC,                NDPI_RISK_HIGH,   CLIENT_HIGH_RISK_PERCENTAGE, NDPI_CLIENT_ACCOUNTABLE },
  { NDPI_TLS_MISSING_SNI,                       NDPI_RISK_MEDIUM, CLIENT_FAIR_RISK_PERCENTAGE, NDPI_CLIENT_ACCOUNTABLE },
  { NDPI_HTTP_SUSPICIOUS_CONTENT,               NDPI_RISK_HIGH,   CLIENT_HIGH_RISK_PERCENTAGE, NDPI_SERVER_ACCOUNTABLE },
  { NDPI_RISKY_ASN,                             NDPI_RISK_MEDIUM, CLIENT_FAIR_RISK_PERCENTAGE, NDPI_SERVER_ACCOUNTABLE },
  { NDPI_RISKY_DOMAIN,                          NDPI_RISK_MEDIUM, CLIENT_FAIR_RISK_PERCENTAGE, NDPI_SERVER_ACCOUNTABLE },
  { NDPI_MALICIOUS_JA3,                         NDPI_RISK_MEDIUM, CLIENT_FAIR_RISK_PERCENTAGE, NDPI_CLIENT_ACCOUNTABLE },
  { NDPI_MALICIOUS_SHA1_CERTIFICATE,            NDPI_RISK_MEDIUM, CLIENT_FAIR_RISK_PERCENTAGE, NDPI_SERVER_ACCOUNTABLE },
  { NDPI_DESKTOP_OR_FILE_SHARING_SESSION,       NDPI_RISK_LOW,    CLIENT_FAIR_RISK_PERCENTAGE, NDPI_BOTH_ACCOUNTABLE   },
  { NDPI_TLS_UNCOMMON_ALPN,                     NDPI_RISK_MEDIUM, CLIENT_FAIR_RISK_PERCENTAGE, NDPI_CLIENT_ACCOUNTABLE },
  { NDPI_TLS_CERT_VALIDITY_TOO_LONG,            NDPI_RISK_MEDIUM, CLIENT_FAIR_RISK_PERCENTAGE, NDPI_SERVER_ACCOUNTABLE },
  { NDPI_TLS_SUSPICIOUS_EXTENSION,              NDPI_RISK_HIGH,   CLIENT_HIGH_RISK_PERCENTAGE, NDPI_BOTH_ACCOUNTABLE   },
  { NDPI_TLS_FATAL_ALERT,                       NDPI_RISK_LOW,    CLIENT_FAIR_RISK_PERCENTAGE, NDPI_BOTH_ACCOUNTABLE   },
  { NDPI_SUSPICIOUS_ENTROPY,                    NDPI_RISK_MEDIUM, CLIENT_FAIR_RISK_PERCENTAGE, NDPI_BOTH_ACCOUNTABLE   },
  { NDPI_CLEAR_TEXT_CREDENTIALS,                NDPI_RISK_HIGH,   CLIENT_HIGH_RISK_PERCENTAGE, NDPI_CLIENT_ACCOUNTABLE },
  { NDPI_DNS_LARGE_PACKET,                      NDPI_RISK_MEDIUM, CLIENT_FAIR_RISK_PERCENTAGE, NDPI_CLIENT_ACCOUNTABLE },
  { NDPI_DNS_FRAGMENTED,                        NDPI_RISK_MEDIUM, CLIENT_FAIR_RISK_PERCENTAGE, NDPI_CLIENT_ACCOUNTABLE },
  { NDPI_INVALID_CHARACTERS,                    NDPI_RISK_HIGH,   CLIENT_HIGH_RISK_PERCENTAGE, NDPI_CLIENT_ACCOUNTABLE },
  { NDPI_POSSIBLE_EXPLOIT,                      NDPI_RISK_SEVERE, CLIENT_HIGH_RISK_PERCENTAGE, NDPI_CLIENT_ACCOUNTABLE },
  { NDPI_TLS_CERTIFICATE_ABOUT_TO_EXPIRE,       NDPI_RISK_MEDIUM, CLIENT_LOW_RISK_PERCENTAGE,  NDPI_SERVER_ACCOUNTABLE },
  { NDPI_PUNYCODE_IDN,                          NDPI_RISK_LOW,    CLIENT_LOW_RISK_PERCENTAGE,  NDPI_CLIENT_ACCOUNTABLE },
  { NDPI_ERROR_CODE_DETECTED,                   NDPI_RISK_LOW,    CLIENT_LOW_RISK_PERCENTAGE,  NDPI_BOTH_ACCOUNTABLE   },
  { NDPI_HTTP_CRAWLER_BOT,                      NDPI_RISK_LOW,    CLIENT_LOW_RISK_PERCENTAGE,  NDPI_CLIENT_ACCOUNTABLE },
  { NDPI_ANONYMOUS_SUBSCRIBER,                  NDPI_RISK_MEDIUM, CLIENT_FAIR_RISK_PERCENTAGE, NDPI_CLIENT_ACCOUNTABLE },
  { NDPI_UNIDIRECTIONAL_TRAFFIC,                NDPI_RISK_LOW,    CLIENT_FAIR_RISK_PERCENTAGE, NDPI_CLIENT_ACCOUNTABLE },
  { NDPI_HTTP_OBSOLETE_SERVER,                  NDPI_RISK_MEDIUM, CLIENT_LOW_RISK_PERCENTAGE,  NDPI_SERVER_ACCOUNTABLE },
  { NDPI_PERIODIC_FLOW,                         NDPI_RISK_LOW,    CLIENT_LOW_RISK_PERCENTAGE,  NDPI_CLIENT_ACCOUNTABLE },
  { NDPI_MINOR_ISSUES,                          NDPI_RISK_LOW,    CLIENT_LOW_RISK_PERCENTAGE,  NDPI_BOTH_ACCOUNTABLE   },
  { NDPI_TCP_ISSUES,                            NDPI_RISK_MEDIUM, CLIENT_FAIR_RISK_PERCENTAGE, NDPI_CLIENT_ACCOUNTABLE },

  /* Leave this as last member */
  { NDPI_MAX_RISK,                              NDPI_RISK_LOW,    CLIENT_FAIR_RISK_PERCENTAGE, NDPI_NO_ACCOUNTABILITY   }
};

float ndpi_parameters_splt[NUM_PARAMETERS_SPLT_LOGREG] = {
							  -2.088057846500587456e+00, 7.763936238952200239e-05, 4.404309737393306595e-05, -9.467385027293546973e-02,
							  4.348947142638090457e-01, -2.091409170053043390e-04, -5.788902107267982974e-04, 4.481443450852441001e-10,
							  -3.136135459023654537e+00, -1.507730262127600751e+00, -1.204663669965535977e+00, -1.171839254318371104e+00,
							  4.329302247232582057e-01, 8.310653628092458334e+00, 3.299246725156660176e+00, 0.000000000000000000e+00,
							  1.847454931582027254e-02, -1.498024139966201096e+00, -7.660670007653060942e-01, -2.908130300830076731e+00,
							  -1.252564844610269734e+00, -1.910955328742287573e+00, 9.471710980110392697e-01, 2.352302758516665371e+00,
							  2.982269972214651954e+00, 4.280736383314343918e+00, 4.633629909719495288e+00, -2.198052637823726840e+00,
							  -1.150759637168392580e+00, 3.420433363184381292e+00, 1.857878113059351077e-02, -1.559806674919653746e+00,
							  4.197498183183401288e+00, 6.262186949633183453e+00, 1.100694844370524095e+01, 2.778688785515088000e+01,
							  3.679948298336883195e+00, -2.432801394376875592e+00, 5.133442052706843617e-01, 2.181172654073517680e+00,
							  -8.577551729671881731e-01, 7.013844214023315926e-01, 3.138233436228588857e+00, 7.319940508466630247e-01,
							  0.000000000000000000e+00, 3.529209394581482861e+00, 1.464585117707144413e+01, 8.506550226820598359e-01,
							  -9.060397326548508268e-01, 6.787474954688997641e+00, 8.125411068867387954e+00, 4.515740684104064151e+00,
							  5.372135582950940069e+00, 9.210951196799497254e-01, 4.802177410869620466e+00, 2.945445016176073594e+01,
							  1.575032253128311632e+00, -1.355276854364796946e-01, -3.322474764169629502e-01, 3.018397817188666732e+00,
							  1.186503569922195744e+00, 0.000000000000000000e+00, 8.883242370198487503e-01, 7.248276146728496627e+00,
							  0.000000000000000000e+00, 0.000000000000000000e+00, -4.831246718433664711e+00, 6.124136970173365002e-01,
							  4.145693892559814686e-01, 2.683998941637626867e+00, 2.063906603639539039e+00, 2.989801217386735210e+00,
							  2.262965767379551962e-01, 2.240332214649647380e+00, 5.984550782416063086e+00, 4.587011255338186544e+00,
							  1.233118485315272039e+01, 1.115223490909697857e+00, -3.682686422016995476e+00, 6.096498453291562258e-01,
							  1.119275528656461516e+00, 1.377886278915177731e-01, 3.828176805973048324e+00, 0.000000000000000000e+00,
							  0.000000000000000000e+00, 1.442927634029647344e+01, 0.000000000000000000e+00, 5.719118583309401593e-01,
							  1.993632609731877392e-01, 3.047472271520709430e+00, 5.736784864911910198e+00, 6.677826247219391220e+00,
							  6.307175478564531090e+00, 3.150295169417364249e+01, 3.738597740702392258e+00, 1.129754590514236234e+01,
							  6.108506268573830056e+00, 1.605489516792866667e+00, 2.929631990348545489e+00, -2.832543082245212937e-02,
							  1.358286530670594461e+00, 1.655932469853677924e+00, 6.701964773769768513e-01, 2.131182050917533211e+00,
							  2.998351165769753468e+00, 7.772095996358327596e+00, 1.285014785269981141e+00, 4.407334784589962418e+00,
							  1.719858214230612026e+00, -1.012765674651314063e+00, -5.749271123172469133e-01, -3.559614093795681278e+00,
							  -3.073088477387719397e+00, -4.492469521371540431e+00, -3.753286990415885427e+00, -3.219255423324282273e+00,
							  -2.806436518181075090e+00, -2.697305948568419875e+00, -7.879608430851776646e-01, 4.625507221739111330e+00,
							  4.809280703883450414e+00, -3.435194026629848629e+00, -3.218943068168937049e+00, 3.335535704890596698e+00,
							  2.071359212435486263e+00, 4.538992059175040339e+00, -2.770772323566738038e+01, 2.903047708571506735e+00,
							  -4.436143805989154032e+00, -2.647991280011542381e-01, 1.737252348126810064e+00, -4.121989655995259128e+00,
							  3.209709099445720581e-01, 1.012758514896711759e+01, 3.313255624721038295e+00, 4.631467619785444967e+00,
							  7.668642402146534032e+00, 6.780938812710099128e+00, -3.256164342602652972e+00, 6.749565128319576779e-01,
							  0.000000000000000000e+00, -4.407265954524525853e+00, 0.000000000000000000e+00, -3.666522115024547901e+01,
							  -7.886029397826226273e+01, 0.000000000000000000e+00, 0.000000000000000000e+00, -2.261283814517791058e+01,
							  -4.024317426178160240e+00, 3.213063737030031342e-01, 5.079805145796887800e+00, 1.326813226475260343e+00,
							  1.233684078112145643e+00, 8.671852503871454232e+00, -2.041800256066371944e+00, 0.000000000000000000e+00,
							  0.000000000000000000e+00, -1.607347800380474823e+01, -4.430790279223246309e+00, 1.177552465851384511e+00,
							  6.342921220500139512e+00, -2.466913734548706327e-02, 3.451642566010713065e-01, -6.012767168531006234e+00,
							  7.328146570137336724e+00, 7.500088131707050465e+00, 0.000000000000000000e+00, -3.547913249211809017e+01,
							  -3.130964814607208879e+00, 8.247326544297072237e-01, 3.757262485775580418e-01, -2.136528302027558723e+00,
							  -2.631627236037529793e-01, -2.016718799388414141e+01, 0.000000000000000000e+00, 0.000000000000000000e+00,
							  0.000000000000000000e+00, -7.708602132869285528e-01, -2.602868328868111814e+00, 1.435184800833797958e+00,
							  0.000000000000000000e+00, -2.080420864280113413e+00, 1.169498351211070819e+00, -1.798334115637199560e+01,
							  -1.193885252696202670e+01, 0.000000000000000000e+00, 0.000000000000000000e+00, 4.304089297965300709e+00,
							  -3.020893216686394656e+00, -1.234427481614708721e+00, 0.000000000000000000e+00, 1.853340741926325697e+00,
							  -2.686000064995862147e+01, -1.672275139058893600e+01, -2.826268691607605987e+01, 0.000000000000000000e+00,
							  0.000000000000000000e+00, -1.547397429377200817e+00, -4.018181657009961327e+00, -7.289186736637049968e+00,
							  -7.458655219230571731e+00, -9.625538282761622710e+00, -1.103039457077456298e+01, -6.262675161142102809e+01,
							  -9.265912629799268885e+00, -8.961543476816615339e+00, -9.622764435629340696e+00, -1.097978292092879826e+01,
};

float ndpi_parameters_bd[NUM_PARAMETERS_BD_LOGREG] = {
						      -1.678134053325450292e+00, 1.048946534609769413e-04, 9.608725756967682636e-05, -7.515489355100658797e-02,
						      2.089554874872663892e-01, -1.012058874142656513e-04, -2.917652723373885169e-04, 1.087540461196068741e-10,
						      -2.594688448425090055e+00, -2.071803573048482061e+00, -1.399303273236228939e+00, -2.089300736641718004e+00,
						      -8.842347826063630123e-01, 6.476433717022786141e+00, 3.114501282249810377e+00, -2.239127990932460399e+00,
						      -4.667574389646080291e-01, -2.200651610813817438e+00, -1.674926704401964894e+00, -3.894420410398949706e+00,
						      -1.232376502509682004e+00, -2.231027070413975189e+00, 7.691948448668822769e-01, 3.222335181407633531e+00,
						      1.430983188964249919e+00, 2.144317250116257956e+00, 6.596745231472220361e+00, -2.464580889153460852e+00,
						      -1.923337901965658681e+00, 2.910328594745831943e+00, -3.123244869063500073e-01, -1.683345539896562659e+00,
						      3.785795988845424898e+00, 5.235473328290667361e+00, 8.512526402199654285e+00, 1.393475907195251473e+01,
						      1.673386027437856916e+00, -2.910729265724139925e+00, 2.969886703676111184e-01, 1.700051266957717466e+00,
						      -5.472121114836264733e-01, 1.716354591332415469e-01, 3.177884264837486317e+00, 0.000000000000000000e+00,
						      0.000000000000000000e+00, 1.924354871334499062e-01, 6.568439271753665487e+00, 2.102316342451608644e-01,
						      -1.132124603237853355e+00, 7.329625148148498859e+00, 6.606460464951361189e+00, 2.844223241371105271e+00,
						      3.078771172794853683e+00, 0.000000000000000000e+00, 2.656884613648917703e+00, 1.779697712165259205e+01,
						      0.000000000000000000e+00, -3.457017935109325535e-01, 2.157595478838472414e-01, 3.829196175023549031e+00,
						      0.000000000000000000e+00, 1.650776974765602867e-01, 1.357223085191380796e-02, 3.946357663253555081e+00,
						      0.000000000000000000e+00, 0.000000000000000000e+00, -2.155616432815957495e+00, 8.213633570666911687e-01,
						      1.125480801049912050e-01, 2.684005418659722420e+00, 5.769541257304295900e-01, 1.060883870466023948e+00,
						      0.000000000000000000e+00, 0.000000000000000000e+00, 3.413708974045502664e+00, 2.275281553961784553e+00,
						      5.176725998383044924e+00, 1.019445219242678835e+00, -1.848344450190015698e+00, 0.000000000000000000e+00,
						      0.000000000000000000e+00, 0.000000000000000000e+00, 1.491820649409327126e+00, 0.000000000000000000e+00,
						      0.000000000000000000e+00, 9.379741891282449728e+00, 0.000000000000000000e+00, 5.444605374840002510e-01,
						      -9.654403640632221173e-02, 2.642171746731144744e+00, 4.626416118226488905e+00, 3.654642208477139498e+00,
						      3.427412899258296619e+00, 1.490784083593987397e+01, 2.322393214516801141e+00, 6.511453713852694669e+00,
						      6.949721651828602020e+00, 1.186838154505042375e+00, 2.072129970488261197e+00, 0.000000000000000000e+00,
						      1.598928631178261561e+00, 5.926083912988970859e-01, -1.612886287403501873e-01, 9.452951868724716045e-01,
						      2.145707914290207352e+00, 5.391610489831286657e+00, 8.454389313314318866e-01, 2.372736567215404602e+00,
						      -3.130110237826235764e-01, -2.994989290166069740e+00, -2.571950567149417832e+00, -5.018016256298333921e+00,
						      -4.851489154898488643e+00, -7.101788768628541249e+00, -5.227281714666618839e+00, -6.351346048086286444e+00,
						      -4.558191218464671124e+00, -5.293990544168526213e+00, -2.920034449434862345e-01, 5.166915658100844411e+00,
						      4.642130303354632836e+00, -5.246106907306949951e-01, -3.120281208300208498e+00, 1.544764033379846691e+00,
						      0.000000000000000000e+00, 3.721469736246234561e+00, -1.083434721745241625e+01, 2.901590918368040395e+00,
						      -3.602037909234679258e+00, 0.000000000000000000e+00, 2.736307835089097917e+00, -5.037400262764839987e+00,
						      -1.163050013241316849e+00, 6.565863507998260573e+00, 1.872406036485896097e+00, 2.249439295570562880e+00,
						      3.276076277814265136e+00, 5.747730113795930684e+00, -2.084335807954610154e+00, 1.812930768433161921e+00,
						      0.000000000000000000e+00, -4.068875727535363751e+00, -4.509432609364653205e-02, -1.424182063303933710e+01,
						      -1.743400430675688639e+01, 0.000000000000000000e+00, 0.000000000000000000e+00, -8.986019040369217947e+00,
						      -2.005955598483518898e+00, 1.514163405869717538e+00, 4.060752357984299010e+00, 1.405971170124569403e+00,
						      1.383171915541985708e+00, 4.654452090729912506e+00, -3.395023560174311950e+00, 0.000000000000000000e+00,
						      0.000000000000000000e+00, -8.562968788250293173e+00, -1.939561462845156514e+00, 2.627499899415196793e+00,
						      4.949794698120698833e+00, 4.355655772643094448e-01, 0.000000000000000000e+00, -1.055190553626396577e+00,
						      4.757318838337171840e+00, 3.966536148163406938e+00, 0.000000000000000000e+00, -1.190662117721104352e+01,
						      -1.673945042186458121e+00, 0.000000000000000000e+00, -1.203943763219820356e-02, -1.411827841131889194e+00,
						      -7.623501643009024109e-01, -6.774873775798392117e+00, 0.000000000000000000e+00, 0.000000000000000000e+00,
						      0.000000000000000000e+00, 0.000000000000000000e+00, -1.755294779557688090e+00, 1.542887322103192238e+00,
						      0.000000000000000000e+00, -8.228978371972577310e-01, 0.000000000000000000e+00, -5.379142925264499553e+00,
						      -1.144060263986041326e+00, 0.000000000000000000e+00, 0.000000000000000000e+00, 4.731108583634047626e+00,
						      -1.569393147397664556e+00, -3.449886418134247568e-01, 0.000000000000000000e+00, 1.658412661295906920e+00,
						      -5.077151059809188460e+00, -7.326467579034271260e+00, -1.190177296658179840e+00, 0.000000000000000000e+00,
						      0.000000000000000000e+00, 0.000000000000000000e+00, -1.914781807241187739e+00, -5.438446604150855457e+00,
						      -5.988893208768400811e+00, -7.886849112491050029e+00, -9.355574940159534947e+00, -1.682361325340106006e+01,
						      -7.609538696398503888e+00, -7.363350786768400269e+00, -7.366039984795356155e+00, -7.051111570136543882e+00,
						      2.337391373249395610e+00, -4.374845402801011574e+01, -3.610863365629191080e+00, 7.684297617701028571e+01,
						      2.162851395732025139e+01, 1.066280518306870562e+01, 8.109257308306457901e+01, 5.149561395669890906e+00,
						      0.000000000000000000e+00, 3.219993054481156136e+00, 0.000000000000000000e+00, 2.093519725422254396e+01,
						      -5.225298528278367272e+00, 0.000000000000000000e+00, 2.159597932230871820e+00, -5.205637201784965384e+01,
						      1.601979388461561982e+01, 6.945290207097973401e+00, 8.036724740759808583e-01, 4.712266457087280536e+00,
						      2.146353485778652370e+01, 3.470089369007970248e+01, 9.468591086256607170e+00, 9.760488656497257054e-01,
						      0.000000000000000000e+00, 0.000000000000000000e+00, 0.000000000000000000e+00, 9.008837970422939323e-01,
						      0.000000000000000000e+00, 1.462843531299845168e+01, 0.000000000000000000e+00, 0.000000000000000000e+00,
						      -1.179406942091425847e+01, 0.000000000000000000e+00, 1.642473653464513816e+01, 1.387228776263151175e+01,
						      0.000000000000000000e+00, 1.613129141280310108e+01, 0.000000000000000000e+00, -1.077318890268341045e+00,
						      4.189407459072477802e-01, 0.000000000000000000e+00, -1.570052145651456899e+00, 0.000000000000000000e+00,
						      1.120834605828141939e+01, 4.286417457736029490e+01, 0.000000000000000000e+00, 2.938378293327098945e+01,
						      1.194087082487160956e+01, 0.000000000000000000e+00, -9.951431855637998813e-02, 3.844291513997798448e-01,
						      2.362333099868798669e+01, -1.002532136112976957e+01, 2.427817537309562823e+01, 0.000000000000000000e+00,
						      1.076329692188489773e+01, 1.760895870067486157e+00, 2.080295785135324849e+01, -4.335217053626006134e+01,
						      -6.272369476984676062e-01, 5.165768790797590881e+00, -4.507215926635629311e-01, 0.000000000000000000e+00,
						      -4.242472062530233679e+00, -4.931831554080153168e+00, -2.806203935735193777e+00, -2.670377941558885126e+01,
						      0.000000000000000000e+00, -2.124688439238133242e+01, 0.000000000000000000e+00, 0.000000000000000000e+00,
						      2.452415244698852970e+00, -1.173727222080745092e+00, 0.000000000000000000e+00, 0.000000000000000000e+00,
						      -1.458125295680756039e+01, -1.757703406512062827e+01, 0.000000000000000000e+00, 3.943626521423988951e+00,
						      0.000000000000000000e+00, -4.006095410470026152e+00, 1.727171067402430538e+01, -3.412620901789366457e+01,
						      0.000000000000000000e+00, 1.760073934312834254e+01, 3.266082201875645552e+01, 0.000000000000000000e+00,
						      0.000000000000000000e+00, 0.000000000000000000e+00, 1.514535424913179362e+01, 0.000000000000000000e+00,
						      0.000000000000000000e+00, -3.100487758075622935e-01, 0.000000000000000000e+00, 2.387863228159451978e+01,
						      1.237098847411416891e+01, 1.154430573879687560e-02, 7.976366278729441817e+00, 0.000000000000000000e+00,
						      -6.296727640787388447e-01, 1.406230674131906255e+01, 1.430275589872723430e+01, -2.231764570537816184e+00,
						      0.000000000000000000e+00, 5.003869692542436631e+00, 0.000000000000000000e+00, -5.482127427587509594e+00,
						      -8.830547931126154992e+00, -5.376776036224484301e+01, -2.918517871695104304e+01, -1.009022417771788049e+01,
						      -4.811775051355994037e+00, -1.188016976215758547e+01, -2.055483647266791536e+01, -2.482333959706277327e+01,
						      -1.048392515070836950e+01, -3.837352144714887459e+01, 0.000000000000000000e+00, -9.298440675063780247e+00,
						      0.000000000000000000e+00, 3.584086297861655890e+00, 0.000000000000000000e+00, 0.000000000000000000e+00,
						      0.000000000000000000e+00, 0.000000000000000000e+00, 0.000000000000000000e+00, 1.184271790014085113e+00,
						      1.594266439891793219e+01, 0.000000000000000000e+00, 8.473235161049382569e+00, 0.000000000000000000e+00,
						      0.000000000000000000e+00, 0.000000000000000000e+00, 6.748879951595517568e+00, 0.000000000000000000e+00,
						      0.000000000000000000e+00, -1.057534737660506430e+01, 0.000000000000000000e+00, 0.000000000000000000e+00,
						      0.000000000000000000e+00, -3.179879192807419841e+01, 0.000000000000000000e+00, 5.000324879565139824e+00,
						      0.000000000000000000e+00, 1.229183419446936654e+00, 0.000000000000000000e+00, 0.000000000000000000e+00,
						      0.000000000000000000e+00, 0.000000000000000000e+00, 0.000000000000000000e+00, 0.000000000000000000e+00,
						      0.000000000000000000e+00, 0.000000000000000000e+00, 0.000000000000000000e+00, 0.000000000000000000e+00,
						      0.000000000000000000e+00, 0.000000000000000000e+00, 0.000000000000000000e+00, 0.000000000000000000e+00,
						      4.127983063177185663e+00, 6.616705680943091750e+00, 5.848245769217652601e+00, -1.818944631334333550e+01,
						      0.000000000000000000e+00, 0.000000000000000000e+00, 0.000000000000000000e+00, 0.000000000000000000e+00,
						      0.000000000000000000e+00, 0.000000000000000000e+00, 0.000000000000000000e+00, 0.000000000000000000e+00,
						      2.694838778746875274e+00, 0.000000000000000000e+00, 1.463145767737777625e+01, -4.924734438569850603e+00,
						      0.000000000000000000e+00, 1.877377621310543088e+00, 0.000000000000000000e+00, 0.000000000000000000e+00,
						      1.971941442729244764e+00, 0.000000000000000000e+00, 0.000000000000000000e+00, 0.000000000000000000e+00,
						      0.000000000000000000e+00, 0.000000000000000000e+00, 0.000000000000000000e+00, 0.000000000000000000e+00,
						      0.000000000000000000e+00, 0.000000000000000000e+00, 1.732809836566829187e+00, 2.700285877421266534e+01,
						      2.915978562591383216e+00, 0.000000000000000000e+00, 0.000000000000000000e+00, -6.999629705176019456e+00,
						      0.000000000000000000e+00, 0.000000000000000000e+00, 0.000000000000000000e+00, 1.089611710258455268e+01,
						      0.000000000000000000e+00, 0.000000000000000000e+00, 0.000000000000000000e+00, 0.000000000000000000e+00,
						      2.121018958070171934e+00, 0.000000000000000000e+00, 0.000000000000000000e+00, 0.000000000000000000e+00,
						      -7.416250358067024706e+00, -1.263327458973565065e+01, 0.000000000000000000e+00, 0.000000000000000000e+00,
						      0.000000000000000000e+00, 0.000000000000000000e+00, 0.000000000000000000e+00, 2.241612733384156897e+01,
						      0.000000000000000000e+00, 8.607688079645482659e+00, 0.000000000000000000e+00, 0.000000000000000000e+00,
						      0.000000000000000000e+00, 0.000000000000000000e+00, 1.750217629228628269e+01, 0.000000000000000000e+00,
						      0.000000000000000000e+00, 0.000000000000000000e+00, -1.957769005108392690e+01, 0.000000000000000000e+00,
						      0.000000000000000000e+00, 0.000000000000000000e+00, 0.000000000000000000e+00, 0.000000000000000000e+00,
						      0.000000000000000000e+00, -3.242393079195928784e+00, 0.000000000000000000e+00, 0.000000000000000000e+00,
						      0.000000000000000000e+00, 0.000000000000000000e+00, 0.000000000000000000e+00, 0.000000000000000000e+00,
						      0.000000000000000000e+00, 0.000000000000000000e+00, 1.348338590741638932e+01, 0.000000000000000000e+00,
						      -2.000312276678208392e-02, -7.776608146776987640e-01, 0.000000000000000000e+00, 0.000000000000000000e+00,
						      0.000000000000000000e+00, -5.387825733845168941e+00, 0.000000000000000000e+00, 2.153516224136292934e+01,
						      0.000000000000000000e+00, 0.000000000000000000e+00, -9.635140703414636576e+00, 2.603288107669730511e+00,
};

/* ****************************************************** */

/*
  This is a function used to see if we need to
  add a trailer $ in case the string is complete
  or is a string that can be matched in the
  middle of a domain name

  Example:
  microsoft.com    ->     microsoft.com$
  apple.           ->     apple.
*/
static u_int8_t ndpi_is_middle_string_char(char c) {
  switch(c) {
  case '.':
  case '-':
    return(1);
    break;

  default:
    return(0);
  }
}

const char *ndpi_confidence_get_name(ndpi_confidence_t confidence)
{
  switch(confidence) {
  case NDPI_CONFIDENCE_UNKNOWN:
    return "Unknown";
  case NDPI_CONFIDENCE_MATCH_BY_PORT:
    return "Match by port";
  case NDPI_CONFIDENCE_DPI_PARTIAL:
    return "DPI (partial)";
  case NDPI_CONFIDENCE_DPI_PARTIAL_CACHE:
    return "DPI (partial cache)";
  case NDPI_CONFIDENCE_DPI_CACHE:
    return "DPI (cache)";
  case NDPI_CONFIDENCE_DPI:
    return "DPI";
  case NDPI_CONFIDENCE_NBPF:
    return "nBPF";
  default:
    return NULL;
  }
}

/*
  These are UDP protocols that must fit a single packet
  and thus that if have NOT been detected they cannot be guessed
  as they have been excluded
*/
u_int8_t is_udp_not_guessable_protocol(u_int16_t l7_guessed_proto) {
  switch(l7_guessed_proto) {
  case NDPI_PROTOCOL_SNMP:
  case NDPI_PROTOCOL_NETFLOW:
    /* TODO: add more protocols (if any missing) */
    return(1);
  }

  return(0);
}

/*
  NOTE:

  This function is called only by ndpi_detection_giveup() as it checks
  flows that have anomalous conditions such as SYN+RST ACK+RST....
  As these conditions won't happen with nDPI protocol-detected protocols
  it is not necessary to call this function elsewhere
 */
static void ndpi_check_tcp_flags(struct ndpi_detection_module_struct *ndpi_str,
				 struct ndpi_flow_struct *flow) {
#if 0
  printf("[TOTAL] %u / %u [tot: %u]\n", flow->packet_direction_counter[0], flow->packet_direction_counter[1], flow->all_packets_counter);
#endif

  if((flow->l4.tcp.cli2srv_tcp_flags & TH_SYN)
     && (flow->l4.tcp.srv2cli_tcp_flags & TH_RST)
     && (flow->all_packets_counter < 5 /* Ignore connections terminated by RST but that exchanged data (3WH + RST) */)
     )
    ndpi_set_risk(ndpi_str, flow, NDPI_TCP_ISSUES, "Connection refused (server)");
  else if((flow->l4.tcp.cli2srv_tcp_flags & TH_SYN)
	  && (flow->l4.tcp.cli2srv_tcp_flags & TH_RST)
	  && (flow->all_packets_counter < 5 /* Ignore connections terminated by RST but that exchanged data (3WH + RST) */)
     )
    ndpi_set_risk(ndpi_str, flow, NDPI_TCP_ISSUES, "Connection refused (client)");
  else if((flow->l4.tcp.srv2cli_tcp_flags & TH_RST) && (flow->packet_direction_counter[1 /* server -> client */] == 1))
    ndpi_set_risk(ndpi_str, flow, NDPI_TCP_ISSUES, "TCP probing attempt");
}

/* Based on djb2 hash - http://www.cse.yorku.ca/~oz/hash.html */
u_int32_t ndpi_quick_hash(unsigned char *str, u_int str_len) {
  u_int32_t hash = 5381, i;

  for(i=0; i<str_len; i++)
    hash = ((hash << 5) + hash) + str[i]; /* hash * 33 + str[i] */

  return hash;
}


static u_int32_t make_zoom_key(struct ndpi_flow_struct *flow, int server) {
  u_int32_t key;

  if(server) {
    if(flow->is_ipv6)
      key = ndpi_quick_hash(flow->s_address.v6, 16);
    else
      key = flow->s_address.v4;
  } else {
    if(flow->is_ipv6)
      key = ndpi_quick_hash(flow->c_address.v6, 16);
    else
      key = flow->c_address.v4;
  }

  return key;
}

/* ********************************************************************************* */

static u_int8_t ndpi_search_into_zoom_cache(struct ndpi_detection_module_struct *ndpi_struct,
					    struct ndpi_flow_struct *flow, int server) {

  if(ndpi_struct->zoom_cache) {
    u_int16_t cached_proto;
    u_int32_t key;

    key = make_zoom_key(flow, server);
    u_int8_t found = ndpi_lru_find_cache(ndpi_struct->zoom_cache, key, &cached_proto,
					 0 /* Don't remove it as it can be used for other connections */,
					 ndpi_get_current_time(flow));

#ifdef ZOOM_CACHE_DEBUG
    printf("[Zoom] *** [TCP] SEARCHING key %u [found: %u]\n", key, found);
#endif

    return(found);
  }

  return(0);
}

/* LRU cache */
struct ndpi_lru_cache *ndpi_lru_cache_init(u_int32_t num_entries, u_int32_t ttl) {
  struct ndpi_lru_cache *c = (struct ndpi_lru_cache *) ndpi_calloc(1, sizeof(struct ndpi_lru_cache));

  if(!c)
    return(NULL);

  c->ttl = ttl;
  c->entries = (struct ndpi_lru_cache_entry *) ndpi_calloc(num_entries, sizeof(struct ndpi_lru_cache_entry));

  if(!c->entries) {
    ndpi_free(c);
    return(NULL);
  } else
    c->num_entries = num_entries;

  return(c);
}

void ndpi_lru_free_cache(struct ndpi_lru_cache *c) {
  ndpi_free(c->entries);
  ndpi_free(c);
}

u_int8_t ndpi_lru_find_cache(struct ndpi_lru_cache *c, u_int32_t key,
			     u_int16_t *value, u_int8_t clean_key_when_found, u_int32_t now_sec) {
  u_int32_t slot = key % c->num_entries;

  c->stats.n_search++;
  if(c->entries[slot].is_full && c->entries[slot].key == key &&
     now_sec >= c->entries[slot].timestamp &&
     (c->ttl == 0 || now_sec - c->entries[slot].timestamp <= c->ttl)) {
    *value = c->entries[slot].value;
    if(clean_key_when_found)
      c->entries[slot].is_full = 0;
    c->stats.n_found++;
    return(1);
  } else
    return(0);
}

void ndpi_lru_add_to_cache(struct ndpi_lru_cache *c, u_int32_t key, u_int16_t value, u_int32_t now_sec) {
  u_int32_t slot = key % c->num_entries;

  c->stats.n_insert++;
  c->entries[slot].is_full = 1, c->entries[slot].key = key, c->entries[slot].value = value, c->entries[slot].timestamp = now_sec;
}

void ndpi_lru_get_stats(struct ndpi_lru_cache *c, struct ndpi_lru_cache_stats *stats) {
  if(c) {
    stats->n_insert = c->stats.n_insert;
    stats->n_search = c->stats.n_search;
    stats->n_found = c->stats.n_found;
  } else {
    stats->n_insert = 0;
    stats->n_search = 0;
    stats->n_found = 0;
  }
}

int ndpi_get_lru_cache_stats(struct ndpi_detection_module_struct *ndpi_struct,
			     lru_cache_type cache_type,
			     struct ndpi_lru_cache_stats *stats)
{
  if(!ndpi_struct || !stats)
    return -1;

  switch(cache_type) {
  case NDPI_LRUCACHE_OOKLA:
    ndpi_lru_get_stats(ndpi_struct->ookla_cache, stats);
    return 0;
  case NDPI_LRUCACHE_BITTORRENT:
    ndpi_lru_get_stats(ndpi_struct->bittorrent_cache, stats);
    return 0;
  case NDPI_LRUCACHE_ZOOM:
    ndpi_lru_get_stats(ndpi_struct->zoom_cache, stats);
    return 0;
  case NDPI_LRUCACHE_STUN:
    ndpi_lru_get_stats(ndpi_struct->stun_cache, stats);
    return 0;
  case NDPI_LRUCACHE_TLS_CERT:
    ndpi_lru_get_stats(ndpi_struct->tls_cert_cache, stats);
    return 0;
  case NDPI_LRUCACHE_MINING:
    ndpi_lru_get_stats(ndpi_struct->mining_cache, stats);
    return 0;
  case NDPI_LRUCACHE_MSTEAMS:
    ndpi_lru_get_stats(ndpi_struct->msteams_cache, stats);
    return 0;
  case NDPI_LRUCACHE_STUN_ZOOM:
    ndpi_lru_get_stats(ndpi_struct->stun_zoom_cache, stats);
    return 0;
  default:
    return -1;
  }
}

int ndpi_set_lru_cache_size(struct ndpi_detection_module_struct *ndpi_struct,
			    lru_cache_type cache_type,
			    u_int32_t num_entries)
{
  if(!ndpi_struct)
    return -1;

  switch(cache_type) {
  case NDPI_LRUCACHE_OOKLA:
    ndpi_struct->ookla_cache_num_entries = num_entries;
    return 0;
  case NDPI_LRUCACHE_BITTORRENT:
    ndpi_struct->bittorrent_cache_num_entries = num_entries;
    return 0;
  case NDPI_LRUCACHE_ZOOM:
    ndpi_struct->zoom_cache_num_entries = num_entries;
    return 0;
  case NDPI_LRUCACHE_STUN:
    ndpi_struct->stun_cache_num_entries = num_entries;
    return 0;
  case NDPI_LRUCACHE_TLS_CERT:
    ndpi_struct->tls_cert_cache_num_entries = num_entries;
    return 0;
  case NDPI_LRUCACHE_MINING:
    ndpi_struct->mining_cache_num_entries = num_entries;
    return 0;
  case NDPI_LRUCACHE_MSTEAMS:
    ndpi_struct->msteams_cache_num_entries = num_entries;
    return 0;
  case NDPI_LRUCACHE_STUN_ZOOM:
    ndpi_struct->stun_zoom_cache_num_entries = num_entries;
    return 0;
  default:
    return -1;
  }
}

int ndpi_get_lru_cache_size(struct ndpi_detection_module_struct *ndpi_struct,
			    lru_cache_type cache_type,
			    u_int32_t *num_entries)
{
  if(!ndpi_struct)
    return -1;

  switch(cache_type) {
  case NDPI_LRUCACHE_OOKLA:
    *num_entries = ndpi_struct->ookla_cache_num_entries;
    return 0;
  case NDPI_LRUCACHE_BITTORRENT:
    *num_entries = ndpi_struct->bittorrent_cache_num_entries;
    return 0;
  case NDPI_LRUCACHE_ZOOM:
    *num_entries = ndpi_struct->zoom_cache_num_entries;
    return 0;
  case NDPI_LRUCACHE_STUN:
    *num_entries = ndpi_struct->stun_cache_num_entries;
    return 0;
  case NDPI_LRUCACHE_TLS_CERT:
    *num_entries = ndpi_struct->tls_cert_cache_num_entries;
    return 0;
  case NDPI_LRUCACHE_MINING:
    *num_entries = ndpi_struct->mining_cache_num_entries;
    return 0;
  case NDPI_LRUCACHE_MSTEAMS:
    *num_entries = ndpi_struct->msteams_cache_num_entries;
    return 0;
  case NDPI_LRUCACHE_STUN_ZOOM:
    *num_entries = ndpi_struct->stun_zoom_cache_num_entries;
    return 0;
  default:
    return -1;
  }
}

int ndpi_set_lru_cache_ttl(struct ndpi_detection_module_struct *ndpi_struct,
			   lru_cache_type cache_type,
			   u_int32_t ttl)
{
  if(!ndpi_struct)
    return -1;

  switch(cache_type) {
  case NDPI_LRUCACHE_OOKLA:
    ndpi_struct->ookla_cache_ttl = ttl;
    return 0;
  case NDPI_LRUCACHE_BITTORRENT:
    ndpi_struct->bittorrent_cache_ttl = ttl;
    return 0;
  case NDPI_LRUCACHE_ZOOM:
    ndpi_struct->zoom_cache_ttl = ttl;
    return 0;
  case NDPI_LRUCACHE_STUN:
    ndpi_struct->stun_cache_ttl = ttl;
    return 0;
  case NDPI_LRUCACHE_TLS_CERT:
    ndpi_struct->tls_cert_cache_ttl = ttl;
    return 0;
  case NDPI_LRUCACHE_MINING:
    ndpi_struct->mining_cache_ttl = ttl;
    return 0;
  case NDPI_LRUCACHE_MSTEAMS:
    ndpi_struct->msteams_cache_ttl = ttl;
    return 0;
  case NDPI_LRUCACHE_STUN_ZOOM:
    ndpi_struct->stun_zoom_cache_ttl = ttl;
    return 0;
  default:
    return -1;
  }
}

int ndpi_get_lru_cache_ttl(struct ndpi_detection_module_struct *ndpi_struct,
			   lru_cache_type cache_type,
			   u_int32_t *ttl)
{
  if(!ndpi_struct || !ttl)
    return -1;

  switch(cache_type) {
  case NDPI_LRUCACHE_OOKLA:
    *ttl = ndpi_struct->ookla_cache_ttl;
    return 0;
  case NDPI_LRUCACHE_BITTORRENT:
    *ttl = ndpi_struct->bittorrent_cache_ttl;
    return 0;
  case NDPI_LRUCACHE_ZOOM:
    *ttl = ndpi_struct->zoom_cache_ttl;
    return 0;
  case NDPI_LRUCACHE_STUN:
    *ttl = ndpi_struct->stun_cache_ttl;
    return 0;
  case NDPI_LRUCACHE_TLS_CERT:
    *ttl = ndpi_struct->tls_cert_cache_ttl;
    return 0;
  case NDPI_LRUCACHE_MINING:
    *ttl = ndpi_struct->mining_cache_ttl;
    return 0;
  case NDPI_LRUCACHE_MSTEAMS:
    *ttl = ndpi_struct->msteams_cache_ttl;
    return 0;
  case NDPI_LRUCACHE_STUN_ZOOM:
    *ttl = ndpi_struct->stun_zoom_cache_ttl;
    return 0;
  default:
    return -1;
  }
}

static inline int ndpi_proto_cb_tcp_payload(const struct ndpi_detection_module_struct *ndpi_str, uint32_t idx) {
    return (ndpi_str->callback_buffer[idx].ndpi_selection_bitmask &
	     (NDPI_SELECTION_BITMASK_PROTOCOL_INT_TCP |
	      NDPI_SELECTION_BITMASK_PROTOCOL_INT_TCP_OR_UDP |
              NDPI_SELECTION_BITMASK_PROTOCOL_COMPLETE_TRAFFIC)) != 0;
}

static inline int ndpi_proto_cb_tcp_nopayload(const struct ndpi_detection_module_struct *ndpi_str, uint32_t idx) {
    return (ndpi_str->callback_buffer[idx].ndpi_selection_bitmask &
	     (NDPI_SELECTION_BITMASK_PROTOCOL_INT_TCP |
	      NDPI_SELECTION_BITMASK_PROTOCOL_INT_TCP_OR_UDP |
              NDPI_SELECTION_BITMASK_PROTOCOL_COMPLETE_TRAFFIC)) != 0
	   && (ndpi_str->callback_buffer[idx].ndpi_selection_bitmask &
	       NDPI_SELECTION_BITMASK_PROTOCOL_HAS_PAYLOAD) == 0;
}

static inline int ndpi_proto_cb_udp(const struct ndpi_detection_module_struct *ndpi_str, uint32_t idx) {
    return (ndpi_str->callback_buffer[idx].ndpi_selection_bitmask &
	     (NDPI_SELECTION_BITMASK_PROTOCOL_INT_UDP |
	      NDPI_SELECTION_BITMASK_PROTOCOL_INT_TCP_OR_UDP |
	      NDPI_SELECTION_BITMASK_PROTOCOL_COMPLETE_TRAFFIC)) != 0;
}

static inline int ndpi_proto_cb_other(const struct ndpi_detection_module_struct *ndpi_str, uint32_t idx) {
    return (ndpi_str->callback_buffer[idx].ndpi_selection_bitmask &
	     (NDPI_SELECTION_BITMASK_PROTOCOL_INT_TCP |
	      NDPI_SELECTION_BITMASK_PROTOCOL_INT_UDP |
	      NDPI_SELECTION_BITMASK_PROTOCOL_INT_TCP_OR_UDP)) == 0
	   ||
             (ndpi_str->callback_buffer[idx].ndpi_selection_bitmask &
	       NDPI_SELECTION_BITMASK_PROTOCOL_COMPLETE_TRAFFIC) != 0;
}

void ndpi_exclude_protocol(struct ndpi_detection_module_struct *ndpi_str, struct ndpi_flow_struct *flow,
                           u_int16_t protocol_id, const char *_file, const char *_func, int _line) {
  if(ndpi_is_valid_protoId(protocol_id)) {
#ifdef NDPI_ENABLE_DEBUG_MESSAGES
    if(ndpi_str && ndpi_str->ndpi_log_level >= NDPI_LOG_DEBUG && ndpi_str->ndpi_debug_printf != NULL) {
      (*(ndpi_str->ndpi_debug_printf))(protocol_id, ndpi_str, NDPI_LOG_DEBUG, _file, _func, _line, "exclude %s\n",
				       ndpi_get_proto_name(ndpi_str, protocol_id));
    }
#endif
    NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, protocol_id);
  }
}

/* ******************************************************************** */

u_int32_t ndpi_get_current_time(struct ndpi_flow_struct *flow)
{
  if(flow)
    return flow->last_packet_time_ms / 1000;
  return 0;
}

static u_int32_t make_msteams_key(struct ndpi_flow_struct *flow) {
  u_int32_t key;

  if(flow->is_ipv6)
    key = ndpi_quick_hash(flow->c_address.v6, 16);
  else
    key = ntohl(flow->c_address.v4);

  return key;
}

static void ndpi_reconcile_protocols(struct ndpi_detection_module_struct *ndpi_str,
				     struct ndpi_flow_struct *flow,
				     ndpi_protocol *ret) {
  /* This function can NOT access &ndpi_str->packet since it is called also from ndpi_detection_giveup() */

#if 0
  if(flow) {
    /* Do not go for DNS when there is an application protocol. Example DNS.Apple */
    if((flow->detected_protocol_stack[1] != NDPI_PROTOCOL_UNKNOWN)
       && (flow->detected_protocol_stack[0] /* app */ != flow->detected_protocol_stack[1] /* major */))
      NDPI_CLR_BIT(flow->risk, NDPI_SUSPICIOUS_DGA_DOMAIN);
  }
#endif

  // printf("====>> %u.%u [%u]\n", ret->master_protocol, ret->app_protocol, flow->detected_protocol_stack[0]);

  switch(ret->app_protocol) {
    /*
      Skype for a host doing MS Teams means MS Teams
      (MS Teams uses Skype as transport protocol for voice/video)
    */
  case NDPI_PROTOCOL_MSTEAMS:
    if(flow->l4_proto == IPPROTO_TCP) {
      // printf("====>> NDPI_PROTOCOL_MSTEAMS\n");

      if(ndpi_str->msteams_cache)
	ndpi_lru_add_to_cache(ndpi_str->msteams_cache,
			      make_msteams_key(flow),
			      0 /* dummy */,
			      ndpi_get_current_time(flow));
    }
    break;

  case NDPI_PROTOCOL_NETFLOW:
  case NDPI_PROTOCOL_SFLOW:
  case NDPI_PROTOCOL_RTP:
  case NDPI_PROTOCOL_COLLECTD:
    /* Remove NDPI_UNIDIRECTIONAL_TRAFFIC from unidirectional protocols */
    ndpi_unset_risk(ndpi_str, flow, NDPI_UNIDIRECTIONAL_TRAFFIC);
    break;

  case NDPI_PROTOCOL_SYSLOG:
    if(flow->l4_proto == IPPROTO_UDP)
      ndpi_unset_risk(ndpi_str, flow, NDPI_UNIDIRECTIONAL_TRAFFIC);
    break;

  case NDPI_PROTOCOL_SKYPE_TEAMS:
  case NDPI_PROTOCOL_SKYPE_TEAMS_CALL:
    if(flow->l4_proto == IPPROTO_UDP
       && ndpi_str->msteams_cache) {
      u_int16_t dummy;

      if(ndpi_lru_find_cache(ndpi_str->msteams_cache, make_msteams_key(flow),
			     &dummy, 0 /* Don't remove it as it can be used for other connections */,
			     ndpi_get_current_time(flow))) {
	  ret->app_protocol = NDPI_PROTOCOL_MSTEAMS;

	  /* Refresh cache */
	  ndpi_lru_add_to_cache(ndpi_str->msteams_cache,
				make_msteams_key(flow),
				0 /* dummy */,
				ndpi_get_current_time(flow));
      }
    }
    break;

  case NDPI_PROTOCOL_RDP:
    ndpi_set_risk(ndpi_str, flow, NDPI_DESKTOP_OR_FILE_SHARING_SESSION, "Found RDP"); /* Remote assistance */
    break;

  case NDPI_PROTOCOL_ANYDESK:
    if(flow->l4_proto == IPPROTO_TCP) /* TCP only */
      ndpi_set_risk(ndpi_str, flow, NDPI_DESKTOP_OR_FILE_SHARING_SESSION, "Found AnyDesk"); /* Remote assistance */
    break;
  } /* switch */

  if(flow) {
    switch(ndpi_get_proto_breed(ndpi_str, ret->app_protocol)) {
    case NDPI_PROTOCOL_UNSAFE:
    case NDPI_PROTOCOL_POTENTIALLY_DANGEROUS:
    case NDPI_PROTOCOL_DANGEROUS:
      ndpi_set_risk(ndpi_str, flow, NDPI_UNSAFE_PROTOCOL, NULL);
      break;
    default:
      /* Nothing to do */
      break;
    }
  }
}

/**
 * @brief malloc wrapper function
 */
static void *
malloc_wrapper(size_t size) {
        current_ndpi_memory += size;

        if (current_ndpi_memory > max_ndpi_memory)
                max_ndpi_memory = current_ndpi_memory;

        return malloc(size);
}

/* ***************************************************** */

/**
 * @brief free wrapper function
 */
static void
free_wrapper(void *freeable) {
        free(freeable);
}

void ndpi_free(void *ptr) {
  if(_ndpi_free) {
    if(ptr)
      _ndpi_free(ptr);
  } else {
    if(ptr)
      free(ptr);
  }
}

void ndpi_free_flow_data(struct ndpi_flow_struct* flow) {
  if(flow) {
    if(flow->num_risk_infos) {
      u_int i;

      for(i=0; i<flow->num_risk_infos; i++)
	ndpi_free(flow->risk_infos[i].info);
    }

    if(flow->http.url)
      ndpi_free(flow->http.url);

    if(flow->http.content_type)
      ndpi_free(flow->http.content_type);

    if(flow->http.request_content_type)
      ndpi_free(flow->http.request_content_type);

    if(flow->http.user_agent)
      ndpi_free(flow->http.user_agent);

    if(flow->http.nat_ip)
      ndpi_free(flow->http.nat_ip);

    if(flow->http.detected_os)
      ndpi_free(flow->http.detected_os);

    if(flow->http.server)
      ndpi_free(flow->http.server);

    if(flow->kerberos_buf.pktbuf)
      ndpi_free(flow->kerberos_buf.pktbuf);

    if(flow_is_proto(flow, NDPI_PROTOCOL_QUIC) ||
       flow_is_proto(flow, NDPI_PROTOCOL_TLS) ||
       flow_is_proto(flow, NDPI_PROTOCOL_DTLS) ||
       flow_is_proto(flow, NDPI_PROTOCOL_MAIL_SMTPS) ||
       flow_is_proto(flow, NDPI_PROTOCOL_MAIL_POPS) ||
       flow_is_proto(flow, NDPI_PROTOCOL_MAIL_IMAPS) ||
       flow_is_proto(flow, NDPI_PROTOCOL_FTPS)) {
      if(flow->protos.tls_quic.server_names)
	ndpi_free(flow->protos.tls_quic.server_names);

      if(flow->protos.tls_quic.advertised_alpns)
	ndpi_free(flow->protos.tls_quic.advertised_alpns);

      if(flow->protos.tls_quic.negotiated_alpn)
	ndpi_free(flow->protos.tls_quic.negotiated_alpn);

      if(flow->protos.tls_quic.tls_supported_versions)
	ndpi_free(flow->protos.tls_quic.tls_supported_versions);

      if(flow->protos.tls_quic.issuerDN)
	ndpi_free(flow->protos.tls_quic.issuerDN);

      if(flow->protos.tls_quic.subjectDN)
	ndpi_free(flow->protos.tls_quic.subjectDN);

      if(flow->protos.tls_quic.encrypted_sni.esni)
	ndpi_free(flow->protos.tls_quic.encrypted_sni.esni);
    }

    if(flow->tls_quic.message[0].buffer)
      ndpi_free(flow->tls_quic.message[0].buffer);
    if(flow->tls_quic.message[1].buffer)
      ndpi_free(flow->tls_quic.message[1].buffer);

    if(flow->l4_proto == IPPROTO_UDP) {
      if(flow->l4.udp.quic_reasm_buf)
        ndpi_free(flow->l4.udp.quic_reasm_buf);
      if(flow->l4.udp.quic_reasm_buf_bitmap)
        ndpi_free(flow->l4.udp.quic_reasm_buf_bitmap);
    }

    if(flow->flow_payload != NULL)
      ndpi_free(flow->flow_payload);
  }
}

void ndpi_free_flow(struct ndpi_flow_struct *flow) {
  if(flow) {
    ndpi_free_flow_data(flow);
    ndpi_free(flow);
  }
}

void ndpi_flow_free(void *ptr) {
  if(_ndpi_flow_free)
    _ndpi_flow_free(ptr);
  else
    ndpi_free_flow((struct ndpi_flow_struct *) ptr);
}

void set_ndpi_malloc(void *(*__ndpi_malloc)(size_t size)) {
  _ndpi_malloc = __ndpi_malloc;
}
void set_ndpi_flow_malloc(void *(*__ndpi_flow_malloc)(size_t size)) {
  _ndpi_flow_malloc = __ndpi_flow_malloc;
}

void set_ndpi_free(void (*__ndpi_free)(void *ptr)) {
  _ndpi_free = __ndpi_free;
}
void set_ndpi_flow_free(void (*__ndpi_flow_free)(void *ptr)) {
  _ndpi_flow_free = __ndpi_flow_free;
}

void *ndpi_realloc(void *ptr, size_t old_size, size_t new_size) {
  void *ret = ndpi_malloc(new_size);

  if(!ret)
    return(ret);
  else {
    if(ptr != NULL) {
      memcpy(ret, ptr, (old_size < new_size ? old_size : new_size));
      ndpi_free(ptr);
    }
    return(ret);
  }
}

char *ndpi_strdup(const char *s) {
  if(s == NULL ){
    return NULL;
  }

  int len = strlen(s);
  char *m = ndpi_malloc(len + 1);

  if(m) {
    memcpy(m, s, len);
    m[len] = '\0';
  }

  return(m);
}

static u_int8_t ndpi_domain_level(const char *name) {
  u_int8_t level = 1, state = 0;
  char c;
  while((c = *name++) != '\0') {
    c = c == '-' ? 2 : (c == '.' ? 1:0);
    level += ndpi_domain_level_automat[state][3];
    state  = ndpi_domain_level_automat[state][(uint8_t)c];
    if(!state) break;
  }
  return state >= 2 ? level:0;
}

static int ndpi_string_to_automa(struct ndpi_detection_module_struct *ndpi_str,
				 AC_AUTOMATA_t *ac_automa, const char *value,
                                 u_int16_t protocol_id, ndpi_protocol_category_t category,
				 ndpi_protocol_breed_t breed, uint8_t level,
                                 u_int8_t add_ends_with) {
  AC_PATTERN_t ac_pattern;
  AC_ERROR_t rc;
  u_int len;
  char *value_dup = NULL;

  if(!ndpi_is_valid_protoId(protocol_id)) {
    NDPI_LOG_ERR(ndpi_str, "[NDPI] protoId=%d: INTERNAL ERROR\n", protocol_id);
    return(-1);
  }

  if((ac_automa == NULL) || (value == NULL) || !*value)
    return(-2);

  value_dup = ndpi_strdup(value);
  if(!value_dup)
    return(-1);

  memset(&ac_pattern, 0, sizeof(ac_pattern));

  len = strlen(value);

  ac_pattern.astring      = value_dup;
  ac_pattern.length       = len;
  ac_pattern.rep.number   = protocol_id;
  ac_pattern.rep.category = (u_int16_t) category;
  ac_pattern.rep.breed    = (u_int16_t) breed;
  ac_pattern.rep.level    = level ? level : ndpi_domain_level(value);
  ac_pattern.rep.at_end   = add_ends_with && !ndpi_is_middle_string_char(value[len-1]); /* len != 0 */
  ac_pattern.rep.dot      = memchr(value,'.',len) != NULL;

#ifdef MATCH_DEBUG
  printf("Adding to %s %lx [%s%s][protocol_id: %u][category: %u][breed: %u][level: %u]\n",
	 ac_automa->name,(unsigned long int)ac_automa,
	 ac_pattern.astring,ac_pattern.rep.at_end? "$":"", protocol_id, category, breed,ac_pattern.rep.level);
#endif

  rc = ac_automata_add(ac_automa, &ac_pattern);

  if(rc != ACERR_SUCCESS) {
    ndpi_free(value_dup);

    if(rc != ACERR_DUPLICATE_PATTERN)
      return (-2);
  }

  return(0);
}

/* ****************************************************** */

static int ndpi_add_host_url_subprotocol(struct ndpi_detection_module_struct *ndpi_str,
					 char *value, int protocol_id,
                                         ndpi_protocol_category_t category,
					 ndpi_protocol_breed_t breed, uint8_t level) {
#ifndef DEBUG
  NDPI_LOG_DBG2(ndpi_str, "[NDPI] Adding [%s][%d]\n", value, protocol_id);
#endif

  return ndpi_string_to_automa(ndpi_str, (AC_AUTOMATA_t *)ndpi_str->host_automa.ac_automa,
			       value, protocol_id, category, breed, level, 1);

}

static int is_proto_enabled(struct ndpi_detection_module_struct *ndpi_str, int protoId)
{
  /* Custom protocols are always enabled */
  if(protoId >= NDPI_MAX_SUPPORTED_PROTOCOLS)
    return 1;
  if(NDPI_COMPARE_PROTOCOL_TO_BITMASK(ndpi_str->detection_bitmask, protoId) == 0)
    return 0;
  return 1;
}

void ndpi_init_protocol_match(struct ndpi_detection_module_struct *ndpi_str,
			      ndpi_protocol_match *match) {
  ndpi_port_range ports_a[MAX_DEFAULT_PORTS], ports_b[MAX_DEFAULT_PORTS];

  if(ndpi_str->proto_defaults[match->protocol_id].protoName == NULL) {
    ndpi_str->proto_defaults[match->protocol_id].protoName = ndpi_strdup(match->proto_name);
    if(!ndpi_str->proto_defaults[match->protocol_id].protoName)
      return;
    ndpi_str->proto_defaults[match->protocol_id].isAppProtocol = 1;
    ndpi_str->proto_defaults[match->protocol_id].protoId = match->protocol_id;
    ndpi_str->proto_defaults[match->protocol_id].protoCategory = match->protocol_category;
    ndpi_str->proto_defaults[match->protocol_id].protoBreed = match->protocol_breed;

    ndpi_set_proto_defaults(ndpi_str,
			    ndpi_str->proto_defaults[match->protocol_id].isClearTextProto,
			    ndpi_str->proto_defaults[match->protocol_id].isAppProtocol,
			    ndpi_str->proto_defaults[match->protocol_id].protoBreed,
			    ndpi_str->proto_defaults[match->protocol_id].protoId,
			    ndpi_str->proto_defaults[match->protocol_id].protoName,
			    ndpi_str->proto_defaults[match->protocol_id].protoCategory,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  }

  if(!is_proto_enabled(ndpi_str, match->protocol_id)) {
    NDPI_LOG_DBG(ndpi_str, "[NDPI] Skip protocol match for %s/protoId=%d: disabled\n",
		 match->string_to_match, match->protocol_id);
    return;
  }

  ndpi_add_host_url_subprotocol(ndpi_str, match->string_to_match,
				match->protocol_id, match->protocol_category,
				match->protocol_breed, match->level);
}

char *ndpi_get_proto_name(struct ndpi_detection_module_struct *ndpi_str,
			  u_int16_t proto_id) {
  if((proto_id >= ndpi_str->ndpi_num_supported_protocols)
     || (!ndpi_is_valid_protoId(proto_id))
     || (ndpi_str->proto_defaults[proto_id].protoName == NULL))
    proto_id = NDPI_PROTOCOL_UNKNOWN;

  return(ndpi_str->proto_defaults[proto_id].protoName);
}

int ndpi_search_into_bittorrent_cache(struct ndpi_detection_module_struct *ndpi_struct,
				      struct ndpi_flow_struct *flow,
				      /* Parameters below need to be in network byte order */
				      u_int32_t saddr, u_int16_t sport, u_int32_t daddr, u_int16_t dport) {

#ifdef BITTORRENT_CACHE_DEBUG
  printf("[%s:%u] ndpi_search_into_bittorrent_cache(%08X, %u, %08X, %u) [bt_check_performed=%d]\n",
	 __FILE__, __LINE__, saddr, sport, daddr, dport,
	 flow ? flow->bt_check_performed : -1);
#endif

  if(flow && flow->bt_check_performed /* Do the check once */)
    return(0);

  if(ndpi_struct->bittorrent_cache) {
    u_int16_t cached_proto;
    u_int8_t found = 0;
    u_int32_t key1, key2;

    if(flow)
      flow->bt_check_performed = 1;

    /* Check cached communications */
    key1 = ndpi_ip_port_hash_funct(saddr, sport), key2 = ndpi_ip_port_hash_funct(daddr, dport);

    found =
      ndpi_lru_find_cache(ndpi_struct->bittorrent_cache, saddr+daddr, &cached_proto, 0 /* Don't remove it as it can be used for other connections */, ndpi_get_current_time(flow))
      || ndpi_lru_find_cache(ndpi_struct->bittorrent_cache, key1, &cached_proto, 0     /* Don't remove it as it can be used for other connections */, ndpi_get_current_time(flow))
      || ndpi_lru_find_cache(ndpi_struct->bittorrent_cache, key2, &cached_proto, 0     /* Don't remove it as it can be used for other connections */, ndpi_get_current_time(flow));

#ifdef BITTORRENT_CACHE_DEBUG
    if(ndpi_struct->packet.udp)
      printf("[BitTorrent] *** [UDP] SEARCHING ports %u / %u [%u][%u][found: %u][packet_counter: %u]\n",
	     ntohs(sport), ntohs(dport), key1, key2, found, flow ? flow->packet_counter : 0);
    else
      printf("[BitTorrent] *** [TCP] SEARCHING ports %u / %u [%u][%u][found: %u][packet_counter: %u]\n",
	     ntohs(sport), ntohs(dport), key1, key2, found, flow ? flow->packet_counter : 0);
#endif

    return(found);
  }

  return(0);
}

void ndpi_fill_protocol_category(struct ndpi_detection_module_struct *ndpi_str, struct ndpi_flow_struct *flow,
				 ndpi_protocol *ret) {
  if((ret->master_protocol == NDPI_PROTOCOL_UNKNOWN) && (ret->app_protocol == NDPI_PROTOCOL_UNKNOWN))
    return;

  if(ndpi_str->custom_categories.categories_loaded) {
    if(flow->guessed_header_category != NDPI_PROTOCOL_CATEGORY_UNSPECIFIED) {
      flow->category = ret->category = flow->guessed_header_category;
      return;
    }

    if(flow->host_server_name[0] != '\0') {
      u_int32_t id;
      int rc = ndpi_match_custom_category(ndpi_str, flow->host_server_name,
					  strlen(flow->host_server_name), &id);
      if(rc == 0) {
	flow->category = ret->category = (ndpi_protocol_category_t) id;
	return;
      }
    }
  }

  flow->category = ret->category = ndpi_get_proto_category(ndpi_str, *ret);
}

ndpi_protocol_breed_t ndpi_get_proto_breed(struct ndpi_detection_module_struct *ndpi_str,
					   u_int16_t proto_id) {
  if((proto_id >= ndpi_str->ndpi_num_supported_protocols) ||
     (!ndpi_is_valid_protoId(proto_id)) ||
     (ndpi_str->proto_defaults[proto_id].protoName == NULL))
    proto_id = NDPI_PROTOCOL_UNKNOWN;

  return(ndpi_str->proto_defaults[proto_id].protoBreed);
}

int ndpi_handle_ipv6_extension_headers(u_int16_t l3len, const u_int8_t **l4ptr,
                                       u_int16_t *l4len, u_int8_t *nxt_hdr) {
  while(l3len > 1 && (*nxt_hdr == 0 || *nxt_hdr == 43 || *nxt_hdr == 44 || *nxt_hdr == 60 || *nxt_hdr == 135 || *nxt_hdr == 59)) {
    u_int16_t ehdr_len, frag_offset;

    // no next header
    if(*nxt_hdr == 59) {
      return(1);
    }

    // fragment extension header has fixed size of 8 bytes and the first byte is the next header type
    if(*nxt_hdr == 44) {
      if(*l4len < 8) {
	return(1);
      }

      if(l3len < 5) {
        return 1;
      }
      l3len -= 5;

      *nxt_hdr = (*l4ptr)[0];
      frag_offset = ntohs(*(u_int16_t *)((*l4ptr) + 2)) >> 3;
      // Handle ipv6 fragments as the ipv4 ones: keep the first fragment, drop the others
      if(frag_offset != 0)
          return(1);
      *l4len -= 8;
      (*l4ptr) += 8;
      continue;
    }

    // the other extension headers have one byte for the next header type
    // and one byte for the extension header length in 8 byte steps minus the first 8 bytes
    if(*l4len < 2) {
      return(1);
    }

    ehdr_len = (*l4ptr)[1];
    ehdr_len *= 8;
    ehdr_len += 8;

    if(ehdr_len > l3len) {
      return 1;
    }
    l3len -= ehdr_len;

    if(*l4len < ehdr_len) {
      return(1);
    }

    *nxt_hdr = (*l4ptr)[0];

    if(*l4len < ehdr_len)
      return(1);

    *l4len -= ehdr_len;
    (*l4ptr) += ehdr_len;
  }

  return(0);
}

static int ndpi_match_string_common(AC_AUTOMATA_t *automa, char *string_to_match,size_t string_len,
				    u_int32_t *protocol_id, ndpi_protocol_category_t *category,
				    ndpi_protocol_breed_t *breed) {
  AC_REP_t match = { NDPI_PROTOCOL_UNKNOWN, NDPI_PROTOCOL_CATEGORY_UNSPECIFIED, NDPI_PROTOCOL_UNRATED, 0, 0, 0, 0, 0 };
  AC_TEXT_t ac_input_text;
  int rc;

  if(protocol_id) *protocol_id = NDPI_PROTOCOL_UNKNOWN;

  if((automa == NULL) || (string_to_match == NULL) || (string_to_match[0] == '\0')) {
    return(-2);
  }

  if(automa->automata_open) {
    return(-1);
  }

  ac_input_text.astring = string_to_match, ac_input_text.length = string_len;
  ac_input_text.option = 0;
  rc = ac_automata_search(automa, &ac_input_text, &match);

  if(protocol_id)
    *protocol_id = rc ? match.number : NDPI_PROTOCOL_UNKNOWN;

  if(category)
    *category = rc ? match.category : 0;

  if(breed)
    *breed = rc ? match.breed : 0;

  return rc;
}

int ndpi_match_custom_category(struct ndpi_detection_module_struct *ndpi_str,
			       char *name, u_int name_len,
                               ndpi_protocol_category_t *category) {
  u_int32_t id;
  int rc = ndpi_match_string_common(ndpi_str->custom_categories.hostnames.ac_automa,
				    name, name_len, &id, category, NULL);
  if(rc < 0) return rc;
  return(id != NDPI_PROTOCOL_UNKNOWN ? 0 : -1);
}

u_int8_t ndpi_is_public_ipv4(u_int32_t a /* host byte order */) {
  if(   ((a & 0xFF000000) == 0x0A000000 /* 10.0.0.0/8 */)
	|| ((a & 0xFFF00000) == 0xAC100000 /* 172.16.0.0/12 */)
	|| ((a & 0xFFFF0000) == 0xC0A80000 /* 192.168.0.0/16 */)
	|| ((a & 0xFF000000) == 0x7F000000 /* 127.0.0.0/8 */)
	|| ((a & 0xF0000000) == 0xE0000000 /* 224.0.0.0/4 */)
	)
    return(0);
  else
    return(1);
}

static void ndpi_int_change_flow_protocol(struct ndpi_detection_module_struct *ndpi_str, struct ndpi_flow_struct *flow,
					  u_int16_t upper_detected_protocol, u_int16_t lower_detected_protocol,
					  ndpi_confidence_t confidence) {
  if(!flow)
    return;

  flow->detected_protocol_stack[0] = upper_detected_protocol,
  flow->detected_protocol_stack[1] = lower_detected_protocol;
  flow->confidence = confidence;
}

static void ndpi_int_change_protocol(struct ndpi_detection_module_struct *ndpi_str, struct ndpi_flow_struct *flow,
				     u_int16_t upper_detected_protocol, u_int16_t lower_detected_protocol,
				     ndpi_confidence_t confidence) {
  if((upper_detected_protocol == NDPI_PROTOCOL_UNKNOWN) && (lower_detected_protocol != NDPI_PROTOCOL_UNKNOWN))
    upper_detected_protocol = lower_detected_protocol;

  if(upper_detected_protocol == lower_detected_protocol)
    lower_detected_protocol = NDPI_PROTOCOL_UNKNOWN;

  ndpi_int_change_flow_protocol(ndpi_str, flow, upper_detected_protocol, lower_detected_protocol, confidence);
}

void ndpi_set_detected_protocol(struct ndpi_detection_module_struct *ndpi_str, struct ndpi_flow_struct *flow,
				u_int16_t upper_detected_protocol, u_int16_t lower_detected_protocol,
				ndpi_confidence_t confidence) {
  ndpi_int_change_protocol(ndpi_str, flow, upper_detected_protocol, lower_detected_protocol, confidence);
}

u_int32_t ndpi_ip_port_hash_funct(u_int32_t ip, u_int16_t port) {
  return(ip + 3 * port);
}

u_int16_t ndpi_network_ptree_match(struct ndpi_detection_module_struct *ndpi_str,
                                   struct in_addr *pin /* network byte order */) {
  ndpi_prefix_t prefix;
  ndpi_patricia_node_t *node;

  if(!ndpi_str->protocols_ptree)
    return(NDPI_PROTOCOL_UNKNOWN);

  if(ndpi_str->ndpi_num_custom_protocols == 0) {
    /*
      In case we don't have defined any custom protocol we check the ptree
      only in case of public IP addresses as in ndpi_content_match.c.inc
      we only have public IP addresses. Instead with custom protocols, users
      might have defined private protocols hence we should not skip
      the checks below
    */

    if(ndpi_is_public_ipv4(ntohl(pin->s_addr)) == 0)
      return(NDPI_PROTOCOL_UNKNOWN); /* Non public IP */
  }

  /* Make sure all in network byte order otherwise compares wont work */
  ndpi_fill_prefix_v4(&prefix, pin, 32, ((ndpi_patricia_tree_t *) ndpi_str->protocols_ptree)->maxbits);
  node = ndpi_patricia_search_best(ndpi_str->protocols_ptree, &prefix);

  return(node ? node->value.u.uv32.user_value : NDPI_PROTOCOL_UNKNOWN);
}

char *ndpi_protocol2name(struct ndpi_detection_module_struct *ndpi_str,
			 ndpi_protocol proto, char *buf, u_int buf_len) {
  if((proto.master_protocol != NDPI_PROTOCOL_UNKNOWN) && (proto.master_protocol != proto.app_protocol)) {
    if(proto.app_protocol != NDPI_PROTOCOL_UNKNOWN)
      ndpi_snprintf(buf, buf_len, "%s.%s", ndpi_get_proto_name(ndpi_str, proto.master_protocol),
	       ndpi_get_proto_name(ndpi_str, proto.app_protocol));
    else
      ndpi_snprintf(buf, buf_len, "%s", ndpi_get_proto_name(ndpi_str, proto.master_protocol));
  } else
    ndpi_snprintf(buf, buf_len, "%s", ndpi_get_proto_name(ndpi_str, proto.app_protocol));

  return(buf);
}

void ndpi_set_detected_protocol_keeping_master(struct ndpi_detection_module_struct *ndpi_str,
					       struct ndpi_flow_struct *flow,
					       u_int16_t detected_protocol,
					       ndpi_confidence_t confidence) {
  u_int16_t master;

  master = flow->detected_protocol_stack[1] ? flow->detected_protocol_stack[1] : flow->detected_protocol_stack[0];

  if (master != NDPI_PROTOCOL_UNKNOWN)
    ndpi_set_detected_protocol(ndpi_str, flow, detected_protocol, master, confidence);
  else
    ndpi_set_detected_protocol(ndpi_str, flow, NDPI_PROTOCOL_UNKNOWN, detected_protocol, confidence);
}

void set_ndpi_malloc(void* (*__ndpi_malloc)(size_t size));
void set_ndpi_free(void  (*__ndpi_free)(void *ptr));
void set_ndpi_flow_malloc(void* (*__ndpi_flow_malloc)(size_t size));
void set_ndpi_flow_free(void  (*__ndpi_flow_free)(void *ptr));

void * ndpi_malloc(size_t size);
void * ndpi_calloc(unsigned long count, size_t size);
void * ndpi_realloc(void *ptr, size_t old_size, size_t new_size);

void *ndpi_malloc(size_t size) {
  __sync_fetch_and_add(&ndpi_tot_allocated_memory, size);
  return(_ndpi_malloc ? _ndpi_malloc(size) : malloc(size));
}

/* ****************************************** */

void *ndpi_flow_malloc(size_t size) {
  return(_ndpi_flow_malloc ? _ndpi_flow_malloc(size) : ndpi_malloc(size));
}

void *ndpi_calloc(unsigned long count, size_t size) {
  size_t len = count * size;
  void *p = ndpi_malloc(len);

  if(p) {
    memset(p, 0, len);
    __sync_fetch_and_add(&ndpi_tot_allocated_memory, size);
  }

  return(p);
}


int
ndpi_workflow_node_cmp(const void *a, const void *b) {
        struct ndpi_flow_info *fa = (struct ndpi_flow_info *)a;
        struct ndpi_flow_info *fb = (struct ndpi_flow_info *)b;

        if (fa->hashval < fb->hashval)
                return (-1);
        else if (fa->hashval > fb->hashval)
                return (1);

        /* Flows have the same hash */

        if (fa->vlan_id < fb->vlan_id)
                return (-1);
        else {
                if (fa->vlan_id > fb->vlan_id)
                        return (1);
        }
        if (fa->protocol < fb->protocol)
                return (-1);
        else {
                if (fa->protocol > fb->protocol)
                        return (1);
        }

        if (((fa->src_ip == fb->src_ip) && (fa->src_port == fb->src_port) && (fa->dst_ip == fb->dst_ip) &&
             (fa->dst_port == fb->dst_port)) ||
            ((fa->src_ip == fb->dst_ip) && (fa->src_port == fb->dst_port) && (fa->dst_ip == fb->src_ip) &&
             (fa->dst_port == fb->src_port)))
                return (0);

        if (fa->src_ip < fb->src_ip)
                return (-1);
        else {
                if (fa->src_ip > fb->src_ip)
                        return (1);
        }
        if (fa->src_port < fb->src_port)
                return (-1);
        else {
                if (fa->src_port > fb->src_port)
                        return (1);
        }
        if (fa->dst_ip < fb->dst_ip)
                return (-1);
        else {
                if (fa->dst_ip > fb->dst_ip)
                        return (1);
        }
        if (fa->dst_port < fb->dst_port)
                return (-1);
        else {
                if (fa->dst_port > fb->dst_port)
                        return (1);
        }

        return (0); /* notreached */
}

int ndpi_current_pkt_from_client_to_server(const struct ndpi_packet_struct *packet,
					   const struct ndpi_flow_struct *flow)
{
  return packet->packet_direction == flow->client_packet_direction;
}

u_int8_t ndpi_extra_dissection_possible(struct ndpi_detection_module_struct *ndpi_str,
					struct ndpi_flow_struct *flow) {
#if 0
  u_int16_t proto =
    flow->detected_protocol_stack[1] ? flow->detected_protocol_stack[1] : flow->detected_protocol_stack[0];

  printf("[DEBUG] %s(%u.%u): %u\n", __FUNCTION__,
	 flow->detected_protocol_stack[0],
	 flow->detected_protocol_stack[1],
	 proto);
#endif

  if(!flow->extra_packets_func)
    return(0);
  return(1);
}

static u_int8_t ndpi_is_multi_or_broadcast(struct ndpi_packet_struct *packet) {

  if(packet->iph) {
    /* IPv4 */
    u_int32_t daddr = ntohl(packet->iph->daddr);

    if(((daddr & 0xE0000000) == 0xE0000000 /* multicast */)
       || ((daddr & 0x000000FF) == 0x000000FF /* last byte is 0xFF, not super correct, but a good approximation */)
       || ((daddr & 0x000000FF) == 0x00000000 /* last byte is 0x00, not super correct, but a good approximation */)
       || (daddr == 0xFFFFFFFF))
      return(1);
  } else if(packet->iphv6) {
    /* IPv6 */

    if((ntohl(packet->iphv6->ip6_dst.u6_addr.u6_addr32[0]) & 0xFF000000) == 0xFF000000)
      return(1);
  }

  return(0);
}

int NDPI_BITMASK_COMPARE(NDPI_PROTOCOL_BITMASK a, NDPI_PROTOCOL_BITMASK b) {
  unsigned int i;

  for(i = 0; i < NDPI_NUM_FDS_BITS; i++) {
    if(a.fds_bits[i] & b.fds_bits[i])
      return(1);
  }

  return(0);
}

static void ndpi_add_connection_as_zoom(struct ndpi_detection_module_struct *ndpi_struct,
					struct ndpi_flow_struct *flow) {
  if(ndpi_struct->zoom_cache)
    ndpi_lru_add_to_cache(ndpi_struct->zoom_cache, make_zoom_key(flow, 1), NDPI_PROTOCOL_ZOOM, ndpi_get_current_time(flow));
}

ndpi_risk_info* ndpi_risk2severity(ndpi_risk_enum risk) {
  return(&ndpi_known_risks[risk]);
}

static u_int32_t check_ndpi_subprotocols(struct ndpi_detection_module_struct * const ndpi_str,
                                         struct ndpi_flow_struct * const flow,
                                         NDPI_SELECTION_BITMASK_PROTOCOL_SIZE const ndpi_selection_packet,
                                         NDPI_PROTOCOL_BITMASK detection_bitmask,
                                         u_int16_t detected_protocol)
{
  u_int32_t num_calls = 0, a;

  if(detected_protocol == NDPI_PROTOCOL_UNKNOWN)
  {
    return num_calls;
  }

  for (a = 0; a < ndpi_str->proto_defaults[detected_protocol].subprotocol_count; a++)
  {
    u_int16_t subproto_id = ndpi_str->proto_defaults[detected_protocol].subprotocols[a];
    if(subproto_id == (uint16_t)NDPI_PROTOCOL_MATCHED_BY_CONTENT ||
        subproto_id == flow->detected_protocol_stack[0] ||
        subproto_id == flow->detected_protocol_stack[1])
    {
      continue;
    }

    u_int16_t subproto_index = ndpi_str->proto_defaults[subproto_id].protoIdx;
    if((ndpi_str->callback_buffer[subproto_index].ndpi_selection_bitmask & ndpi_selection_packet) ==
         ndpi_str->callback_buffer[subproto_index].ndpi_selection_bitmask &&
        NDPI_BITMASK_COMPARE(flow->excluded_protocol_bitmask,
                             ndpi_str->callback_buffer[subproto_index].excluded_protocol_bitmask) == 0 &&
        NDPI_BITMASK_COMPARE(ndpi_str->callback_buffer[subproto_index].detection_bitmask,
                             detection_bitmask) != 0)
    {
      ndpi_str->callback_buffer[subproto_index].func(ndpi_str, flow);
      num_calls++;
    }
  }

  return num_calls;
}

static u_int32_t check_ndpi_detection_func(struct ndpi_detection_module_struct * const ndpi_str,
					   struct ndpi_flow_struct * const flow,
					   NDPI_SELECTION_BITMASK_PROTOCOL_SIZE const ndpi_selection_packet,
					   struct ndpi_call_function_struct const * const callback_buffer,
					   uint32_t callback_buffer_size,
					   int is_tcp_without_payload)
{
  void *func = NULL;
  u_int32_t num_calls = 0;
  u_int16_t proto_index = ndpi_str->proto_defaults[flow->guessed_protocol_id].protoIdx;
  u_int16_t proto_id = ndpi_str->proto_defaults[flow->guessed_protocol_id].protoId;
  NDPI_PROTOCOL_BITMASK detection_bitmask;
  u_int32_t a;

  NDPI_SAVE_AS_BITMASK(detection_bitmask, flow->detected_protocol_stack[0]);

  if((proto_id != NDPI_PROTOCOL_UNKNOWN) &&
      NDPI_BITMASK_COMPARE(flow->excluded_protocol_bitmask,
			   ndpi_str->callback_buffer[proto_index].excluded_protocol_bitmask) == 0 &&
      NDPI_BITMASK_COMPARE(ndpi_str->callback_buffer[proto_index].detection_bitmask, detection_bitmask) != 0 &&
      (ndpi_str->callback_buffer[proto_index].ndpi_selection_bitmask & ndpi_selection_packet) ==
      ndpi_str->callback_buffer[proto_index].ndpi_selection_bitmask)
    {
      if((flow->guessed_protocol_id != NDPI_PROTOCOL_UNKNOWN) &&
          (ndpi_str->proto_defaults[flow->guessed_protocol_id].func != NULL) &&
          (is_tcp_without_payload == 0 ||
           ((ndpi_str->callback_buffer[proto_index].ndpi_selection_bitmask &
	     NDPI_SELECTION_BITMASK_PROTOCOL_HAS_PAYLOAD) == 0)))
	{
	  ndpi_str->proto_defaults[flow->guessed_protocol_id].func(ndpi_str, flow);
	  func = ndpi_str->proto_defaults[flow->guessed_protocol_id].func;
	  num_calls++;
	}
    }

  if(flow->detected_protocol_stack[0] == NDPI_PROTOCOL_UNKNOWN)
    {
      for (a = 0; a < callback_buffer_size; a++) {
        if((func != callback_buffer[a].func) &&
            (callback_buffer[a].ndpi_selection_bitmask & ndpi_selection_packet) ==
	    callback_buffer[a].ndpi_selection_bitmask &&
            NDPI_BITMASK_COMPARE(flow->excluded_protocol_bitmask,
                                 callback_buffer[a].excluded_protocol_bitmask) == 0 &&
            NDPI_BITMASK_COMPARE(callback_buffer[a].detection_bitmask,
                                 detection_bitmask) != 0)
	  {
	    callback_buffer[a].func(ndpi_str, flow);
	    num_calls++;

	    if(flow->detected_protocol_stack[0] != NDPI_PROTOCOL_UNKNOWN)
	      {
		break; /* Stop after the first detected protocol. */
	      }
	  }
      }
    }

  num_calls += check_ndpi_subprotocols(ndpi_str, flow, ndpi_selection_packet, detection_bitmask,
                                       flow->detected_protocol_stack[0]);
  num_calls += check_ndpi_subprotocols(ndpi_str, flow, ndpi_selection_packet, detection_bitmask,
                                       flow->detected_protocol_stack[1]);

  return num_calls;
}

static u_int32_t check_ndpi_udp_flow_func(struct ndpi_detection_module_struct *ndpi_str,
					  struct ndpi_flow_struct *flow,
					  NDPI_SELECTION_BITMASK_PROTOCOL_SIZE *ndpi_selection_packet)
{
  return check_ndpi_detection_func(ndpi_str, flow, *ndpi_selection_packet,
				   ndpi_str->callback_buffer_udp,
				   ndpi_str->callback_buffer_size_udp, 0);
}

static u_int32_t check_ndpi_tcp_flow_func(struct ndpi_detection_module_struct *ndpi_str,
					  struct ndpi_flow_struct *flow,
					  NDPI_SELECTION_BITMASK_PROTOCOL_SIZE *ndpi_selection_packet)
{
  if(ndpi_str->packet.payload_packet_len != 0) {
    return check_ndpi_detection_func(ndpi_str, flow, *ndpi_selection_packet,
				     ndpi_str->callback_buffer_tcp_payload,
				     ndpi_str->callback_buffer_size_tcp_payload, 0);
  } else {
    /* no payload */
    return check_ndpi_detection_func(ndpi_str, flow, *ndpi_selection_packet,
				     ndpi_str->callback_buffer_tcp_no_payload,
				     ndpi_str->callback_buffer_size_tcp_no_payload, 1);
  }
}
u_int32_t check_ndpi_other_flow_func(struct ndpi_detection_module_struct *ndpi_str,
				     struct ndpi_flow_struct *flow,
				     NDPI_SELECTION_BITMASK_PROTOCOL_SIZE *ndpi_selection_packet)
{
  return check_ndpi_detection_func(ndpi_str, flow, *ndpi_selection_packet,
				   ndpi_str->callback_buffer_non_tcp_udp,
				   ndpi_str->callback_buffer_size_non_tcp_udp, 0);
}

u_int16_t ndpi_network_port_ptree_match(struct ndpi_detection_module_struct *ndpi_str,
					struct in_addr *pin /* network byte order */,
					u_int16_t port /* network byte order */) {
  ndpi_prefix_t prefix;
  ndpi_patricia_node_t *node;

  if(!ndpi_str->protocols_ptree)
    return(NDPI_PROTOCOL_UNKNOWN);

  if(ndpi_str->ndpi_num_custom_protocols == 0) {
    /*
      In case we don't have defined any custom protocol we check the ptree
      only in case of public IP addresses as in ndpi_content_match.c.inc
      we only have public IP addresses. Instead with custom protocols, users
      might have defined private protocols hence we should not skip
      the checks below
    */

    if(ndpi_is_public_ipv4(ntohl(pin->s_addr)) == 0)
      return(NDPI_PROTOCOL_UNKNOWN); /* Non public IP */
  }

  /* Make sure all in network byte order otherwise compares wont work */
  ndpi_fill_prefix_v4(&prefix, pin, 32, ((ndpi_patricia_tree_t *) ndpi_str->protocols_ptree)->maxbits);
  node = ndpi_patricia_search_best(ndpi_str->protocols_ptree, &prefix);

  if(node) {
    if((node->value.u.uv32.additional_user_value == 0)
       || (node->value.u.uv32.additional_user_value == port))
      return(node->value.u.uv32.user_value);
  }

  return(NDPI_PROTOCOL_UNKNOWN);
}

u_int32_t ndpi_check_flow_func(struct ndpi_detection_module_struct *ndpi_str,
			       struct ndpi_flow_struct *flow,
			       NDPI_SELECTION_BITMASK_PROTOCOL_SIZE *ndpi_selection_packet) {
  if(!flow)
    return(0);
  else if(ndpi_str->packet.tcp != NULL)
    return(check_ndpi_tcp_flow_func(ndpi_str, flow, ndpi_selection_packet));
  else if(ndpi_str->packet.udp != NULL)
    return(check_ndpi_udp_flow_func(ndpi_str, flow, ndpi_selection_packet));
  else
    return(check_ndpi_other_flow_func(ndpi_str, flow, ndpi_selection_packet));
}

u_int16_t ndpi_guess_host_protocol_id(struct ndpi_detection_module_struct *ndpi_str,
				      struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &ndpi_str->packet;
  u_int16_t ret = NDPI_PROTOCOL_UNKNOWN;

  if(packet->iph) {
    struct in_addr addr;

    /* guess host protocol; server first */
    addr.s_addr = flow->s_address.v4;
    ret = ndpi_network_port_ptree_match(ndpi_str, &addr, flow->s_port);

    if(ret == NDPI_PROTOCOL_UNKNOWN) {
      addr.s_addr = flow->c_address.v4;
      ret = ndpi_network_port_ptree_match(ndpi_str, &addr, flow->c_port);
    }
  }

  return(ret);
}

int ndpi_fill_ip_protocol_category(struct ndpi_detection_module_struct *ndpi_str,
				   u_int32_t saddr, u_int32_t daddr,
				   ndpi_protocol *ret) {

  ret->custom_category_userdata = NULL;

  if(ndpi_str->custom_categories.categories_loaded) {
    ndpi_prefix_t prefix;
    ndpi_patricia_node_t *node;

    if(saddr == 0)
      node = NULL;
    else {
      /* Make sure all in network byte order otherwise compares wont work */
      ndpi_fill_prefix_v4(&prefix, (struct in_addr *) &saddr, 32,
			  ((ndpi_patricia_tree_t *) ndpi_str->protocols_ptree)->maxbits);
      node = ndpi_patricia_search_best(ndpi_str->custom_categories.ipAddresses, &prefix);
    }

    if(!node) {
      if(daddr != 0) {
	ndpi_fill_prefix_v4(&prefix, (struct in_addr *) &daddr, 32,
			    ((ndpi_patricia_tree_t *) ndpi_str->protocols_ptree)->maxbits);
	node = ndpi_patricia_search_best(ndpi_str->custom_categories.ipAddresses, &prefix);
      }
    }

    if(node) {
      ret->category = (ndpi_protocol_category_t) node->value.u.uv32.user_value;
      ret->custom_category_userdata = node->custom_user_data;
      return(1);
    }
  }

  ret->category = ndpi_get_proto_category(ndpi_str, *ret);

  return(0);
}

static int ndpi_do_guess(struct ndpi_detection_module_struct *ndpi_str, struct ndpi_flow_struct *flow, ndpi_protocol *ret) {
  struct ndpi_packet_struct *packet = &ndpi_str->packet;

  ret->master_protocol = ret->app_protocol = NDPI_PROTOCOL_UNKNOWN, ret->category = 0;

  if(packet->iphv6 || packet->iph) {
    u_int8_t user_defined_proto;

    /* guess protocol */
    flow->guessed_protocol_id      = (int16_t) ndpi_guess_protocol_id(ndpi_str, flow, flow->l4_proto, ntohs(flow->c_port), ntohs(flow->s_port), &user_defined_proto);
    flow->guessed_protocol_id_by_ip = ndpi_guess_host_protocol_id(ndpi_str, flow);

    ret->protocol_by_ip = flow->guessed_protocol_id_by_ip;

    if(ndpi_str->custom_categories.categories_loaded && packet->iph) {
      if(ndpi_str->ndpi_num_custom_protocols != 0)
	ndpi_fill_ip_protocol_category(ndpi_str, flow->c_address.v4, flow->s_address.v4, ret);
      flow->guessed_header_category = ret->category;
    } else
      flow->guessed_header_category = NDPI_PROTOCOL_CATEGORY_UNSPECIFIED;

    if(flow->guessed_protocol_id >= NDPI_MAX_SUPPORTED_PROTOCOLS) {
      /* This is a custom protocol and it has priority over everything else */
      ret->master_protocol = NDPI_PROTOCOL_UNKNOWN,
      ret->app_protocol = flow->guessed_protocol_id;
      flow->confidence = NDPI_CONFIDENCE_MATCH_BY_PORT; /* TODO */
      ndpi_fill_protocol_category(ndpi_str, flow, ret);
      return(-1);
    }

    if(user_defined_proto && flow->guessed_protocol_id != NDPI_PROTOCOL_UNKNOWN) {
      if(flow->guessed_protocol_id_by_ip != NDPI_PROTOCOL_UNKNOWN) {
        u_int8_t protocol_was_guessed;

        *ret = ndpi_detection_giveup(ndpi_str, flow, 0, &protocol_was_guessed);
      }

      ndpi_fill_protocol_category(ndpi_str, flow, ret);
      return(-1);
    }
  }

  if(flow->guessed_protocol_id_by_ip >= NDPI_MAX_SUPPORTED_PROTOCOLS) {
    NDPI_SELECTION_BITMASK_PROTOCOL_SIZE ndpi_selection_packet = {0};

    /* This is a custom protocol and it has priority over everything else */
    ret->master_protocol = flow->guessed_protocol_id, ret->app_protocol = flow->guessed_protocol_id_by_ip;

    flow->num_dissector_calls += ndpi_check_flow_func(ndpi_str, flow, &ndpi_selection_packet);

    ndpi_fill_protocol_category(ndpi_str, flow, ret);
    return(-1);
  }

  return(0);
}


u_int8_t ndpi_iph_is_valid_and_not_fragmented(const struct ndpi_iphdr *iph, const u_int16_t ipsize) {
  /*
    returned value:
    0: fragmented
    1: not fragmented
  */
  //#ifdef REQUIRE_FULL_PACKETS

  if(iph->protocol == IPPROTO_UDP) {
    if((ipsize < iph->ihl * 4)
       || (ipsize < ntohs(iph->tot_len))
       || (ntohs(iph->tot_len) < iph->ihl * 4)
       || (iph->frag_off & htons(0x1FFF)) != 0) {
      return(0);
    }
  }
  //#endif

  return(1);
}

void ndpi_connection_tracking(struct ndpi_detection_module_struct *ndpi_str,
			      struct ndpi_flow_struct *flow) {
  if(!flow) {
    return;
  } else {
    /* const for gcc code optimization and cleaner code */
    struct ndpi_packet_struct *packet = &ndpi_str->packet;
    const struct ndpi_iphdr *iph = packet->iph;
    const struct ndpi_ipv6hdr *iphv6 = packet->iphv6;
    const struct ndpi_tcphdr *tcph = packet->tcp;
    const struct ndpi_udphdr *udph = packet->udp;

    if(ndpi_str->max_payload_track_len > 0 && packet->payload_packet_len > 0) {
      /* printf("LEN: %u [%s]\n", packet->payload_packet_len, packet->payload); */

      if(flow->flow_payload == NULL)
	flow->flow_payload = (char*)ndpi_malloc(ndpi_str->max_payload_track_len + 1);

      if(flow->flow_payload != NULL)  {
	u_int i;

	for(i=0; (i<packet->payload_packet_len)
	      && (flow->flow_payload_len < ndpi_str->max_payload_track_len); i++) {
	  flow->flow_payload[flow->flow_payload_len++] =
	    (isprint(packet->payload[i]) || isspace(packet->payload[i])) ? packet->payload[i] : '.';
	}
      }
    }

    packet->tcp_retransmission = 0, packet->packet_direction = 0;

    if(ndpi_str->direction_detect_disable) {
      packet->packet_direction = flow->packet_direction;
    } else {
      if(iph != NULL && ntohl(iph->saddr) < ntohl(iph->daddr))
	packet->packet_direction = 1;

      if((iphv6 != NULL)
	 && NDPI_COMPARE_IPV6_ADDRESS_STRUCTS(&iphv6->ip6_src, &iphv6->ip6_dst) != 0)
	packet->packet_direction = 1;
    }

    flow->is_ipv6 = (packet->iphv6 != NULL);

    flow->last_packet_time_ms = packet->current_time_ms;

    packet->packet_lines_parsed_complete = 0;

    if(tcph != NULL) {
      u_int8_t flags = ((u_int8_t*)tcph)[13];

      if(flags == 0)
	ndpi_set_risk(ndpi_str, flow, NDPI_TCP_ISSUES, "TCP NULL scan");
      else if(flags == (TH_FIN | TH_PUSH | TH_URG))
	ndpi_set_risk(ndpi_str, flow, NDPI_TCP_ISSUES, "TCP XMAS scan");

      if(!ndpi_str->direction_detect_disable)
	packet->packet_direction = (ntohs(tcph->source) < ntohs(tcph->dest)) ? 1 : 0;

      if(packet->packet_direction == 0 /* cli -> srv */) {
	if(flags == TH_FIN)
	  ndpi_set_risk(ndpi_str, flow, NDPI_TCP_ISSUES, "TCP FIN scan");

	flow->l4.tcp.cli2srv_tcp_flags |= flags;
      } else
	flow->l4.tcp.srv2cli_tcp_flags |= flags;

      if((ndpi_str->input_info == NULL)
	 || ndpi_str->input_info->seen_flow_beginning == NDPI_FLOW_BEGINNING_UNKNOWN) {
	if(tcph->syn != 0 && tcph->ack == 0 && flow->l4.tcp.seen_syn == 0
	   && flow->l4.tcp.seen_syn_ack == 0 &&
	   flow->l4.tcp.seen_ack == 0) {
	  flow->l4.tcp.seen_syn = 1;
	} else {
	  if(tcph->syn != 0 && tcph->ack != 0 && flow->l4.tcp.seen_syn == 1
	     && flow->l4.tcp.seen_syn_ack == 0 &&
	     flow->l4.tcp.seen_ack == 0) {
	    flow->l4.tcp.seen_syn_ack = 1;
	  } else {
	    if(tcph->syn == 0 && tcph->ack == 1 && flow->l4.tcp.seen_syn == 1 && flow->l4.tcp.seen_syn_ack == 1 &&
	       flow->l4.tcp.seen_ack == 0) {
	      flow->l4.tcp.seen_ack = 1;
	    }
	  }
	}
      }

      if(flow->next_tcp_seq_nr[0] == 0 || flow->next_tcp_seq_nr[1] == 0 ||
	 (tcph->syn && flow->packet_counter == 0)) {
	/* initialize tcp sequence counters */
	/* the ack flag needs to be set to get valid sequence numbers from the other
	 * direction. Usually it will catch the second packet syn+ack but it works
	 * also for asymmetric traffic where it will use the first data packet
	 *
	 * if the syn flag is set add one to the sequence number,
	 * otherwise use the payload length.
	 *
	 * If we receive multiple syn-ack (before any real data), keep the last one
	 */
	if(tcph->ack != 0) {
	  flow->next_tcp_seq_nr[packet->packet_direction] =
	    ntohl(tcph->seq) + (tcph->syn ? 1 : packet->payload_packet_len);

	  /*
	    Check to avoid discrepancies in case we analyze a flow that does not start with SYN...
	    but that is already started when nDPI being to process it. See also (***) below
	  */
	  if(flow->num_processed_pkts > 1)
	    flow->next_tcp_seq_nr[1 - packet->packet_direction] = ntohl(tcph->ack_seq);
	}
      } else if(packet->payload_packet_len > 0) {
	/* check tcp sequence counters */
	if(((u_int32_t)(ntohl(tcph->seq) - flow->next_tcp_seq_nr[packet->packet_direction])) >
	   ndpi_str->tcp_max_retransmission_window_size) {
	  packet->tcp_retransmission = 1;

	  /* CHECK IF PARTIAL RETRY IS HAPPENING */
	  if((flow->next_tcp_seq_nr[packet->packet_direction] - ntohl(tcph->seq) <
	      packet->payload_packet_len)) {
	    if(flow->num_processed_pkts > 1) /* See also (***) above */
	      flow->next_tcp_seq_nr[packet->packet_direction] = ntohl(tcph->seq) + packet->payload_packet_len;
	  }
	}
	else {
	  flow->next_tcp_seq_nr[packet->packet_direction] = ntohl(tcph->seq) + packet->payload_packet_len;
	}
      }

      if(tcph->rst) {
	flow->next_tcp_seq_nr[0] = 0;
	flow->next_tcp_seq_nr[1] = 0;
      }
    } else if(udph != NULL) {
      if(!ndpi_str->direction_detect_disable)
	packet->packet_direction = (htons(udph->source) < htons(udph->dest)) ? 1 : 0;
    }

    if(flow->init_finished == 0) {
      u_int16_t s_port, d_port; /* Source/Dest ports */

      flow->init_finished = 1;

      if(tcph != NULL &&
	 ndpi_str->input_info &&
	 ndpi_str->input_info->seen_flow_beginning == NDPI_FLOW_BEGINNING_SEEN) {
	flow->l4.tcp.seen_syn = 1;
	flow->l4.tcp.seen_syn_ack = 1;
	flow->l4.tcp.seen_ack = 1;
      }

      /* Client/Server direction */

      s_port = 0;
      d_port = 0;
      if(tcph != NULL) {
	s_port = tcph->source;
	d_port = tcph->dest;
      } else if(udph != NULL) {
	s_port = udph->source;
	d_port = udph->dest;
      }

      if(ndpi_str->input_info &&
	 ndpi_str->input_info->in_pkt_dir != NDPI_IN_PKT_DIR_UNKNOWN) {
	if(ndpi_str->input_info->in_pkt_dir == NDPI_IN_PKT_DIR_C_TO_S)
	  flow->client_packet_direction = packet->packet_direction;
	else
	  flow->client_packet_direction = !packet->packet_direction;
      } else {
	if(tcph && tcph->syn) {
	  if(tcph->ack == 0) {
	    flow->client_packet_direction = packet->packet_direction;
	  } else {
	    flow->client_packet_direction = !packet->packet_direction;
	  }
	} else if(ntohs(s_port) > 1024 && ntohs(d_port) < 1024) {
	  flow->client_packet_direction = packet->packet_direction;
	} else if(ntohs(s_port) < 1024 && ntohs(d_port) > 1024) {
	  flow->client_packet_direction = !packet->packet_direction;
	} else {
	  flow->client_packet_direction = packet->packet_direction;
	}
      }

      if(ndpi_current_pkt_from_client_to_server(packet, flow)) {
	if(flow->is_ipv6 == 0) {
	  flow->c_address.v4 = packet->iph->saddr;
	  flow->s_address.v4 = packet->iph->daddr;
	} else {
	  memcpy(flow->c_address.v6, &packet->iphv6->ip6_src, 16);
	  memcpy(flow->s_address.v6, &packet->iphv6->ip6_dst, 16);
	}
	flow->c_port = s_port;
	flow->s_port = d_port;
      } else {
	if(flow->is_ipv6 == 0) {
	  flow->c_address.v4 = packet->iph->daddr;
	  flow->s_address.v4 = packet->iph->saddr;
	} else {
	  memcpy(flow->c_address.v6, &packet->iphv6->ip6_dst, 16);
	  memcpy(flow->s_address.v6, &packet->iphv6->ip6_src, 16);
	}
	flow->c_port = d_port;
	flow->s_port = s_port;
      }
    }

    if(flow->packet_counter < MAX_PACKET_COUNTER && packet->payload_packet_len) {
      flow->packet_counter++;
    }

    if(flow->all_packets_counter < MAX_PACKET_COUNTER)
      flow->all_packets_counter++;

    if((flow->packet_direction_counter[packet->packet_direction] < MAX_PACKET_COUNTER)
       /* && packet->payload_packet_len */) {
      flow->packet_direction_counter[packet->packet_direction]++;
    }

    if(flow->packet_direction_complete_counter[packet->packet_direction] < MAX_PACKET_COUNTER) {
      flow->packet_direction_complete_counter[packet->packet_direction]++;
    }

    if(ndpi_is_multi_or_broadcast(packet))
      ; /* multicast or broadcast */
    else {
      if(flow->packet_direction_complete_counter[0] == 0)
	ndpi_set_risk(ndpi_str, flow, NDPI_UNIDIRECTIONAL_TRAFFIC, "No client to server traffic"); /* Should never happen */
      else if(flow->packet_direction_complete_counter[1] == 0)
	ndpi_set_risk(ndpi_str, flow, NDPI_UNIDIRECTIONAL_TRAFFIC, "No server to client traffic");
      else {
	ndpi_unset_risk(ndpi_str, flow, NDPI_UNIDIRECTIONAL_TRAFFIC); /* Clear bit */
      }
    }
  }
}

static int ndpi_is_ntop_protocol(ndpi_protocol *ret) {
  if((ret->master_protocol == NDPI_PROTOCOL_HTTP) && (ret->app_protocol == NDPI_PROTOCOL_NTOP))
    return(1);
  else
    return(0);
}

ndpi_risk_enum ndpi_network_risk_ptree_match(struct ndpi_detection_module_struct *ndpi_str,
					     struct in_addr *pin /* network byte order */) {
  ndpi_prefix_t prefix;
  ndpi_patricia_node_t *node;

  /* Make sure all in network byte order otherwise compares wont work */
  ndpi_fill_prefix_v4(&prefix, pin, 32, ((ndpi_patricia_tree_t *) ndpi_str->ip_risk_ptree)->maxbits);
  node = ndpi_patricia_search_best(ndpi_str->ip_risk_ptree, &prefix);

  if(node)
    return((ndpi_risk_enum)node->value.u.uv32.user_value);

  return(NDPI_NO_RISK);
}

static int ndpi_check_protocol_port_mismatch_exceptions(struct ndpi_detection_module_struct *ndpi_str,
							struct ndpi_flow_struct *flow,
							ndpi_default_ports_tree_node_t *expected_proto,
							ndpi_protocol *returned_proto) {
  /*
    For TLS (and other protocols) it is not simple to guess the exact protocol so before
    triggering an alert we need to make sure what we have exhausted all the possible
    options available
  */

  if(ndpi_is_ntop_protocol(returned_proto)) return(1);

  if(returned_proto->master_protocol == NDPI_PROTOCOL_TLS) {
    switch(expected_proto->proto->protoId) {
    case NDPI_PROTOCOL_MAIL_IMAPS:
    case NDPI_PROTOCOL_MAIL_POPS:
    case NDPI_PROTOCOL_MAIL_SMTPS:
      return(1); /* This is a reasonable exception */
      break;
    }
  }

  return(0);
}

u_int16_t ndpi_guess_protocol_id(struct ndpi_detection_module_struct *ndpi_str, struct ndpi_flow_struct *flow,
                                 u_int8_t proto, u_int16_t sport, u_int16_t dport, u_int8_t *user_defined_proto) {
  struct ndpi_packet_struct *packet = &ndpi_str->packet;
  *user_defined_proto = 0; /* Default */

  if(sport && dport) {
    ndpi_default_ports_tree_node_t *found = ndpi_get_guessed_protocol_id(ndpi_str, proto, sport, dport);

    if(found != NULL) {
      u_int16_t guessed_proto = found->proto->protoId;

      /* We need to check if the guessed protocol isn't excluded by nDPI */
      if(flow && (proto == IPPROTO_UDP) &&
	 NDPI_COMPARE_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, guessed_proto) &&
	 is_udp_not_guessable_protocol(guessed_proto))
	return(NDPI_PROTOCOL_UNKNOWN);
      else {
	*user_defined_proto = found->customUserProto;
	return(guessed_proto);
      }
    }
  } else {
    /* No TCP/UDP */

    switch(proto) {
    case NDPI_IPSEC_PROTOCOL_ESP:
    case NDPI_IPSEC_PROTOCOL_AH:
      return(NDPI_PROTOCOL_IPSEC);
    case NDPI_GRE_PROTOCOL_TYPE:
      return(NDPI_PROTOCOL_IP_GRE);
    case NDPI_PGM_PROTOCOL_TYPE:
      return(NDPI_PROTOCOL_IP_PGM);
    case NDPI_PIM_PROTOCOL_TYPE:
      return(NDPI_PROTOCOL_IP_PIM);
    case NDPI_ICMP_PROTOCOL_TYPE:
      if(flow) {
        flow->entropy = 0.0f;
	/* Run some basic consistency tests */

	if(packet->payload_packet_len < sizeof(struct ndpi_icmphdr))
	  ndpi_set_risk(ndpi_str, flow, NDPI_MALFORMED_PACKET, NULL);
	else {
	  u_int8_t icmp_type = (u_int8_t)packet->payload[0];
	  u_int8_t icmp_code = (u_int8_t)packet->payload[1];

	  /* https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml */
	  if(((icmp_type >= 44) && (icmp_type <= 252))
	     || (icmp_code > 15))
	    ndpi_set_risk(ndpi_str, flow, NDPI_MALFORMED_PACKET, NULL);

	  if(packet->payload_packet_len > sizeof(struct ndpi_icmphdr)) {
	    flow->entropy = ndpi_entropy(packet->payload + sizeof(struct ndpi_icmphdr),
	                                 packet->payload_packet_len - sizeof(struct ndpi_icmphdr));

	    if(NDPI_ENTROPY_ENCRYPTED_OR_RANDOM(flow->entropy) != 0) {
	      char str[32];

		snprintf(str, sizeof(str), "Entropy %.2f", flow->entropy);
		ndpi_set_risk(ndpi_str, flow, NDPI_SUSPICIOUS_ENTROPY, str);
	    }

	    u_int16_t chksm = ndpi_calculate_icmp4_checksum(packet->payload, packet->payload_packet_len);
	    if(chksm) {
	      ndpi_set_risk(ndpi_str, flow, NDPI_MALFORMED_PACKET, NULL);
	    }
	  }
	}
      }
      return(NDPI_PROTOCOL_IP_ICMP);
    case NDPI_IGMP_PROTOCOL_TYPE:
      return(NDPI_PROTOCOL_IP_IGMP);
    case NDPI_EGP_PROTOCOL_TYPE:
      return(NDPI_PROTOCOL_IP_EGP);
    case NDPI_SCTP_PROTOCOL_TYPE:
      return(NDPI_PROTOCOL_IP_SCTP);
    case NDPI_OSPF_PROTOCOL_TYPE:
      return(NDPI_PROTOCOL_IP_OSPF);
    case NDPI_IPIP_PROTOCOL_TYPE:
      return(NDPI_PROTOCOL_IP_IP_IN_IP);
    case NDPI_ICMPV6_PROTOCOL_TYPE:
      if(flow) {
	/* Run some basic consistency tests */

	if(packet->payload_packet_len < sizeof(struct ndpi_icmphdr))
	  ndpi_set_risk(ndpi_str, flow, NDPI_MALFORMED_PACKET, NULL);
	else {
	  u_int8_t icmp6_type = (u_int8_t)packet->payload[0];
	  u_int8_t icmp6_code = (u_int8_t)packet->payload[1];

	  /* https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol_for_IPv6 */
	  if(((icmp6_type >= 5) && (icmp6_type <= 127))
	     || ((icmp6_code >= 156) && (icmp6_type != 255)))
	    ndpi_set_risk(ndpi_str, flow, NDPI_MALFORMED_PACKET, NULL);
	}
      }
      return(NDPI_PROTOCOL_IP_ICMPV6);
    case 112:
      return(NDPI_PROTOCOL_IP_VRRP);
    }
  }

  return(NDPI_PROTOCOL_UNKNOWN);
}

int ndpi_fill_prefix_v4(ndpi_prefix_t *p, const struct in_addr *a, int b, int mb) {
  if(b < 0 || b > mb)
    return(-1);

  memset(p, 0, sizeof(ndpi_prefix_t));
  memcpy(&p->add.sin, a, (mb + 7) / 8);
  p->family = AF_INET;
  p->bitlen = b;
  p->ref_count = 0;

  return(0);
}

static ndpi_patricia_node_t* add_to_ptree(ndpi_patricia_tree_t *tree, int family, void *addr, int bits) {
  ndpi_prefix_t prefix;
  ndpi_patricia_node_t *node;

  ndpi_fill_prefix_v4(&prefix, (struct in_addr *) addr, bits, tree->maxbits);

  node = ndpi_patricia_lookup(tree, &prefix);
  if(node) memset(&node->value, 0, sizeof(node->value));

  return(node);
}

/* No static because it is used by fuzzer, too */
int ac_domain_match_handler(AC_MATCH_t *m, AC_TEXT_t *txt, AC_REP_t *match) {
  AC_PATTERN_t *pattern = m->patterns;
  int i,start,end = m->position;

  for(i=0; i < m->match_num; i++,pattern++) {
    /*
     * See ac_automata_exact_match()
     * The bit is set if the pattern exactly matches AND
     * the length of the pattern is longer than that of the previous one.
     * Skip shorter (less precise) templates.
     */
    if(!(m->match_map & (1u << i)))
      continue;
    start = end - pattern->length;

    if(start == 0 && end == txt->length) {
      *match = pattern->rep; txt->match.last = pattern;
      return 1;
    }
    /* pattern is DOMAIN.NAME and string x.DOMAIN.NAME ? */
    if(start > 1 && !ndpi_is_middle_string_char(pattern->astring[0]) && pattern->rep.dot) {
      /*
	The patch below allows in case of pattern ws.amazon.com
	to avoid matching aws.amazon.com whereas a.ws.amazon.com
	has to match
      */
      if(ndpi_is_middle_string_char(txt->astring[start-1])) {
	if(!txt->match.last || txt->match.last->rep.level < pattern->rep.level) {
	  txt->match.last = pattern; *match = pattern->rep;
	}
      }
      continue;
    }

    if(!txt->match.last || txt->match.last->rep.level < pattern->rep.level) {
      txt->match.last = pattern; *match = pattern->rep;
    }
  }
  return 0;
}

int ndpi_load_hostname_category(struct ndpi_detection_module_struct *ndpi_str,
				const char *name_to_add,
				ndpi_protocol_category_t category) {

  if(ndpi_str->custom_categories.hostnames_shadow.ac_automa == NULL)
    return(-1);

  if(name_to_add == NULL)
    return(-1);

  return ndpi_string_to_automa(ndpi_str,
			       (AC_AUTOMATA_t *)ndpi_str->custom_categories.hostnames_shadow.ac_automa,
			       name_to_add,category,category, 0, 0, 1); /* at_end */
}

int ndpi_load_ip_category(struct ndpi_detection_module_struct *ndpi_str,
			  const char *ip_address_and_mask,
			  ndpi_protocol_category_t category,
			  void *user_data) {
  ndpi_patricia_node_t *node;
  struct in_addr pin;
  int bits = 32;
  char *ptr;
  char ipbuf[64];

  strncpy(ipbuf, ip_address_and_mask, sizeof(ipbuf));
  ipbuf[sizeof(ipbuf) - 1] = '\0';

  ptr = strrchr(ipbuf, '/');

  if(ptr) {
    *(ptr++) = '\0';
    if(atoi(ptr) >= 0 && atoi(ptr) <= 32)
      bits = atoi(ptr);
  }

  if(inet_pton(AF_INET, ipbuf, &pin) != 1) {
    NDPI_LOG_DBG2(ndpi_str, "Invalid ip/ip+netmask: %s\n", ip_address_and_mask);
    return(-1);
  }

  if((node = add_to_ptree(ndpi_str->custom_categories.ipAddresses_shadow, AF_INET, &pin, bits)) != NULL) {
    node->value.u.uv32.user_value = (u_int16_t)category, node->value.u.uv32.additional_user_value = 0;
    node->custom_user_data = user_data;
  }


  return(0);
}
/* ********************************************************************************* */

/* Loads an IP or name category */
int ndpi_load_category(struct ndpi_detection_module_struct *ndpi_struct, const char *ip_or_name,
		       ndpi_protocol_category_t category, void *user_data) {
  int rv;

  /* Try to load as IP address first */
  rv = ndpi_load_ip_category(ndpi_struct, ip_or_name, category, user_data);

  if(rv < 0) {
    /*
       IP load failed, load as hostname

       NOTE:
       we cannot add user_data here as with Aho-Corasick this
       information would not be used
    */
    rv = ndpi_load_hostname_category(ndpi_struct, ip_or_name, category);
  }

  return(rv);
}

int ndpi_enable_loaded_categories(struct ndpi_detection_module_struct *ndpi_str) {
  int i;
  static char *built_in = "built-in";

  /* First add the nDPI known categories matches */
  for(i = 0; category_match[i].string_to_match != NULL; i++)
    ndpi_load_category(ndpi_str, category_match[i].string_to_match,
		       category_match[i].protocol_category, built_in);

  /* Free */
  ac_automata_release((AC_AUTOMATA_t *) ndpi_str->custom_categories.hostnames.ac_automa,
		      1 /* free patterns strings memory */);

  /* Finalize */
  if(ndpi_str->custom_categories.hostnames_shadow.ac_automa)
    ac_automata_finalize((AC_AUTOMATA_t *) ndpi_str->custom_categories.hostnames_shadow.ac_automa);

  /* Swap */
  ndpi_str->custom_categories.hostnames.ac_automa = ndpi_str->custom_categories.hostnames_shadow.ac_automa;

  /* Realloc */
  ndpi_str->custom_categories.hostnames_shadow.ac_automa = ac_automata_init(ac_domain_match_handler);
  if(ndpi_str->custom_categories.hostnames_shadow.ac_automa) {
    ac_automata_feature(ndpi_str->custom_categories.hostnames_shadow.ac_automa,AC_FEATURE_LC);
    ac_automata_name(ndpi_str->custom_categories.hostnames_shadow.ac_automa,"ccat_sh",0);
  }

  if(ndpi_str->custom_categories.ipAddresses != NULL)
    ndpi_patricia_destroy((ndpi_patricia_tree_t *) ndpi_str->custom_categories.ipAddresses, free_ptree_data);

  ndpi_str->custom_categories.ipAddresses = ndpi_str->custom_categories.ipAddresses_shadow;
  ndpi_str->custom_categories.ipAddresses_shadow = ndpi_patricia_new(32 /* IPv4 */);

  ndpi_str->custom_categories.categories_loaded = 1;

  return(0);
}

static void ndpi_init_ptree_ipv4(struct ndpi_detection_module_struct *ndpi_str,
				 void *ptree, ndpi_network host_list[]) {
  int i;

  for(i = 0; host_list[i].network != 0x0; i++) {
    struct in_addr pin;
    ndpi_patricia_node_t *node;

    pin.s_addr = htonl(host_list[i].network);
    if((node = add_to_ptree(ptree, AF_INET, &pin, host_list[i].cidr /* bits */)) != NULL) {
      /* Two main cases:
         1) ip -> protocol: uv32.user_value = protocol; uv32.additional_user_value = 0;
         2) ip -> risk: uv32.user_value = risk; uv32.additional_user_value = 0;
      */
      node->value.u.uv32.user_value = host_list[i].value, node->value.u.uv32.additional_user_value = 0;
    }
  }
}

static u_int8_t ndpi_detection_get_l4_internal(struct ndpi_detection_module_struct *ndpi_str, const u_int8_t *l3,
                                               u_int16_t l3_len, const u_int8_t **l4_return, u_int16_t *l4_len_return,
                                               u_int8_t *l4_protocol_return, u_int32_t flags) {
  const struct ndpi_iphdr *iph = NULL;
  const struct ndpi_ipv6hdr *iph_v6 = NULL;
  u_int16_t l4len = 0;
  const u_int8_t *l4ptr = NULL;
  u_int8_t l4protocol = 0;

  if(l3 == NULL || l3_len < sizeof(struct ndpi_iphdr))
    return(1);

  if((iph = (const struct ndpi_iphdr *) l3) == NULL)
    return(1);

  if(iph->version == IPVERSION && iph->ihl >= 5) {
    NDPI_LOG_DBG2(ndpi_str, "ipv4 header\n");
  }
  else if(iph->version == 6 && l3_len >= sizeof(struct ndpi_ipv6hdr)) {
    NDPI_LOG_DBG2(ndpi_str, "ipv6 header\n");
    iph_v6 = (const struct ndpi_ipv6hdr *) l3;
    iph = NULL;
  } else {
    return(1);
  }

  if((flags & NDPI_DETECTION_ONLY_IPV6) && iph != NULL) {
    NDPI_LOG_DBG2(ndpi_str, "ipv4 header found but excluded by flag\n");
    return(1);
  } else if((flags & NDPI_DETECTION_ONLY_IPV4) && iph_v6 != NULL) {
    NDPI_LOG_DBG2(ndpi_str, "ipv6 header found but excluded by flag\n");
    return(1);
  }

  /* 0: fragmented; 1: not fragmented */
  if(iph != NULL && ndpi_iph_is_valid_and_not_fragmented(iph, l3_len)) {
    u_int16_t len = ndpi_min(ntohs(iph->tot_len), l3_len);
    u_int16_t hlen = (iph->ihl * 4);

    l4ptr = (((const u_int8_t *) iph) + iph->ihl * 4);

    if(len == 0)
      len = l3_len;

    l4len = (len > hlen) ? (len - hlen) : 0;
    l4protocol = iph->protocol;
  }

  else if(iph_v6 != NULL && (l3_len - sizeof(struct ndpi_ipv6hdr)) >= ntohs(iph_v6->ip6_hdr.ip6_un1_plen)) {
    l4ptr = (((const u_int8_t *) iph_v6) + sizeof(struct ndpi_ipv6hdr));
    l4len = ntohs(iph_v6->ip6_hdr.ip6_un1_plen);
    l4protocol = iph_v6->ip6_hdr.ip6_un1_nxt;

    // we need to handle IPv6 extension headers if present
    if(ndpi_handle_ipv6_extension_headers(l3_len - sizeof(struct ndpi_ipv6hdr), &l4ptr, &l4len, &l4protocol) != 0) {
      return(1);
    }

  } else {
    return(1);
  }

  if(l4_return != NULL) {
    *l4_return = l4ptr;
  }

  if(l4_len_return != NULL) {
    *l4_len_return = l4len;
  }

  if(l4_protocol_return != NULL) {
    *l4_protocol_return = l4protocol;
  }

  return(0);
}

static void ndpi_reset_packet_line_info(struct ndpi_packet_struct *packet) {
  packet->parsed_lines = 0, packet->empty_line_position_set = 0, packet->host_line.ptr = NULL,
    packet->host_line.len = 0, packet->referer_line.ptr = NULL, packet->referer_line.len = 0,
    packet->authorization_line.len = 0, packet->authorization_line.ptr = NULL,
    packet->content_line.ptr = NULL, packet->content_line.len = 0, packet->accept_line.ptr = NULL,
    packet->accept_line.len = 0, packet->user_agent_line.ptr = NULL, packet->user_agent_line.len = 0,
    packet->http_url_name.ptr = NULL, packet->http_url_name.len = 0, packet->http_encoding.ptr = NULL,
    packet->http_encoding.len = 0, packet->http_transfer_encoding.ptr = NULL, packet->http_transfer_encoding.len = 0,
    packet->http_contentlen.ptr = NULL, packet->http_contentlen.len = 0, packet->content_disposition_line.ptr = NULL,
    packet->content_disposition_line.len = 0, packet->http_cookie.ptr = NULL,
    packet->http_cookie.len = 0, packet->http_origin.len = 0, packet->http_origin.ptr = NULL,
    packet->http_x_session_type.ptr = NULL, packet->http_x_session_type.len = 0, packet->server_line.ptr = NULL,
    packet->server_line.len = 0, packet->http_method.ptr = NULL, packet->http_method.len = 0,
    packet->http_response.ptr = NULL, packet->http_response.len = 0, packet->http_num_headers = 0,
    packet->forwarded_line.ptr = NULL, packet->forwarded_line.len = 0;
}
static int ndpi_init_packet(struct ndpi_detection_module_struct *ndpi_str,
			    struct ndpi_flow_struct *flow,
			    const u_int64_t current_time_ms,
			    const unsigned char *packet_data,
			    unsigned short packetlen,
			    const struct ndpi_flow_input_info *input_info) {
  struct ndpi_packet_struct *packet = &ndpi_str->packet;
  const struct ndpi_iphdr *decaps_iph = NULL;
  u_int16_t l3len;
  u_int16_t l4len, l4_packet_len;
  const u_int8_t *l4ptr;
  u_int8_t l4protocol;
  u_int8_t l4_result;

  if(!flow)
    return(1);

  /* need at least 20 bytes for ip header */
  if(packetlen < 20)
    return 1;

  packet->current_time_ms = current_time_ms;

  ndpi_str->input_info = input_info;

  packet->iph = (const struct ndpi_iphdr *)packet_data;

  /* reset payload_packet_len, will be set if ipv4 tcp or udp */
  packet->payload = NULL;
  packet->payload_packet_len = 0;
  packet->l3_packet_len = packetlen;

  packet->tcp = NULL, packet->udp = NULL;
  packet->generic_l4_ptr = NULL;
  packet->iphv6 = NULL;

  l3len = packet->l3_packet_len;

  ndpi_reset_packet_line_info(packet);
  packet->packet_lines_parsed_complete = 0;
  packet->http_check_content = 0;

  if(packet->iph != NULL)
    decaps_iph = packet->iph;

  if(decaps_iph && decaps_iph->version == IPVERSION && decaps_iph->ihl >= 5) {
    NDPI_LOG_DBG2(ndpi_str, "ipv4 header\n");
  } else if(decaps_iph && decaps_iph->version == 6 && l3len >= sizeof(struct ndpi_ipv6hdr) &&
	    (ndpi_str->ip_version_limit & NDPI_DETECTION_ONLY_IPV4) == 0) {
    NDPI_LOG_DBG2(ndpi_str, "ipv6 header\n");
    packet->iphv6 = (struct ndpi_ipv6hdr *)packet->iph;
    packet->iph = NULL;
  } else {
    packet->iph = NULL;
    return(1);
  }

  /* needed:
   *  - unfragmented packets
   *  - ip header <= packet len
   *  - ip total length >= packet len
   */

  l4ptr = NULL;
  l4len = 0;
  l4protocol = 0;

  l4_result =
    ndpi_detection_get_l4_internal(ndpi_str, (const u_int8_t *) decaps_iph, l3len, &l4ptr, &l4len, &l4protocol, 0);

  if(l4_result != 0) {
    return(1);
  }

  l4_packet_len = l4len;
  flow->l4_proto = l4protocol;

  /* TCP / UDP detection */
  if(l4protocol == IPPROTO_TCP) {
    if(l4_packet_len < 20 /* min size of tcp */)
      return(1);

    /* tcp */
    packet->tcp = (struct ndpi_tcphdr *) l4ptr;
    if(l4_packet_len >= packet->tcp->doff * 4) {
      packet->payload_packet_len = l4_packet_len - packet->tcp->doff * 4;
      packet->payload = ((u_int8_t *) packet->tcp) + (packet->tcp->doff * 4);

      /* check for new tcp syn packets, here
       * idea: reset detection state if a connection is unknown
       */
      if(packet->tcp->syn != 0 && packet->tcp->ack == 0 && flow->init_finished != 0 &&
	 flow->detected_protocol_stack[0] == NDPI_PROTOCOL_UNKNOWN) {
	u_int16_t guessed_protocol_id, guessed_protocol_id_by_ip;
	u_int16_t packet_direction_counter[2];
        u_int8_t num_processed_pkts;

#define flow_save(a) a = flow->a
#define flow_restore(a) flow->a = a

	flow_save(packet_direction_counter[0]);
	flow_save(packet_direction_counter[1]);
	flow_save(num_processed_pkts);
	flow_save(guessed_protocol_id);
	flow_save(guessed_protocol_id_by_ip);

        ndpi_free_flow_data(flow);
        memset(flow, 0, sizeof(*(flow)));

        /* Restore pointers */
        flow->l4_proto = IPPROTO_TCP;

	flow_restore(packet_direction_counter[0]);
	flow_restore(packet_direction_counter[1]);
	flow_restore(num_processed_pkts);
	flow_restore(guessed_protocol_id);
	flow_restore(guessed_protocol_id_by_ip);

#undef flow_save
#undef flow_restore

        NDPI_LOG_DBG(ndpi_str, "tcp syn packet for unknown protocol, reset detection state\n");
      }
    } else {
      /* tcp header not complete */
      return(1);
    }
  } else if(l4protocol == IPPROTO_UDP) {
    if(l4_packet_len < 8 /* size of udp */)
      return(1);
    packet->udp = (struct ndpi_udphdr *) l4ptr;
    packet->payload_packet_len = l4_packet_len - 8;
    packet->payload = ((u_int8_t *) packet->udp) + 8;
  } else if((l4protocol == IPPROTO_ICMP) || (l4protocol == IPPROTO_ICMPV6)) {
    if((l4protocol == IPPROTO_ICMP && l4_packet_len < sizeof(struct ndpi_icmphdr)) ||
       (l4protocol == IPPROTO_ICMPV6 && l4_packet_len < sizeof(struct ndpi_icmp6hdr)))
      return(1);
    packet->payload = ((u_int8_t *) l4ptr);
    packet->payload_packet_len = l4_packet_len;
  } else {
    packet->generic_l4_ptr = l4ptr;
  }

  return(0);
}

void ndpi_exit_detection_module(struct ndpi_detection_module_struct *ndpi_str) {
  if(ndpi_str != NULL) {
    int i;

    for (i = 0; i < (NDPI_MAX_SUPPORTED_PROTOCOLS + NDPI_MAX_NUM_CUSTOM_PROTOCOLS); i++) {
      if(ndpi_str->proto_defaults[i].protoName)
        ndpi_free(ndpi_str->proto_defaults[i].protoName);
      if(ndpi_str->proto_defaults[i].subprotocols != NULL)
        ndpi_free(ndpi_str->proto_defaults[i].subprotocols);
    }

#ifdef HAVE_NBPF
    for(i = 0; (i < MAX_NBPF_CUSTOM_PROTO) && (ndpi_str->nbpf_custom_proto[i].tree != NULL); i++)
      nbpf_free(ndpi_str->nbpf_custom_proto[i].tree);
#endif

    /* NDPI_PROTOCOL_TINC */
    if(ndpi_str->tinc_cache)
      cache_free((cache_t)(ndpi_str->tinc_cache));

    if(ndpi_str->ookla_cache)
      ndpi_lru_free_cache(ndpi_str->ookla_cache);

    if(ndpi_str->bittorrent_cache)
      ndpi_lru_free_cache(ndpi_str->bittorrent_cache);

    if(ndpi_str->zoom_cache)
      ndpi_lru_free_cache(ndpi_str->zoom_cache);

    if(ndpi_str->stun_cache)
      ndpi_lru_free_cache(ndpi_str->stun_cache);

    if(ndpi_str->stun_zoom_cache)
      ndpi_lru_free_cache(ndpi_str->stun_zoom_cache);

    if(ndpi_str->tls_cert_cache)
      ndpi_lru_free_cache(ndpi_str->tls_cert_cache);

    if(ndpi_str->mining_cache)
      ndpi_lru_free_cache(ndpi_str->mining_cache);

    if(ndpi_str->msteams_cache)
      ndpi_lru_free_cache(ndpi_str->msteams_cache);

    if(ndpi_str->protocols_ptree)
      ndpi_patricia_destroy((ndpi_patricia_tree_t *) ndpi_str->protocols_ptree, free_ptree_data);

    if(ndpi_str->ip_risk_mask_ptree)
      ndpi_patricia_destroy((ndpi_patricia_tree_t *) ndpi_str->ip_risk_mask_ptree, free_ptree_data);

    if(ndpi_str->ip_risk_ptree)
      ndpi_patricia_destroy((ndpi_patricia_tree_t *) ndpi_str->ip_risk_ptree, free_ptree_data);

    if(ndpi_str->udpRoot != NULL) ndpi_tdestroy(ndpi_str->udpRoot, ndpi_free);
    if(ndpi_str->tcpRoot != NULL) ndpi_tdestroy(ndpi_str->tcpRoot, ndpi_free);

    if(ndpi_str->host_automa.ac_automa != NULL)
      ac_automata_release((AC_AUTOMATA_t *) ndpi_str->host_automa.ac_automa,
			  1 /* free patterns strings memory */);

    if(ndpi_str->risky_domain_automa.ac_automa != NULL)
      ac_automata_release((AC_AUTOMATA_t *) ndpi_str->risky_domain_automa.ac_automa,
                          1 /* free patterns strings memory */);

    if(ndpi_str->tls_cert_subject_automa.ac_automa != NULL)
      ac_automata_release((AC_AUTOMATA_t *) ndpi_str->tls_cert_subject_automa.ac_automa, 0);

    if(ndpi_str->malicious_ja3_hashmap != NULL)
      ndpi_hash_free(&ndpi_str->malicious_ja3_hashmap, NULL);

    if(ndpi_str->malicious_sha1_hashmap != NULL)
      ndpi_hash_free(&ndpi_str->malicious_sha1_hashmap, NULL);

    if(ndpi_str->custom_categories.hostnames.ac_automa != NULL)
      ac_automata_release((AC_AUTOMATA_t *) ndpi_str->custom_categories.hostnames.ac_automa,
			  1 /* free patterns strings memory */);

    if(ndpi_str->custom_categories.hostnames_shadow.ac_automa != NULL)
      ac_automata_release((AC_AUTOMATA_t *) ndpi_str->custom_categories.hostnames_shadow.ac_automa,
			  1 /* free patterns strings memory */);

    if(ndpi_str->custom_categories.ipAddresses != NULL)
      ndpi_patricia_destroy((ndpi_patricia_tree_t *) ndpi_str->custom_categories.ipAddresses, free_ptree_data);

    if(ndpi_str->custom_categories.ipAddresses_shadow != NULL)
      ndpi_patricia_destroy((ndpi_patricia_tree_t *) ndpi_str->custom_categories.ipAddresses_shadow, free_ptree_data);

    if(ndpi_str->host_risk_mask_automa.ac_automa != NULL)
      ac_automata_release((AC_AUTOMATA_t *) ndpi_str->host_risk_mask_automa.ac_automa,
			  1 /* free patterns strings memory */);

    if(ndpi_str->common_alpns_automa.ac_automa != NULL)
      ac_automata_release((AC_AUTOMATA_t *) ndpi_str->common_alpns_automa.ac_automa,
			  1 /* free patterns strings memory */);

    if(ndpi_str->trusted_issuer_dn) {
      ndpi_list *head = ndpi_str->trusted_issuer_dn;

      while(head != NULL) {
	ndpi_list *next;

	if(head->value) ndpi_free(head->value);
	next = head->next;
	ndpi_free(head);
	head = next;
      }
    }

#ifdef CUSTOM_NDPI_PROTOCOLS
#include "../../../nDPI-custom/ndpi_exit_detection_module.c"
#endif

    ndpi_free_geoip(ndpi_str);

    if(ndpi_str->callback_buffer)
	    ndpi_free(ndpi_str->callback_buffer);
    if(ndpi_str->callback_buffer_tcp_payload)
	    ndpi_free(ndpi_str->callback_buffer_tcp_payload);
    ndpi_free(ndpi_str);
  }
}

static int category_depends_on_master(int proto)
{
  switch(proto) {
  case NDPI_PROTOCOL_MAIL_POP:
  case NDPI_PROTOCOL_MAIL_SMTP:
  case NDPI_PROTOCOL_MAIL_IMAP:
  case NDPI_PROTOCOL_MAIL_POPS:
  case NDPI_PROTOCOL_MAIL_SMTPS:
  case NDPI_PROTOCOL_MAIL_IMAPS:
  case NDPI_PROTOCOL_DNS:
	  return 1;
  }
  return 0;
}

struct ndpi_detection_module_struct *ndpi_init_detection_module(ndpi_init_prefs prefs) {
  struct ndpi_detection_module_struct *ndpi_str = ndpi_malloc(sizeof(struct ndpi_detection_module_struct));
  int i;

  if(ndpi_str == NULL) {
    /* Logging this error is a bit tricky. At this point, we can't use NDPI_LOG*
       functions yet, we don't have a custom log function and, as a library,
       we shouldn't use stdout/stderr. Since this error is quite unlikely,
       simply avoid any logs at all */
    return(NULL);
  }

  memset(ndpi_str, 0, sizeof(struct ndpi_detection_module_struct));

#ifdef NDPI_ENABLE_DEBUG_MESSAGES
  set_ndpi_debug_function(ndpi_str, (ndpi_debug_function_ptr) ndpi_debug_printf);
  NDPI_BITMASK_RESET(ndpi_str->debug_bitmask);
#endif /* NDPI_ENABLE_DEBUG_MESSAGES */

  if(prefs & ndpi_enable_ja3_plus)
    ndpi_str->enable_ja3_plus = 1;

  if(!(prefs & ndpi_dont_init_libgcrypt)) {
    printc("unsupport libgcrypt\n");
    assert(0);
  } else {
    NDPI_LOG_DBG(ndpi_str, "Libgcrypt initialization skipped\n");
  }

  if((ndpi_str->protocols_ptree = ndpi_patricia_new(32 /* IPv4 */)) != NULL) {
//     ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->protocols_ptree, host_protocol_list);

//     if(!(prefs & ndpi_dont_load_cachefly_list))
//       ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->protocols_ptree, ndpi_protocol_cachefly_protocol_list);

//     if(!(prefs & ndpi_dont_load_tor_list))
//       ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->protocols_ptree, ndpi_protocol_tor_protocol_list);

//     if(!(prefs & ndpi_dont_load_azure_list))
//       ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->protocols_ptree, ndpi_protocol_microsoft_azure_protocol_list);

//     if(!(prefs & ndpi_dont_load_whatsapp_list))
//       ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->protocols_ptree, ndpi_protocol_whatsapp_protocol_list);

//     if(!(prefs & ndpi_dont_load_amazon_aws_list))
//       ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->protocols_ptree, ndpi_protocol_amazon_aws_protocol_list);

//     if(!(prefs & ndpi_dont_load_ethereum_list))
//       ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->protocols_ptree, ndpi_protocol_mining_protocol_list);

//     if(!(prefs & ndpi_dont_load_zoom_list))
//       ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->protocols_ptree, ndpi_protocol_zoom_protocol_list);

//     if(!(prefs & ndpi_dont_load_cloudflare_list))
//       ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->protocols_ptree, ndpi_protocol_cloudflare_protocol_list);

//     if(!(prefs & ndpi_dont_load_microsoft_list)) {
//       ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->protocols_ptree, ndpi_protocol_microsoft_365_protocol_list);
//       ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->protocols_ptree, ndpi_protocol_ms_one_drive_protocol_list);
//       ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->protocols_ptree, ndpi_protocol_ms_outlook_protocol_list);
//       ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->protocols_ptree, ndpi_protocol_skype_teams_protocol_list);
//     }

//     if(!(prefs & ndpi_dont_load_google_list))
//       ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->protocols_ptree, ndpi_protocol_google_protocol_list);

//     if(!(prefs & ndpi_dont_load_google_cloud_list))
//       ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->protocols_ptree, ndpi_protocol_google_cloud_protocol_list);

//     if(!(prefs & ndpi_dont_load_asn_lists)) {
//       ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->protocols_ptree, ndpi_protocol_telegram_protocol_list);
//       ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->protocols_ptree, ndpi_protocol_apple_protocol_list);
//       ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->protocols_ptree, ndpi_protocol_twitter_protocol_list);
//       ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->protocols_ptree, ndpi_protocol_netflix_protocol_list);
//       ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->protocols_ptree, ndpi_protocol_webex_protocol_list);
//       ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->protocols_ptree, ndpi_protocol_teamviewer_protocol_list);
//       ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->protocols_ptree, ndpi_protocol_facebook_protocol_list);
//       ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->protocols_ptree, ndpi_protocol_tencent_protocol_list);
//       ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->protocols_ptree, ndpi_protocol_opendns_protocol_list);
//       ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->protocols_ptree, ndpi_protocol_dropbox_protocol_list);
//       ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->protocols_ptree, ndpi_protocol_starcraft_protocol_list);
//       ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->protocols_ptree, ndpi_protocol_ubuntuone_protocol_list);
//       ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->protocols_ptree, ndpi_protocol_twitch_protocol_list);
//       ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->protocols_ptree, ndpi_protocol_hotspot_shield_protocol_list);
//       ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->protocols_ptree, ndpi_protocol_github_protocol_list);
//       ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->protocols_ptree, ndpi_protocol_steam_protocol_list);
//       ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->protocols_ptree, ndpi_protocol_bloomberg_protocol_list);
//       ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->protocols_ptree, ndpi_protocol_citrix_protocol_list);
//       ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->protocols_ptree, ndpi_protocol_edgecast_protocol_list);
//       ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->protocols_ptree, ndpi_protocol_goto_protocol_list);
//       ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->protocols_ptree, ndpi_protocol_riotgames_protocol_list);
//       ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->protocols_ptree, ndpi_protocol_threema_protocol_list);
//       ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->protocols_ptree, ndpi_protocol_alibaba_protocol_list);
//       ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->protocols_ptree, ndpi_protocol_avast_protocol_list);
//       ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->protocols_ptree, ndpi_protocol_discord_protocol_list);
//       ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->protocols_ptree, ndpi_protocol_line_protocol_list);
//     }

    if(prefs & ndpi_track_flow_payload)
      ndpi_str->max_payload_track_len = 1024; /* track up to X payload bytes */
  }

  ndpi_str->ip_risk_mask_ptree = ndpi_patricia_new(32 /* IPv4 */);

  if(!(prefs & ndpi_dont_init_risk_ptree)) {
    if((ndpi_str->ip_risk_ptree = ndpi_patricia_new(32 /* IPv4 */)) != NULL) {
      if(!(prefs & ndpi_dont_load_icloud_private_relay_list)) {
        // ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->ip_risk_ptree, ndpi_anonymous_subscriber_protocol_list);
      }
    }
  }

  ndpi_str->max_packets_to_process = NDPI_DEFAULT_MAX_NUM_PKTS_PER_FLOW_TO_DISSECT;

  NDPI_BITMASK_SET_ALL(ndpi_str->detection_bitmask);
#ifdef NDPI_ENABLE_DEBUG_MESSAGES
  ndpi_str->user_data = NULL;
#endif

  ndpi_str->tcp_max_retransmission_window_size = NDPI_DEFAULT_MAX_TCP_RETRANSMISSION_WINDOW_SIZE;
  ndpi_str->tls_certificate_expire_in_x_days = 30; /* NDPI_TLS_CERTIFICATE_ABOUT_TO_EXPIRE flow risk */

  ndpi_str->ndpi_num_supported_protocols = NDPI_MAX_SUPPORTED_PROTOCOLS;
  ndpi_str->ndpi_num_custom_protocols = 0;

  ndpi_str->host_automa.ac_automa = ac_automata_init(ac_domain_match_handler);
  if(!ndpi_str->host_automa.ac_automa) {
    ndpi_exit_detection_module(ndpi_str);
    return(NULL);
  }
  ndpi_str->host_risk_mask_automa.ac_automa = ac_automata_init(ac_domain_match_handler);
  if(!ndpi_str->host_risk_mask_automa.ac_automa) {
    ndpi_exit_detection_module(ndpi_str);
    return(NULL);
  }
  ndpi_str->common_alpns_automa.ac_automa = ac_automata_init(ac_domain_match_handler);
  if(!ndpi_str->common_alpns_automa.ac_automa) {
    ndpi_exit_detection_module(ndpi_str);
    return(NULL);
  }
  load_common_alpns(ndpi_str);
  ndpi_str->tls_cert_subject_automa.ac_automa = ac_automata_init(NULL);
  if(!ndpi_str->tls_cert_subject_automa.ac_automa) {
    ndpi_exit_detection_module(ndpi_str);
    return(NULL);
  }
  ndpi_str->malicious_ja3_hashmap = NULL; /* Initialized on demand */
  ndpi_str->malicious_sha1_hashmap = NULL; /* Initialized on demand */
  ndpi_str->risky_domain_automa.ac_automa = NULL; /* Initialized on demand */
  ndpi_str->trusted_issuer_dn = NULL;

  ndpi_str->custom_categories.hostnames.ac_automa = ac_automata_init(ac_domain_match_handler);
  if(!ndpi_str->custom_categories.hostnames.ac_automa) {
    ndpi_exit_detection_module(ndpi_str);
    return(NULL);
  }
  ndpi_str->custom_categories.hostnames_shadow.ac_automa = ac_automata_init(ac_domain_match_handler);
  if(!ndpi_str->custom_categories.hostnames_shadow.ac_automa) {
    ndpi_exit_detection_module(ndpi_str);
    return(NULL);
  }

  ndpi_str->custom_categories.ipAddresses = ndpi_patricia_new(32 /* IPv4 */);
  ndpi_str->custom_categories.ipAddresses_shadow = ndpi_patricia_new(32 /* IPv4 */);

  if(ndpi_str->host_automa.ac_automa)
    ac_automata_feature(ndpi_str->host_automa.ac_automa,AC_FEATURE_LC);

  if(ndpi_str->custom_categories.hostnames.ac_automa)
    ac_automata_feature(ndpi_str->custom_categories.hostnames.ac_automa,AC_FEATURE_LC);

  if(ndpi_str->custom_categories.hostnames_shadow.ac_automa)
    ac_automata_feature(ndpi_str->custom_categories.hostnames_shadow.ac_automa,AC_FEATURE_LC);

  if(ndpi_str->tls_cert_subject_automa.ac_automa)
    ac_automata_feature(ndpi_str->tls_cert_subject_automa.ac_automa,AC_FEATURE_LC);

  if(ndpi_str->host_risk_mask_automa.ac_automa)
    ac_automata_feature(ndpi_str->host_risk_mask_automa.ac_automa,AC_FEATURE_LC);

  if(ndpi_str->common_alpns_automa.ac_automa)
    ac_automata_feature(ndpi_str->common_alpns_automa.ac_automa,AC_FEATURE_LC);

  /* ahocorasick debug */
  /* Needed ac_automata_enable_debug(1) for show debug */
  if(ndpi_str->host_automa.ac_automa)
    ac_automata_name(ndpi_str->host_automa.ac_automa,"host",AC_FEATURE_DEBUG);

  if(ndpi_str->custom_categories.hostnames.ac_automa)
    ac_automata_name(ndpi_str->custom_categories.hostnames.ac_automa,"ccat",0);

  if(ndpi_str->custom_categories.hostnames_shadow.ac_automa)
    ac_automata_name(ndpi_str->custom_categories.hostnames_shadow.ac_automa,"ccat_sh",0);

  if(ndpi_str->tls_cert_subject_automa.ac_automa)
    ac_automata_name(ndpi_str->tls_cert_subject_automa.ac_automa,"tls_cert",AC_FEATURE_DEBUG);

  if(ndpi_str->host_risk_mask_automa.ac_automa)
    ac_automata_name(ndpi_str->host_risk_mask_automa.ac_automa,"content",AC_FEATURE_DEBUG);

  if(ndpi_str->common_alpns_automa.ac_automa)
    ac_automata_name(ndpi_str->common_alpns_automa.ac_automa,"content",AC_FEATURE_DEBUG);

  if((ndpi_str->custom_categories.ipAddresses == NULL) || (ndpi_str->custom_categories.ipAddresses_shadow == NULL)) {
    NDPI_LOG_ERR(ndpi_str, "[NDPI] Error allocating Patricia trees\n");
    ndpi_exit_detection_module(ndpi_str);
    return(NULL);
  }

  ndpi_str->ookla_cache_num_entries = 1024;
  ndpi_str->bittorrent_cache_num_entries = 32768;
  ndpi_str->zoom_cache_num_entries = 512;
  ndpi_str->stun_cache_num_entries = 1024;
  ndpi_str->tls_cert_cache_num_entries = 1024;
  ndpi_str->mining_cache_num_entries = 1024;
  ndpi_str->msteams_cache_num_entries = 1024;
  ndpi_str->stun_zoom_cache_num_entries = 1024;

  ndpi_str->ookla_cache_ttl = 0;
  ndpi_str->bittorrent_cache_ttl = 0;
  ndpi_str->zoom_cache_ttl = 0;
  ndpi_str->stun_cache_ttl = 0;
  ndpi_str->tls_cert_cache_ttl = 0;
  ndpi_str->mining_cache_ttl = 0;
  ndpi_str->msteams_cache_ttl = 60; /* sec */
  ndpi_str->stun_zoom_cache_ttl = 60; /* sec */

  ndpi_str->opportunistic_tls_smtp_enabled = 1;
  ndpi_str->opportunistic_tls_imap_enabled = 1;
  ndpi_str->opportunistic_tls_pop_enabled = 1;
  ndpi_str->opportunistic_tls_ftp_enabled = 1;

  for(i = 0; i < NUM_CUSTOM_CATEGORIES; i++)
    ndpi_snprintf(ndpi_str->custom_category_labels[i], CUSTOM_CATEGORY_LABEL_LEN, "User custom category %u",
	     (unsigned int) (i + 1));

  return(ndpi_str);
}

ndpi_protocol ndpi_detection_process_packet(struct ndpi_detection_module_struct *ndpi_str,
					    struct ndpi_flow_struct *flow, const unsigned char *packet_data,
					    const unsigned short packetlen, const u_int64_t current_time_ms,
					    const struct ndpi_flow_input_info *input_info) {
  struct ndpi_packet_struct *packet;
  NDPI_SELECTION_BITMASK_PROTOCOL_SIZE ndpi_selection_packet;
  u_int32_t num_calls = 0;
  ndpi_protocol ret;

  memset(&ret, 0, sizeof(ret));

  if(!flow || !ndpi_str)
    return(ret);

  packet = &ndpi_str->packet;

  NDPI_LOG_DBG(ndpi_str, "[%d/%d] START packet processing\n",
               flow->detected_protocol_stack[0], flow->detected_protocol_stack[1]);

  ret.master_protocol = flow->detected_protocol_stack[1],
  ret.app_protocol = flow->detected_protocol_stack[0];
  ret.protocol_by_ip = flow->guessed_protocol_id_by_ip;
  ret.category = flow->category;

  if(flow->fail_with_unknown) {
    // printf("%s(): FAIL_WITH_UNKNOWN\n", __FUNCTION__);
    return(ret);
  }

  if(ndpi_str->max_packets_to_process > 0 && flow->num_processed_pkts >= ndpi_str->max_packets_to_process) {
    flow->extra_packets_func = NULL; /* To allow ndpi_extra_dissection_possible() to fail */
    flow->fail_with_unknown = 1;
    return(ret); /* Avoid spending too much time with this flow */
  }

  flow->num_processed_pkts++;

  /* Init default */

  if(flow->extra_packets_func) {
    ndpi_process_extra_packet(ndpi_str, flow, packet_data, packetlen, current_time_ms, input_info);
    /* Update in case of new match */
    ret.master_protocol = flow->detected_protocol_stack[1],
      ret.app_protocol = flow->detected_protocol_stack[0],
      ret.category = flow->category;

    return ret;
  } else if(flow->detected_protocol_stack[0] != NDPI_PROTOCOL_UNKNOWN) {
    if(ndpi_init_packet(ndpi_str, flow, current_time_ms, packet_data, packetlen, input_info) != 0)
      return ret;

    goto ret_protocols;
  }

  if(ndpi_init_packet(ndpi_str, flow, current_time_ms, packet_data, packetlen, input_info) != 0)
    return ret;

#ifdef HAVE_NBPF
  if((flow->num_processed_pkts == 1) /* first packet of this flow to be analyzed */
     && (ndpi_str->nbpf_custom_proto[0].tree != NULL)) {
    u_int8_t i;
    nbpf_pkt_info_t t;

    memset(&t, 0, sizeof(t));

    if(packet->iphv6 != NULL) {
      t.tuple.eth_type = 0x86DD;
      t.tuple.ip_version = 6;
      memcpy(&t.tuple.ip_src.v6, &packet->iphv6->ip6_src, 16);
      memcpy(&t.tuple.ip_dst.v6, &packet->iphv6->ip6_dst, 16);
    } else {
      t.tuple.eth_type = 0x0800;
      t.tuple.ip_version = 4;
      t.tuple.ip_src.v4 = packet->iph->saddr;
      t.tuple.ip_dst.v4 = packet->iph->daddr;
    }

    t.tuple.l3_proto = flow->l4_proto;

    if(packet->tcp)
      t.tuple.l4_src_port = packet->tcp->source, t.tuple.l4_dst_port = packet->tcp->dest;
    else if(packet->udp)
      t.tuple.l4_src_port = packet->udp->source, t.tuple.l4_dst_port = packet->udp->dest;

    for(i=0; (i<MAX_NBPF_CUSTOM_PROTO) && (ndpi_str->nbpf_custom_proto[i].tree != NULL); i++) {
      if(nbpf_match(ndpi_str->nbpf_custom_proto[i].tree, &t)) {
	/* match found */
	ret.master_protocol = ret.app_protocol = ndpi_str->nbpf_custom_proto[i].l7_protocol;
	ndpi_fill_protocol_category(ndpi_str, flow, &ret);
	ndpi_reconcile_protocols(ndpi_str, flow, &ret);
	flow->confidence = NDPI_CONFIDENCE_NBPF;

	return(ret);
      }
    }
  }
#endif

  ndpi_connection_tracking(ndpi_str, flow);

  /* build ndpi_selection packet bitmask */
  ndpi_selection_packet = NDPI_SELECTION_BITMASK_PROTOCOL_COMPLETE_TRAFFIC;
  if(packet->iph != NULL)
    ndpi_selection_packet |= NDPI_SELECTION_BITMASK_PROTOCOL_IP | NDPI_SELECTION_BITMASK_PROTOCOL_IPV4_OR_IPV6;

  if(packet->tcp != NULL)
    ndpi_selection_packet |=
      (NDPI_SELECTION_BITMASK_PROTOCOL_INT_TCP | NDPI_SELECTION_BITMASK_PROTOCOL_INT_TCP_OR_UDP);

  if(packet->udp != NULL)
    ndpi_selection_packet |=
      (NDPI_SELECTION_BITMASK_PROTOCOL_INT_UDP | NDPI_SELECTION_BITMASK_PROTOCOL_INT_TCP_OR_UDP);

  if(packet->payload_packet_len != 0)
    ndpi_selection_packet |= NDPI_SELECTION_BITMASK_PROTOCOL_HAS_PAYLOAD;

  if(packet->tcp_retransmission == 0)
    ndpi_selection_packet |= NDPI_SELECTION_BITMASK_PROTOCOL_NO_TCP_RETRANSMISSION;

  if(packet->iphv6 != NULL)
    ndpi_selection_packet |= NDPI_SELECTION_BITMASK_PROTOCOL_IPV6 | NDPI_SELECTION_BITMASK_PROTOCOL_IPV4_OR_IPV6;

  if(!flow->protocol_id_already_guessed) {
    flow->protocol_id_already_guessed = 1;

    if(ndpi_do_guess(ndpi_str, flow, &ret) == -1)
      return ret;
  }

  num_calls = ndpi_check_flow_func(ndpi_str, flow, &ndpi_selection_packet);

 ret_protocols:
  if(flow->detected_protocol_stack[1] != NDPI_PROTOCOL_UNKNOWN) {
    ret.master_protocol = flow->detected_protocol_stack[1], ret.app_protocol = flow->detected_protocol_stack[0];

    if(ret.app_protocol == ret.master_protocol)
      ret.master_protocol = NDPI_PROTOCOL_UNKNOWN;
  } else
    ret.app_protocol = flow->detected_protocol_stack[0];

  /* Don't overwrite the category if already set */
  if((flow->category == NDPI_PROTOCOL_CATEGORY_UNSPECIFIED) && (ret.app_protocol != NDPI_PROTOCOL_UNKNOWN))
    ndpi_fill_protocol_category(ndpi_str, flow, &ret);
  else
    ret.category = flow->category;

  if((flow->num_processed_pkts == 1) /* first packet of this flow to be analyzed */
     && (ret.master_protocol == NDPI_PROTOCOL_UNKNOWN)
     && (ret.app_protocol == NDPI_PROTOCOL_UNKNOWN) && packet->tcp && (packet->tcp->syn == 0)
     && (flow->guessed_protocol_id == 0)) {
    u_int8_t protocol_was_guessed;

    /*
      This is a TCP flow
      - whose first packet is NOT a SYN
      - no protocol has been detected

      We don't see how future packets can match anything
      hence we giveup here
    */
    ret = ndpi_detection_giveup(ndpi_str, flow, 0, &protocol_was_guessed);
  }

  if((!flow->risk_checked)
     && ((ret.master_protocol != NDPI_PROTOCOL_UNKNOWN) || (ret.app_protocol != NDPI_PROTOCOL_UNKNOWN))
     ) {
    ndpi_default_ports_tree_node_t *found;
    u_int16_t *default_ports;

    if(packet->udp)
      found = ndpi_get_guessed_protocol_id(ndpi_str, IPPROTO_UDP,
					   ntohs(flow->c_port),
					   ntohs(flow->s_port)),
	default_ports = ndpi_str->proto_defaults[ret.master_protocol ? ret.master_protocol : ret.app_protocol].udp_default_ports;
    else if(packet->tcp)
      found = ndpi_get_guessed_protocol_id(ndpi_str, IPPROTO_TCP,
					   ntohs(flow->c_port),
					   ntohs(flow->s_port)),
	default_ports = ndpi_str->proto_defaults[ret.master_protocol ? ret.master_protocol : ret.app_protocol].tcp_default_ports;
    else
      found = NULL, default_ports = NULL;

    if(found
       && (found->proto->protoId != NDPI_PROTOCOL_UNKNOWN)
       && (found->proto->protoId != ret.master_protocol)
       && (found->proto->protoId != ret.app_protocol)
       ) {
      // printf("******** %u / %u\n", found->proto->protoId, ret.master_protocol);

      if(!ndpi_check_protocol_port_mismatch_exceptions(ndpi_str, flow, found, &ret)) {
	/*
	  Before triggering the alert we need to make some extra checks
	  - the protocol found is not running on the port we have found
	  (i.e. two or more protools share the same default port)
	*/
	u_int8_t found = 0, i;

	for(i=0; (i<MAX_DEFAULT_PORTS) && (default_ports[i] != 0); i++) {
	  if(default_ports[i] == ntohs(flow->s_port)) {
	    found = 1;
	    break;
	  }
	} /* for */

	if(!found) {
	  ndpi_default_ports_tree_node_t *r = ndpi_get_guessed_protocol_id(ndpi_str, packet->udp ? IPPROTO_UDP : IPPROTO_TCP,
									   ntohs(flow->c_port), ntohs(flow->s_port));

	  if((r == NULL)
	     || ((r->proto->protoId != ret.app_protocol) && (r->proto->protoId != ret.master_protocol))) {
	    if(default_ports[0] != 0) {
		char str[64];
		u_int8_t i, offset;

		offset = snprintf(str, sizeof(str), "Expected on port ");

		for(i=0; (i<MAX_DEFAULT_PORTS) && (default_ports[i] != 0); i++) {
		  int rc = snprintf(&str[offset], sizeof(str)-offset, "%s%u",
				    (i > 0) ? "," : "", default_ports[i]);

		  if(rc > 0)
		    offset += rc;
		  else
		    break;
		}

		str[offset] = '\0';
		ndpi_set_risk(ndpi_str, flow, NDPI_KNOWN_PROTOCOL_ON_NON_STANDARD_PORT, str);
	    }
	  }
	}
      }
    } else if((!ndpi_is_ntop_protocol(&ret)) && default_ports && (default_ports[0] != 0)) {
      u_int8_t found = 0, i, num_loops = 0;

    check_default_ports:
      for(i=0; (i<MAX_DEFAULT_PORTS) && (default_ports[i] != 0); i++) {
	if((default_ports[i] == ntohs(flow->c_port)) || (default_ports[i] == ntohs(flow->s_port))) {
	  found = 1;
	  break;
	}
      } /* for */

      if((num_loops == 0) && (!found)) {
	if(packet->udp)
	  default_ports = ndpi_str->proto_defaults[ret.app_protocol].udp_default_ports;
	else
	  default_ports = ndpi_str->proto_defaults[ret.app_protocol].tcp_default_ports;

	num_loops = 1;
	goto check_default_ports;
      }

      if(!found) {
	ndpi_default_ports_tree_node_t *r = ndpi_get_guessed_protocol_id(ndpi_str, packet->udp ? IPPROTO_UDP : IPPROTO_TCP,
									   ntohs(flow->c_port), ntohs(flow->s_port));

	if((r == NULL)
	   || ((r->proto->protoId != ret.app_protocol) && (r->proto->protoId != ret.master_protocol)))
	  ndpi_set_risk(ndpi_str, flow, NDPI_KNOWN_PROTOCOL_ON_NON_STANDARD_PORT,NULL);
      }
    }

    flow->risk_checked = 1;
  }
  if(!flow->tree_risk_checked) {
    if(ndpi_str->ip_risk_ptree) {
      /* TODO: ipv6 */
      if(packet->iph &&
         ndpi_is_public_ipv4(ntohl(packet->iph->saddr)) &&
         ndpi_is_public_ipv4(ntohl(packet->iph->daddr))) {
        struct in_addr addr;
        ndpi_risk_enum net_risk;

        addr.s_addr = packet->iph->saddr;
        net_risk = ndpi_network_risk_ptree_match(ndpi_str, &addr);
        if(net_risk == NDPI_NO_RISK) {
          addr.s_addr = packet->iph->daddr;
          net_risk = ndpi_network_risk_ptree_match(ndpi_str, &addr);
        }

        if(net_risk != NDPI_NO_RISK)
          ndpi_set_risk(ndpi_str, flow, net_risk, NULL);
      }
    }
    flow->tree_risk_checked = 1;
  }

  /* It is common to don't trigger any dissectors for pure TCP ACKs
     and for for retransmissions */
  if(num_calls == 0 &&
     (packet->tcp_retransmission == 0 && packet->payload_packet_len != 0))
    flow->fail_with_unknown = 1;
  flow->num_dissector_calls += num_calls;

  ndpi_reconcile_protocols(ndpi_str, flow, &ret);

  /* Zoom cache */
  if((ret.app_protocol == NDPI_PROTOCOL_ZOOM)
     && (flow->l4_proto == IPPROTO_TCP))
    ndpi_add_connection_as_zoom(ndpi_str, flow);

  return(ret);
}
void ndpi_process_extra_packet(struct ndpi_detection_module_struct *ndpi_str, struct ndpi_flow_struct *flow,
			       const unsigned char *packet_data, const unsigned short packetlen,
			       const u_int64_t current_time_ms,
			       const struct ndpi_flow_input_info *input_info) {
  if(flow == NULL)
    return;

  /* set up the packet headers for the extra packet function to use if it wants */
  if(ndpi_init_packet(ndpi_str, flow, current_time_ms, packet_data, packetlen, input_info) != 0)
    return;

  ndpi_connection_tracking(ndpi_str, flow);

  /* call the extra packet function (which may add more data/info to flow) */
  if(flow->extra_packets_func) {
    if((flow->extra_packets_func(ndpi_str, flow)) == 0)
      flow->extra_packets_func = NULL; /* Enough packets detected */

    if(++flow->num_extra_packets_checked == flow->max_extra_packets_to_check)
      flow->extra_packets_func = NULL; /* Enough packets detected */
  }
}
/* ***************************************************** */

struct ndpi_workflow *
ndpi_workflow_init(const struct ndpi_workflow_prefs *prefs) {
        set_ndpi_malloc(malloc_wrapper), set_ndpi_free(free_wrapper);
        set_ndpi_flow_malloc(NULL), set_ndpi_flow_free(NULL);

	ndpi_init_prefs init_prefs = 0;
	init_prefs |= ndpi_dont_load_tor_list | ndpi_dont_init_libgcrypt | ndpi_dont_load_azure_list | ndpi_dont_load_whatsapp_list
		| ndpi_dont_load_amazon_aws_list | ndpi_dont_load_ethereum_list | ndpi_dont_load_zoom_list | ndpi_dont_load_cloudflare_list
		| ndpi_dont_load_microsoft_list | ndpi_dont_load_google_list | ndpi_dont_load_google_cloud_list | ndpi_dont_load_asn_lists
		| ndpi_dont_load_icloud_private_relay_list | ndpi_dont_init_risk_ptree | ndpi_dont_load_cachefly_list;

	printc("@@@set up ndpi...\n");


        /* TODO: just needed here to init ndpi malloc wrapper */
        struct ndpi_detection_module_struct *module = ndpi_init_detection_module(init_prefs);

        struct ndpi_workflow *workflow = ndpi_calloc(1, sizeof(struct ndpi_workflow));

        // workflow->pcap_handle = pcap_handle;
        workflow->prefs = *prefs;
        workflow->ndpi_struct = module;

        if (workflow->ndpi_struct == NULL) {
                NDPI_LOG(0, NULL, NDPI_LOG_ERROR, "global structure initialization failed\n");
                exit(-1);
        }

        workflow->ndpi_flows_root = ndpi_calloc(workflow->prefs.num_roots, sizeof(void *));
        return workflow;
}

ndpi_protocol_category_t ndpi_get_proto_category(struct ndpi_detection_module_struct *ndpi_str,
						 ndpi_protocol proto) {
  if(proto.category != NDPI_PROTOCOL_CATEGORY_UNSPECIFIED)
    return(proto.category);

  /* Simple rule: sub protocol first, master after, with some exceptions (i.e. mail) */

  if(category_depends_on_master(proto.master_protocol)) {
    if(ndpi_is_valid_protoId(proto.master_protocol))
      return(ndpi_str->proto_defaults[proto.master_protocol].protoCategory);
  } else if((proto.master_protocol == NDPI_PROTOCOL_UNKNOWN) ||
	  (ndpi_str->proto_defaults[proto.app_protocol].protoCategory != NDPI_PROTOCOL_CATEGORY_UNSPECIFIED)) {
    if(ndpi_is_valid_protoId(proto.app_protocol))
      return(ndpi_str->proto_defaults[proto.app_protocol].protoCategory);
  } else if(ndpi_is_valid_protoId(proto.master_protocol))
    return(ndpi_str->proto_defaults[proto.master_protocol].protoCategory);

  return(NDPI_PROTOCOL_CATEGORY_UNSPECIFIED);
}

static void ndpi_free_flow_tls_data(struct ndpi_flow_info *flow) {

  if(flow->dhcp_fingerprint) {
    ndpi_free(flow->dhcp_fingerprint);
    flow->dhcp_fingerprint = NULL;
  }
  if(flow->dhcp_class_ident) {
    ndpi_free(flow->dhcp_class_ident);
    flow->dhcp_class_ident = NULL;
  }

  if(flow->bittorent_hash) {
    ndpi_free(flow->bittorent_hash);
    flow->bittorent_hash = NULL;
  }

  if(flow->telnet.username) {
    ndpi_free(flow->telnet.username);
    flow->telnet.username = NULL;
  }
  if(flow->telnet.password) {
    ndpi_free(flow->telnet.password);
    flow->telnet.password = NULL;
  }

  if(flow->ssh_tls.server_names) {
    ndpi_free(flow->ssh_tls.server_names);
    flow->ssh_tls.server_names = NULL;
  }

  if(flow->ssh_tls.advertised_alpns) {
    ndpi_free(flow->ssh_tls.advertised_alpns);
    flow->ssh_tls.advertised_alpns = NULL;
  }

  if(flow->ssh_tls.negotiated_alpn) {
    ndpi_free(flow->ssh_tls.negotiated_alpn);
    flow->ssh_tls.negotiated_alpn = NULL;
  }

  if(flow->ssh_tls.tls_supported_versions) {
    ndpi_free(flow->ssh_tls.tls_supported_versions);
    flow->ssh_tls.tls_supported_versions = NULL;
  }

  if(flow->ssh_tls.tls_issuerDN) {
    ndpi_free(flow->ssh_tls.tls_issuerDN);
    flow->ssh_tls.tls_issuerDN = NULL;
  }

  if(flow->ssh_tls.tls_subjectDN) {
    ndpi_free(flow->ssh_tls.tls_subjectDN);
    flow->ssh_tls.tls_subjectDN = NULL;
  }

  if(flow->ssh_tls.encrypted_sni.esni) {
    ndpi_free(flow->ssh_tls.encrypted_sni.esni);
    flow->ssh_tls.encrypted_sni.esni = NULL;
  }
}

void ndpi_free_flow_info_half(struct ndpi_flow_info *flow) {
  if(flow->ndpi_flow) { ndpi_flow_free(flow->ndpi_flow); flow->ndpi_flow = NULL; }
}

static void ndpi_free_flow_data_analysis(struct ndpi_flow_info *flow) {
  if(flow->iat_c_to_s) ndpi_free_data_analysis(flow->iat_c_to_s, 1);
  if(flow->iat_s_to_c) ndpi_free_data_analysis(flow->iat_s_to_c, 1);

  if(flow->pktlen_c_to_s) ndpi_free_data_analysis(flow->pktlen_c_to_s, 1);
  if(flow->pktlen_s_to_c) ndpi_free_data_analysis(flow->pktlen_s_to_c, 1);

  if(flow->iat_flow) ndpi_free_data_analysis(flow->iat_flow, 1);

  if(flow->entropy) ndpi_free(flow->entropy);
  if(flow->last_entropy) ndpi_free(flow->last_entropy);
}

void ndpi_flow_info_free_data(struct ndpi_flow_info *flow) {

  ndpi_free_flow_info_half(flow);
  ndpi_term_serializer(&flow->ndpi_flow_serializer);
  ndpi_free_flow_data_analysis(flow);
  ndpi_free_flow_tls_data(flow);

#ifdef DIRECTION_BINS
  ndpi_free_bin(&flow->payload_len_bin_src2dst);
  ndpi_free_bin(&flow->payload_len_bin_dst2src);
#else
  ndpi_free_bin(&flow->payload_len_bin);
#endif

  if(flow->risk_str)     ndpi_free(flow->risk_str);
  if(flow->flow_payload) ndpi_free(flow->flow_payload);
}

static struct ndpi_flow_info *get_ndpi_flow_info(struct ndpi_workflow * workflow,
						 const u_int8_t version,
						 u_int16_t vlan_id,
						 ndpi_packet_tunnel tunnel_type,
						 const struct ndpi_iphdr *iph,
						 const struct ndpi_ipv6hdr *iph6,
						 u_int16_t ip_offset,
						 u_int16_t ipsize,
						 u_int16_t l4_packet_len,
						 u_int16_t l4_offset,
						 struct ndpi_tcphdr **tcph,
						 struct ndpi_udphdr **udph,
						 u_int16_t *sport, u_int16_t *dport,
						 u_int8_t *proto,
						 u_int8_t **payload,
						 u_int16_t *payload_len,
						 u_int8_t *src_to_dst_direction,
                                                 pkt_timeval when) {
  u_int32_t idx, hashval;
  struct ndpi_flow_info flow;
  void *ret;
  const u_int8_t *l3, *l4;
  u_int32_t l4_data_len = 0XFEEDFACE;

  /*
    Note: to keep things simple (ndpiReader is just a demo app)
    we handle IPv6 a-la-IPv4.
  */
  if(version == IPVERSION) {
    if(ipsize < 20)
      return NULL;

    if((iph->ihl * 4) > ipsize || ipsize < ntohs(iph->tot_len)
       /* || (iph->frag_off & htons(0x1FFF)) != 0 */)
      return NULL;

    l3 = (const u_int8_t*)iph;
  } else {
    if(l4_offset > ipsize)
      return NULL;

    l3 = (const u_int8_t*)iph6;
  }
  if(ipsize < l4_offset + l4_packet_len)
    return NULL;

  *proto = iph->protocol;

  if(l4_packet_len < 64)
    workflow->stats.packet_len[0]++;
  else if(l4_packet_len >= 64 && l4_packet_len < 128)
    workflow->stats.packet_len[1]++;
  else if(l4_packet_len >= 128 && l4_packet_len < 256)
    workflow->stats.packet_len[2]++;
  else if(l4_packet_len >= 256 && l4_packet_len < 1024)
    workflow->stats.packet_len[3]++;
  else if(l4_packet_len >= 1024 && l4_packet_len < 1500)
    workflow->stats.packet_len[4]++;
  else if(l4_packet_len >= 1500)
    workflow->stats.packet_len[5]++;

  if(l4_packet_len > workflow->stats.max_packet_len)
    workflow->stats.max_packet_len = l4_packet_len;

  l4 =& ((const u_int8_t *) l3)[l4_offset];

  if(*proto == IPPROTO_TCP && l4_packet_len >= sizeof(struct ndpi_tcphdr)) {
    u_int tcp_len;

    // TCP
    workflow->stats.tcp_count++;
    *tcph = (struct ndpi_tcphdr *)l4;
    *sport = ntohs((*tcph)->source), *dport = ntohs((*tcph)->dest);
    tcp_len = ndpi_min(4*(*tcph)->doff, l4_packet_len);
    *payload = (u_int8_t*)&l4[tcp_len];
    *payload_len = ndpi_max(0, l4_packet_len-4*(*tcph)->doff);
    l4_data_len = l4_packet_len - sizeof(struct ndpi_tcphdr);
  } else if(*proto == IPPROTO_UDP && l4_packet_len >= sizeof(struct ndpi_udphdr)) {
    // UDP
    workflow->stats.udp_count++;
    *udph = (struct ndpi_udphdr *)l4;
    *sport = ntohs((*udph)->source), *dport = ntohs((*udph)->dest);
    *payload = (u_int8_t*)&l4[sizeof(struct ndpi_udphdr)];
    *payload_len = (l4_packet_len > sizeof(struct ndpi_udphdr)) ? l4_packet_len-sizeof(struct ndpi_udphdr) : 0;
    l4_data_len = l4_packet_len - sizeof(struct ndpi_udphdr);
  } else if(*proto == IPPROTO_ICMP) {
    *payload = (u_int8_t*)&l4[sizeof(struct ndpi_icmphdr )];
    *payload_len = (l4_packet_len > sizeof(struct ndpi_icmphdr)) ? l4_packet_len-sizeof(struct ndpi_icmphdr) : 0;
    l4_data_len = l4_packet_len - sizeof(struct ndpi_icmphdr);
    *sport = *dport = 0;
  } else if(*proto == IPPROTO_ICMPV6) {
    *payload = (u_int8_t*)&l4[sizeof(struct ndpi_icmp6hdr)];
    *payload_len = (l4_packet_len > sizeof(struct ndpi_icmp6hdr)) ? l4_packet_len-sizeof(struct ndpi_icmp6hdr) : 0;
    l4_data_len = l4_packet_len - sizeof(struct ndpi_icmp6hdr);
    *sport = *dport = 0;
  } else {
    // non tcp/udp protocols
    *sport = *dport = 0;
    l4_data_len = 0;
  }

  flow.protocol = iph->protocol, flow.vlan_id = vlan_id;
  flow.src_ip = iph->saddr, flow.dst_ip = iph->daddr;
  flow.src_port = htons(*sport), flow.dst_port = htons(*dport);
  flow.hashval = hashval = flow.protocol + ntohl(flow.src_ip) + ntohl(flow.dst_ip) 
	  + ntohs(flow.src_port) + ntohs(flow.dst_port);

#if 0
  {
  char ip1[48],ip2[48];
       inet_ntop(AF_INET, &flow.src_ip, ip1, sizeof(ip1));
       inet_ntop(AF_INET, &flow.dst_ip, ip2, sizeof(ip2));
  printf("hashval=%u [%u][%u][%s:%u][%s:%u]\n", hashval, flow.protocol, flow.vlan_id,
        ip1, ntohs(flow.src_port),  ip2, ntohs(flow.dst_port));
  }
#endif

  idx = hashval % workflow->prefs.num_roots;
  ret = ndpi_tfind(&flow, &workflow->ndpi_flows_root[idx], ndpi_workflow_node_cmp);

  /* to avoid two nodes in one binary tree for a flow */
  int is_changed = 0;
  if(ret == NULL) {
    u_int32_t orig_src_ip = flow.src_ip;
    u_int16_t orig_src_port = flow.src_port;
    u_int32_t orig_dst_ip = flow.dst_ip;
    u_int16_t orig_dst_port = flow.dst_port;

    flow.src_ip = orig_dst_ip;
    flow.src_port = orig_dst_port;
    flow.dst_ip = orig_src_ip;
    flow.dst_port = orig_src_port;

    is_changed = 1;

    ret = ndpi_tfind(&flow, &workflow->ndpi_flows_root[idx], ndpi_workflow_node_cmp);
  }

  if(ret == NULL) {
    if(workflow->stats.ndpi_flow_count == workflow->prefs.max_ndpi_flows) {
      return NULL;
    } else {
      struct ndpi_flow_info *newflow = (struct ndpi_flow_info*)ndpi_malloc(sizeof(struct ndpi_flow_info));

      if(newflow == NULL) {
#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
	/* Avoid too much logging while fuzzing */
#endif
	return(NULL);
      } else
        workflow->num_allocated_flows++;

      memset(newflow, 0, sizeof(struct ndpi_flow_info));
      newflow->flow_id = flow_id++;
      newflow->hashval = hashval;
      newflow->tunnel_type = tunnel_type;
      newflow->protocol = iph->protocol, newflow->vlan_id = vlan_id;
      newflow->src_ip = iph->saddr, newflow->dst_ip = iph->daddr;
      newflow->src_port = htons(*sport), newflow->dst_port = htons(*dport);
      newflow->ip_version = version;
      newflow->iat_c_to_s = ndpi_alloc_data_analysis(DATA_ANALUYSIS_SLIDING_WINDOW),
	newflow->iat_s_to_c =  ndpi_alloc_data_analysis(DATA_ANALUYSIS_SLIDING_WINDOW);
      newflow->pktlen_c_to_s = ndpi_alloc_data_analysis(DATA_ANALUYSIS_SLIDING_WINDOW),
	newflow->pktlen_s_to_c =  ndpi_alloc_data_analysis(DATA_ANALUYSIS_SLIDING_WINDOW),
	newflow->iat_flow = ndpi_alloc_data_analysis(DATA_ANALUYSIS_SLIDING_WINDOW);

#ifdef DIRECTION_BINS
      ndpi_init_bin(&newflow->payload_len_bin_src2dst, ndpi_bin_family8, PLEN_NUM_BINS);
      ndpi_init_bin(&newflow->payload_len_bin_dst2src, ndpi_bin_family8, PLEN_NUM_BINS);
#else
      ndpi_init_bin(&newflow->payload_len_bin, ndpi_bin_family8, PLEN_NUM_BINS);
#endif

      if(version == IPVERSION) {
	inet_ntop(AF_INET, &newflow->src_ip, newflow->src_name, sizeof(newflow->src_name));
	inet_ntop(AF_INET, &newflow->dst_ip, newflow->dst_name, sizeof(newflow->dst_name));
      } else {
        newflow->src_ip6 = *(struct ndpi_in6_addr *)&iph6->ip6_src;
        inet_ntop(AF_INET6, &newflow->src_ip6,
                  newflow->src_name, sizeof(newflow->src_name));
        newflow->dst_ip6 = *(struct ndpi_in6_addr *)&iph6->ip6_dst;
        inet_ntop(AF_INET6, &newflow->dst_ip6,
                  newflow->dst_name, sizeof(newflow->dst_name));
        /* For consistency across platforms replace :0: with :: */
        ndpi_patchIPv6Address(newflow->src_name), ndpi_patchIPv6Address(newflow->dst_name);
      }

      if((newflow->ndpi_flow = ndpi_flow_malloc(SIZEOF_FLOW_STRUCT)) == NULL) {
#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
	/* Avoid too much logging while fuzzing */
#endif
	ndpi_flow_info_free_data(newflow);
	ndpi_free(newflow);
	return(NULL);
      } else
	memset(newflow->ndpi_flow, 0, SIZEOF_FLOW_STRUCT);

    if (workflow->ndpi_serialization_format != ndpi_serialization_format_unknown)
    {
      if (ndpi_init_serializer(&newflow->ndpi_flow_serializer,
                               workflow->ndpi_serialization_format) != 0)
      {
        ndpi_flow_info_free_data(newflow);
        ndpi_free(newflow);
        return(NULL);
      }
    }

      if(ndpi_tsearch(newflow, &workflow->ndpi_flows_root[idx], ndpi_workflow_node_cmp) == NULL) { /* Add */
        ndpi_flow_info_free_data(newflow);
        ndpi_free(newflow);
        return(NULL);
      }
      workflow->stats.ndpi_flow_count++;
      if(*proto == IPPROTO_TCP)
        workflow->stats.flow_count[0]++;
      else if(*proto == IPPROTO_UDP)
        workflow->stats.flow_count[1]++;
      else
        workflow->stats.flow_count[2]++;

      if(enable_flow_stats) {
        newflow->entropy = ndpi_calloc(1, sizeof(struct ndpi_entropy));
        newflow->last_entropy = ndpi_calloc(1, sizeof(struct ndpi_entropy));
        newflow->entropy->src2dst_pkt_len[newflow->entropy->src2dst_pkt_count] = l4_data_len;
        newflow->entropy->src2dst_pkt_time[newflow->entropy->src2dst_pkt_count] = when;
        if(newflow->entropy->src2dst_pkt_count == 0) {
          newflow->entropy->src2dst_start = when;
        }
        newflow->entropy->src2dst_pkt_count++;
        // Non zero app data.
        if(l4_data_len != 0XFEEDFACE && l4_data_len != 0) {
          newflow->entropy->src2dst_opackets++;
          newflow->entropy->src2dst_l4_bytes += l4_data_len;
        }
      }
      return newflow;
    }
  } else {
    struct ndpi_flow_info *rflow = *(struct ndpi_flow_info**)ret;

    if(is_changed) {
	*src_to_dst_direction = 0, rflow->bidirectional |= 1;
    }
    else {
	*src_to_dst_direction = 1;
    }
    if(enable_flow_stats) {
      if(src_to_dst_direction) {
        if(rflow->entropy->src2dst_pkt_count < max_num_packets_per_flow) {
          rflow->entropy->src2dst_pkt_len[rflow->entropy->src2dst_pkt_count] = l4_data_len;
          rflow->entropy->src2dst_pkt_time[rflow->entropy->src2dst_pkt_count] = when;
          rflow->entropy->src2dst_l4_bytes += l4_data_len;
          rflow->entropy->src2dst_pkt_count++;
        }
        // Non zero app data.
        if(l4_data_len != 0XFEEDFACE && l4_data_len != 0) {
          rflow->entropy->src2dst_opackets++;
        }
      } else {
        if(rflow->entropy->dst2src_pkt_count < max_num_packets_per_flow) {
          rflow->entropy->dst2src_pkt_len[rflow->entropy->dst2src_pkt_count] = l4_data_len;
          rflow->entropy->dst2src_pkt_time[rflow->entropy->dst2src_pkt_count] = when;
          if(rflow->entropy->dst2src_pkt_count == 0) {
            rflow->entropy->dst2src_start = when;
          }
          rflow->entropy->dst2src_l4_bytes += l4_data_len;
          rflow->entropy->dst2src_pkt_count++;
        }
        // Non zero app data.
        if(l4_data_len != 0XFEEDFACE && l4_data_len != 0) {
          rflow->entropy->dst2src_opackets++;
        }
      }
    }

    return(rflow);
  }
}

static struct ndpi_flow_info *get_ndpi_flow_info6(struct ndpi_workflow * workflow,
						  u_int16_t vlan_id,
						  ndpi_packet_tunnel tunnel_type,
						  const struct ndpi_ipv6hdr *iph6,
						  u_int16_t ip_offset,
						  u_int16_t ipsize,
						  struct ndpi_tcphdr **tcph,
						  struct ndpi_udphdr **udph,
						  u_int16_t *sport, u_int16_t *dport,
						  u_int8_t *proto,
						  u_int8_t **payload,
						  u_int16_t *payload_len,
						  u_int8_t *src_to_dst_direction,
                                                  pkt_timeval when) {
  struct ndpi_iphdr iph;

  if(ipsize < 40)
    return(NULL);
  memset(&iph, 0, sizeof(iph));
  iph.version = IPVERSION;
  iph.saddr = iph6->ip6_src.u6_addr.u6_addr32[2] + iph6->ip6_src.u6_addr.u6_addr32[3];
  iph.daddr = iph6->ip6_dst.u6_addr.u6_addr32[2] + iph6->ip6_dst.u6_addr.u6_addr32[3];
  u_int8_t l4proto = iph6->ip6_hdr.ip6_un1_nxt;
  u_int16_t ip_len = ntohs(iph6->ip6_hdr.ip6_un1_plen);
  const u_int8_t *l4ptr = (((const u_int8_t *) iph6) + sizeof(struct ndpi_ipv6hdr));
  if(ipsize < sizeof(struct ndpi_ipv6hdr) + ip_len)
    return(NULL);
  if(ndpi_handle_ipv6_extension_headers(ipsize - sizeof(struct ndpi_ipv6hdr), &l4ptr, &ip_len, &l4proto) != 0) {
    return(NULL);
  }
  iph.protocol = l4proto;

  return(get_ndpi_flow_info(workflow, 6, vlan_id, tunnel_type,
			    &iph, iph6, ip_offset, ipsize,
			    ip_len, l4ptr - (const u_int8_t *)iph6,
			    tcph, udph, sport, dport,
			    proto, payload,
			    payload_len, src_to_dst_direction, when));
}

// void update_tcp_flags_count(struct ndpi_flow_info* flow, struct ndpi_tcphdr* tcp, u_int8_t src_to_dst_direction){
//   if(tcp->cwr){
//     flow->cwr_count++;
//     src_to_dst_direction ? flow->src2dst_cwr_count++ : flow->dst2src_cwr_count++;
//   }
//   if(tcp->ece){
//     flow->ece_count++;
//     src_to_dst_direction ? flow->src2dst_ece_count++ : flow->dst2src_ece_count++;
//   }
//   if(tcp->rst){
//     flow->rst_count++;
//     src_to_dst_direction ? flow->src2dst_rst_count++ : flow->dst2src_rst_count++;
//   }
//   if(tcp->ack){
//     flow->ack_count++;
//     src_to_dst_direction ? flow->src2dst_ack_count++ : flow->dst2src_ack_count++;
//   }
//   if(tcp->fin){
//     flow->fin_count++;
//     src_to_dst_direction ? flow->src2dst_fin_count++ : flow->dst2src_fin_count++;
//   }
//   if(tcp->syn){
//     flow->syn_count++;
//     src_to_dst_direction ? flow->src2dst_syn_count++ : flow->dst2src_syn_count++;
//   }
//   if(tcp->psh){
//     flow->psh_count++;
//     src_to_dst_direction ? flow->src2dst_psh_count++ : flow->dst2src_psh_count++;
//   }
//   if(tcp->urg){
//     flow->urg_count++;
//     src_to_dst_direction ? flow->src2dst_urg_count++ : flow->dst2src_urg_count++;
//   }
// }

ndpi_protocol ndpi_guess_undetected_protocol(struct ndpi_detection_module_struct *ndpi_str,
					     struct ndpi_flow_struct *flow, u_int8_t proto,
					     u_int32_t shost /* host byte order */, u_int16_t sport,
					     u_int32_t dhost /* host byte order */, u_int16_t dport) {
  u_int32_t rc;
  struct in_addr addr;
  ndpi_protocol ret = NDPI_PROTOCOL_NULL;
  u_int8_t user_defined_proto;

  if(!ndpi_str)
    return ret;

#ifdef BITTORRENT_CACHE_DEBUG
  printf("[%s:%u] ndpi_guess_undetected_protocol(%08X, %u, %08X, %u) [flow: %p]\n",
	 __FILE__, __LINE__, shost, sport, dhost, dport, flow);
#endif

  if((proto == IPPROTO_TCP) || (proto == IPPROTO_UDP)) {
    rc = ndpi_search_tcp_or_udp_raw(ndpi_str, flow, proto, shost, dhost, sport, dport);

    if(rc != NDPI_PROTOCOL_UNKNOWN) {
      if(flow && (proto == IPPROTO_UDP) &&
	 NDPI_COMPARE_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, rc) && is_udp_not_guessable_protocol(rc))
	;
      else {
	ret.app_protocol = rc,
	  ret.master_protocol = ndpi_guess_protocol_id(ndpi_str, flow, proto, sport, dport, &user_defined_proto);

	if(ret.app_protocol == ret.master_protocol)
	  ret.master_protocol = NDPI_PROTOCOL_UNKNOWN;

#ifdef BITTORRENT_CACHE_DEBUG
	printf("[%s:%u] Guessed %u.%u\n", __FILE__, __LINE__, ret.master_protocol, ret.app_protocol);
#endif

	ret.category = ndpi_get_proto_category(ndpi_str, ret);
	return(ret);
      }
    }

    rc = ndpi_guess_protocol_id(ndpi_str, flow, proto, sport, dport, &user_defined_proto);
    if(rc != NDPI_PROTOCOL_UNKNOWN) {
      if(flow && (proto == IPPROTO_UDP) &&
	 NDPI_COMPARE_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, rc) && is_udp_not_guessable_protocol(rc))
	;
      else {
	ret.app_protocol = rc;

	if(rc == NDPI_PROTOCOL_TLS)
	  goto check_guessed_skype;
	else {
#ifdef BITTORRENT_CACHE_DEBUG
	  printf("[%s:%u] Guessed %u.%u\n", __FILE__, __LINE__, ret.master_protocol, ret.app_protocol);
#endif

	  ret.category = ndpi_get_proto_category(ndpi_str, ret);
	  return(ret);
	}
      }
    }

    if(ndpi_search_into_bittorrent_cache(ndpi_str, NULL /* flow */,
					 htonl(shost), htons(sport),
					 htonl(dhost), htons(dport))) {
      /* This looks like BitTorrent */
      ret.app_protocol = NDPI_PROTOCOL_BITTORRENT;
      ret.category = ndpi_get_proto_category(ndpi_str, ret);

#ifdef BITTORRENT_CACHE_DEBUG
      printf("[%s:%u] Guessed %u.%u\n", __FILE__, __LINE__, ret.master_protocol, ret.app_protocol);
#endif

      return(ret);
    }

  check_guessed_skype:
    addr.s_addr = htonl(shost);
    if(ndpi_network_ptree_match(ndpi_str, &addr) == NDPI_PROTOCOL_SKYPE_TEAMS) {
      ret.app_protocol = NDPI_PROTOCOL_SKYPE_TEAMS;
    } else {
      addr.s_addr = htonl(dhost);
      if(ndpi_network_ptree_match(ndpi_str, &addr) == NDPI_PROTOCOL_SKYPE_TEAMS)
	ret.app_protocol = NDPI_PROTOCOL_SKYPE_TEAMS;
    }
  } else
    ret.app_protocol = ndpi_guess_protocol_id(ndpi_str, flow, proto, sport, dport, &user_defined_proto);

  ret.category = ndpi_get_proto_category(ndpi_str, ret);

#ifdef BITTORRENT_CACHE_DEBUG
  printf("[%s:%u] Guessed %u.%u\n", __FILE__, __LINE__, ret.master_protocol, ret.app_protocol);
#endif

  return(ret);
}

ndpi_protocol ndpi_detection_giveup(struct ndpi_detection_module_struct *ndpi_str, struct ndpi_flow_struct *flow,
				    u_int8_t enable_guess, u_int8_t *protocol_was_guessed) {
  ndpi_protocol ret = NDPI_PROTOCOL_NULL;
  u_int16_t cached_proto;

  /* *** We can't access ndpi_str->packet from this function!! *** */

  *protocol_was_guessed = 0;

  if(!ndpi_str || !flow)
    return(ret);

  if(flow->l4_proto == IPPROTO_TCP)
    ndpi_check_tcp_flags(ndpi_str, flow);

  /* Init defaults */
  ret.master_protocol = flow->detected_protocol_stack[1];
  ret.app_protocol = flow->detected_protocol_stack[0];
  ret.protocol_by_ip = flow->guessed_protocol_id_by_ip;
  ret.category = flow->category;

  /* Ensure that we don't change our mind if detection is already complete */
  if(ret.app_protocol != NDPI_PROTOCOL_UNKNOWN)
    return(ret);

  if((flow->guessed_protocol_id == NDPI_PROTOCOL_STUN) ||
     (enable_guess &&
      flow->stun.num_binding_requests > 0 &&
      flow->stun.num_processed_pkts > 0)) {
    ndpi_set_detected_protocol(ndpi_str, flow, NDPI_PROTOCOL_STUN, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI_PARTIAL);
    ret.app_protocol = flow->detected_protocol_stack[0];
  }

  /* Check some caches */

  /* Does it looks like BitTorrent? */
  if(ret.app_protocol == NDPI_PROTOCOL_UNKNOWN &&
     ndpi_search_into_bittorrent_cache(ndpi_str, flow,
                                       flow->c_address.v4, flow->c_port,
                                       flow->s_address.v4, flow->s_port)) {
    ndpi_set_detected_protocol(ndpi_str, flow, NDPI_PROTOCOL_BITTORRENT, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI_PARTIAL_CACHE);
    ret.app_protocol = flow->detected_protocol_stack[0];
  }
  /* Does it looks like some Mining protocols? */
  if(ret.app_protocol == NDPI_PROTOCOL_UNKNOWN &&
     ndpi_str->mining_cache &&
     ndpi_lru_find_cache(ndpi_str->mining_cache, make_mining_key(flow),
			 &cached_proto, 0 /* Don't remove it as it can be used for other connections */,
			 ndpi_get_current_time(flow))) {
    ndpi_set_detected_protocol(ndpi_str, flow, cached_proto, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI_PARTIAL_CACHE);
    ret.app_protocol = flow->detected_protocol_stack[0];
  }
  /* Does it looks like Zoom? */
  if(ret.app_protocol == NDPI_PROTOCOL_UNKNOWN &&
     flow->l4_proto == IPPROTO_UDP && /* Zoom/UDP used for video */
     ((ntohs(flow->s_port) == 8801 && ndpi_search_into_zoom_cache(ndpi_str, flow, 1)) ||
      (ntohs(flow->c_port) == 8801 && ndpi_search_into_zoom_cache(ndpi_str, flow, 0)))) {
    ndpi_set_detected_protocol(ndpi_str, flow, NDPI_PROTOCOL_ZOOM, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI_PARTIAL_CACHE);
    ret.app_protocol = flow->detected_protocol_stack[0];
  }
  /* Does it looks like Zoom (via STUN)? */
  if(ret.app_protocol == NDPI_PROTOCOL_UNKNOWN &&
     stun_search_into_zoom_cache(ndpi_str, flow)) {
    ndpi_set_detected_protocol(ndpi_str, flow, NDPI_PROTOCOL_ZOOM, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI_PARTIAL_CACHE);
    ret.app_protocol = flow->detected_protocol_stack[0];
  }

  /* Classification by-port is the last resort */
  if(enable_guess && ret.app_protocol == NDPI_PROTOCOL_UNKNOWN) {

    /* Ignore guessed protocol if they have been discarded */
    if(flow->guessed_protocol_id != NDPI_PROTOCOL_UNKNOWN &&
       flow->l4_proto == IPPROTO_UDP &&
       NDPI_ISSET(&flow->excluded_protocol_bitmask, flow->guessed_protocol_id) &&
       is_udp_not_guessable_protocol(flow->guessed_protocol_id))
      flow->guessed_protocol_id = NDPI_PROTOCOL_UNKNOWN;

    if(flow->guessed_protocol_id != NDPI_PROTOCOL_UNKNOWN) {
      ndpi_set_detected_protocol(ndpi_str, flow, flow->guessed_protocol_id, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_MATCH_BY_PORT);
      ret.app_protocol = flow->detected_protocol_stack[0];
    }
  }

  if(ret.app_protocol != NDPI_PROTOCOL_UNKNOWN) {
    *protocol_was_guessed = 1;
    ndpi_fill_protocol_category(ndpi_str, flow, &ret);
    ndpi_reconcile_protocols(ndpi_str, flow, &ret);
  }

  return(ret);
}

static void
ndpi_flow_update_byte_count(struct ndpi_flow_info *flow, const void *x,
                            unsigned int len, u_int8_t src_to_dst_direction) {
  /*
   * implementation note: The spec says that 4000 octets is enough of a
   * sample size to accurately reflect the byte distribution. Also, to avoid
   * wrapping of the byte count at the 16-bit boundry, we stop counting once
   * the 4000th octet has been seen for a flow.
   */

  if((flow->entropy->src2dst_pkt_count+flow->entropy->dst2src_pkt_count) <= max_num_packets_per_flow) {
    /* octet count was already incremented before processing this payload */
    u_int32_t current_count;

    if(src_to_dst_direction) {
      current_count = flow->entropy->src2dst_l4_bytes - len;
    } else {
      current_count = flow->entropy->dst2src_l4_bytes - len;
    }

    if(current_count < ETTA_MIN_OCTETS) {
      u_int32_t i;
      const unsigned char *data = x;

      for(i=0; i<len; i++) {
        if(src_to_dst_direction) {
          flow->entropy->src2dst_byte_count[data[i]]++;
        } else {
          flow->entropy->dst2src_byte_count[data[i]]++;
        }
        current_count++;
        if(current_count >= ETTA_MIN_OCTETS) {
          break;
        }
      }
    }
  }
}

/* transform times array to Markov chain */
void
ndpi_get_mc_rep_times (uint16_t *times, float *time_mc, uint16_t num_packets)
{
  float row_sum;
  int prev_packet_time = 0;
  int cur_packet_time = 0;
  int i, j;

  for (i = 0; i < MC_BINS_TIME*MC_BINS_TIME; i++) { // init to 0
    time_mc[i] = 0.0;
  }
  if(num_packets == 0) {
    // nothing to do
  } else if(num_packets == 1) {
    cur_packet_time = (int)min(times[0]/(float)MC_BIN_SIZE_TIME,(uint16_t)MC_BINS_TIME-1);
    time_mc[cur_packet_time + cur_packet_time*MC_BINS_TIME] = 1.0;
  } else {
    for (i = 1; i < num_packets; i++) {
      prev_packet_time = (int)min((uint16_t)(times[i-1]/(float)MC_BIN_SIZE_TIME),(uint16_t)MC_BINS_TIME-1);
      cur_packet_time = (int)min((uint16_t)(times[i]/(float)MC_BIN_SIZE_TIME),(uint16_t)MC_BINS_TIME-1);
      time_mc[prev_packet_time*MC_BINS_TIME + cur_packet_time] += 1.0;
    }
    // normalize rows of Markov chain
    for (i = 0; i < MC_BINS_TIME; i++) {
      // find sum
      row_sum = 0.0;
      for (j = 0; j < MC_BINS_TIME; j++) {
	row_sum += time_mc[i*MC_BINS_TIME+j];
      }
      if(row_sum != 0.0) {
	for (j = 0; j < MC_BINS_TIME; j++) {
	  time_mc[i*MC_BINS_TIME+j] /= row_sum;
	}
      }
    }
  }
}

/**
 * \brief Update the byte distribution mean for the flow record.
 * \param f Flow record
 * \param x Data to use for update
 * \param len Length of the data (in bytes)
 * \return none
 */
static void
ndpi_flow_update_byte_dist_mean_var(ndpi_flow_info_t *flow, const void *x,
                                    unsigned int len, u_int8_t src_to_dst_direction) {
  const unsigned char *data = x;

  if((flow->entropy->src2dst_pkt_count+flow->entropy->dst2src_pkt_count) <= max_num_packets_per_flow) {
    unsigned int i;

    for(i=0; i<len; i++) {
      double delta;

      if(src_to_dst_direction) {
        flow->entropy->src2dst_num_bytes += 1;
        delta = ((double)data[i] - flow->entropy->src2dst_bd_mean);
        flow->entropy->src2dst_bd_mean += delta/((double)flow->entropy->src2dst_num_bytes);
        flow->entropy->src2dst_bd_variance += delta*((double)data[i] - flow->entropy->src2dst_bd_mean);
      } else {
        flow->entropy->dst2src_num_bytes += 1;
        delta = ((double)data[i] - flow->entropy->dst2src_bd_mean);
        flow->entropy->dst2src_bd_mean += delta/((double)flow->entropy->dst2src_num_bytes);
        flow->entropy->dst2src_bd_variance += delta*((double)data[i] - flow->entropy->dst2src_bd_mean);
      }
    }
  }
}

void
ndpi_merge_splt_arrays (const uint16_t *pkt_len, const pkt_timeval *pkt_time,
                        const uint16_t *pkt_len_twin, const pkt_timeval *pkt_time_twin,
                        pkt_timeval start_time, pkt_timeval start_time_twin,
                        uint16_t s_idx, uint16_t r_idx,
                        uint16_t *merged_lens, uint16_t *merged_times)
{
  int s,r;
  pkt_timeval ts_start = { 0, 0 }; /* initialize to avoid spurious warnings */
  pkt_timeval tmp, tmp_r;
  pkt_timeval start_m;

  if(r_idx + s_idx == 0) {
    return ;
  } else if(r_idx == 0) {
    ts_start = pkt_time[0];
    tmp = pkt_time[0];
    ndpi_timer_sub(&tmp, &start_time, &start_m);
  } else if(s_idx == 0) {
    ts_start = pkt_time_twin[0];
    tmp = pkt_time_twin[0];
    ndpi_timer_sub(&tmp, &start_time_twin, &start_m);
  } else {
    if(ndpi_timer_lt(&start_time, &start_time_twin)) {
      ts_start = pkt_time[0];
      tmp = pkt_time[0];
      ndpi_timer_sub(&tmp, &start_time, &start_m);
    } else {
      //      ts_start = pkt_time_twin[0];
      tmp = pkt_time_twin[0];
      ndpi_timer_sub(&tmp, &start_time_twin, &start_m);
    }
  }
  s = r = 0;
  while ((s < s_idx) || (r < r_idx)) {
    if(s >= s_idx) {
      merged_lens[s+r] = pkt_len_twin[r];
      tmp = pkt_time_twin[r];
      ndpi_timer_sub(&tmp, &ts_start, &tmp_r);
      merged_times[s+r] = ndpi_timeval_to_milliseconds(tmp_r);
      if(merged_times[s+r] == 0)
	merged_times[s+r] = ndpi_timeval_to_microseconds(tmp_r);
      ts_start = tmp;
      r++;
    } else if(r >= r_idx) {
      merged_lens[s+r] = pkt_len[s];
      tmp = pkt_time[s];
      ndpi_timer_sub(&tmp, &ts_start, &tmp_r);
      merged_times[s+r] = ndpi_timeval_to_milliseconds(tmp_r);
      if(merged_times[s+r] == 0)
	merged_times[s+r] = ndpi_timeval_to_microseconds(tmp_r);
      ts_start = tmp;
      s++;
    } else {
      if(ndpi_timer_lt(&pkt_time[s], &pkt_time_twin[r])) {
	merged_lens[s+r] = pkt_len[s];
	tmp = pkt_time[s];
	ndpi_timer_sub(&tmp, &ts_start, &tmp_r);
	merged_times[s+r] = ndpi_timeval_to_milliseconds(tmp_r);
	if(merged_times[s+r] == 0)
	  merged_times[s+r] = ndpi_timeval_to_microseconds(tmp_r);
	ts_start = tmp;
	s++;
      } else {
	merged_lens[s+r] = pkt_len_twin[r];
	tmp = pkt_time_twin[r];
	ndpi_timer_sub(&tmp, &ts_start, &tmp_r);
	merged_times[s+r] = ndpi_timeval_to_milliseconds(tmp_r);
	if(merged_times[s+r] == 0)
	  merged_times[s+r] = ndpi_timeval_to_microseconds(tmp_r);
	ts_start = tmp;
	r++;
      }
    }
  }
  merged_times[0] = ndpi_timeval_to_milliseconds(start_m);
  if(merged_times[0] == 0)
    merged_times[0] = ndpi_timeval_to_microseconds(start_m);
}

/* transform lens array to Markov chain */
static void
ndpi_get_mc_rep_lens (uint16_t *lens, float *length_mc, uint16_t num_packets)
{
  float row_sum;
  int prev_packet_size = 0;
  int cur_packet_size = 0;
  int i, j;

  for (i = 0; i < MC_BINS_LEN*MC_BINS_LEN; i++) { // init to 0
    length_mc[i] = 0.0;
  }

  if(num_packets == 0) {
    // nothing to do
  } else if(num_packets == 1) {
    cur_packet_size = (int)min(lens[0]/(float)MC_BIN_SIZE_LEN,(uint16_t)MC_BINS_LEN-1);
    length_mc[cur_packet_size + cur_packet_size*MC_BINS_LEN] = 1.0;
  } else {
    for (i = 1; i < num_packets; i++) {
      prev_packet_size = (int)min((uint16_t)(lens[i-1]/(float)MC_BIN_SIZE_LEN),(uint16_t)MC_BINS_LEN-1);
      cur_packet_size = (int)min((uint16_t)(lens[i]/(float)MC_BIN_SIZE_LEN),(uint16_t)MC_BINS_LEN-1);
      length_mc[prev_packet_size*MC_BINS_LEN + cur_packet_size] += 1.0;
    }
    // normalize rows of Markov chain
    for (i = 0; i < MC_BINS_LEN; i++) {
      // find sum
      row_sum = 0.0;
      for (j = 0; j < MC_BINS_LEN; j++) {
	row_sum += length_mc[i*MC_BINS_LEN+j];
      }
      if(row_sum != 0.0) {
	for (j = 0; j < MC_BINS_LEN; j++) {
	  length_mc[i*MC_BINS_LEN+j] /= row_sum;
	}
      }
    }
  }
}

float
ndpi_classify (const unsigned short *pkt_len, const pkt_timeval *pkt_time,
               const unsigned short *pkt_len_twin, const pkt_timeval *pkt_time_twin,
               pkt_timeval start_time, pkt_timeval start_time_twin, uint32_t max_num_pkt_len,
               uint16_t sp, uint16_t dp, uint32_t op, uint32_t ip, uint32_t np_o, uint32_t np_i,
               uint32_t ob, uint32_t ib, uint16_t use_bd, const uint32_t *bd, const uint32_t *bd_t)
{

  float features[NUM_PARAMETERS_BD_LOGREG] = {1.0};
  float mc_lens[MC_BINS_LEN*MC_BINS_LEN];
  float mc_times[MC_BINS_TIME*MC_BINS_TIME];
  uint32_t i;
  float score = 0.0;

  uint32_t op_n = min(np_o, max_num_pkt_len);
  uint32_t ip_n = min(np_i, max_num_pkt_len);
  uint16_t *merged_lens = NULL;
  uint16_t *merged_times = NULL;

  for (i = 1; i < NUM_PARAMETERS_BD_LOGREG; i++) {
    features[i] = 0.0;
  }

  merged_lens = ndpi_calloc(1, sizeof(uint16_t)*(op_n + ip_n));
  merged_times = ndpi_calloc(1, sizeof(uint16_t)*(op_n + ip_n));

  if(!merged_lens || !merged_times) {
    ndpi_free(merged_lens);
    ndpi_free(merged_times);
    return(score);
  }

  // fill out meta data
  features[1] = (float)dp; // destination port
  features[2] = (float)sp; // source port
  features[3] = (float)ip; // inbound packets
  features[4] = (float)op; // outbound packets
  features[5] = (float)ib; // inbound bytes
  features[6] = (float)ob; // outbound bytes
  features[7] = 0.0;// skipping 7 until we process the pkt_time arrays

  // find the raw features
  ndpi_merge_splt_arrays(pkt_len, pkt_time, pkt_len_twin, pkt_time_twin, start_time, start_time_twin, op_n, ip_n,
			 merged_lens, merged_times);

  // find new duration
  for (i = 0; i < op_n+ip_n; i++) {
    features[7] += (float)merged_times[i];
  }

  // get the Markov chain representation for the lengths
  ndpi_get_mc_rep_lens(merged_lens, mc_lens, op_n+ip_n);

  // get the Markov chain representation for the times
  ndpi_get_mc_rep_times(merged_times, mc_times, op_n+ip_n);

  // fill out lens/times in feature vector
  for (i = 0; i < MC_BINS_LEN*MC_BINS_LEN; i++) {
    features[i+8] = mc_lens[i]; // lengths
  }
  for (i = 0; i < MC_BINS_TIME*MC_BINS_TIME; i++) {
    features[i+8+MC_BINS_LEN*MC_BINS_LEN] = mc_times[i]; // times
  }

  // fill out byte distribution features
  if(ob+ib > 100 && use_bd) {
    for (i = 0; i < NUM_BD_VALUES; i++) {
      if(pkt_len_twin != NULL) {
	features[i+8+MC_BINS_LEN*MC_BINS_LEN+MC_BINS_TIME*MC_BINS_TIME] = (bd[i]+bd_t[i])/((float)(ob+ib));
      } else {
	features[i+8+MC_BINS_LEN*MC_BINS_LEN+MC_BINS_TIME*MC_BINS_TIME] = bd[i]/((float)(ob));
      }
    }

    score = ndpi_parameters_bd[0];
    for (i = 1; i < NUM_PARAMETERS_BD_LOGREG; i++) {
      score += features[i]*ndpi_parameters_bd[i];
    }
  } else {
    for (i = 0; i < NUM_PARAMETERS_SPLT_LOGREG; i++) {
      score += features[i]*ndpi_parameters_splt[i];
    }
  }

  score = min(-score,500.0); // check b/c overflow

  ndpi_free(merged_lens);
  ndpi_free(merged_times);

  return 1.0/(1.0+exp(score));
}

void ndpi_analyze_payload(struct ndpi_flow_info *flow,
			  u_int8_t src_to_dst_direction,
			  u_int8_t *payload,
			  u_int16_t payload_len,
			  u_int32_t packet_id) {
  struct payload_stats *ret;
  struct flow_id_stats *f;
  struct packet_id_stats *p;

#ifdef DEBUG_PAYLOAD
  for(i=0; i<payload_len; i++)
    printf("%c", isprint(payload[i]) ? payload[i] : '.');
  printf("\n");
#endif

  HASH_FIND(hh, pstats, payload, payload_len, ret);
  if(ret == NULL) {
    if((ret = (struct payload_stats*)ndpi_calloc(1, sizeof(struct payload_stats))) == NULL)
      return; /* OOM */

    if((ret->pattern = (u_int8_t*)ndpi_malloc(payload_len)) == NULL) {
      ndpi_free(ret);
      return;
    }

    memcpy(ret->pattern, payload, payload_len);
    ret->pattern_len = payload_len;
    ret->num_occurrencies = 1;

    HASH_ADD(hh, pstats, pattern[0], payload_len, ret);

#ifdef DEBUG_PAYLOAD
    printf("Added element [total: %u]\n", HASH_COUNT(pstats));
#endif
  } else {
    ret->num_occurrencies++;
    // printf("==> %u\n", ret->num_occurrencies);
  }

  HASH_FIND_INT(ret->flows, &flow->flow_id, f);
  if(f == NULL) {
    if((f = (struct flow_id_stats*)ndpi_calloc(1, sizeof(struct flow_id_stats))) == NULL)
      return; /* OOM */

    f->flow_id = flow->flow_id;
    HASH_ADD_INT(ret->flows, flow_id, f);
  }

  HASH_FIND_INT(ret->packets, &packet_id, p);
  if(p == NULL) {
    if((p = (struct packet_id_stats*)ndpi_calloc(1, sizeof(struct packet_id_stats))) == NULL)
      return; /* OOM */
    p->packet_id = packet_id;

    HASH_ADD_INT(ret->packets, packet_id, p);
  }
}

void ndpi_payload_analyzer(struct ndpi_flow_info *flow,
			   u_int8_t src_to_dst_direction,
			   u_int8_t *payload, u_int16_t payload_len,
			   u_int32_t packet_id) {
  u_int16_t i, j;
  u_int16_t scan_len = ndpi_min(max_packet_payload_dissection, payload_len);

  if((flow->src2dst_packets+flow->dst2src_packets) <= max_num_packets_per_flow) {
#ifdef DEBUG_PAYLOAD
    printf("[hashval: %u][proto: %u][vlan: %u][%s:%u <-> %s:%u][direction: %s][payload_len: %u]\n",
	   flow->hashval, flow->protocol, flow->vlan_id,
	   flow->src_name, flow->src_port,
	   flow->dst_name, flow->dst_port,
	   src_to_dst_direction ? "s2d" : "d2s",
	   payload_len);
#endif
  } else
    return;

  for(i=0; i<scan_len; i++) {
    for(j=min_pattern_len; j <= max_pattern_len; j++) {
      if((i+j) < payload_len) {
	ndpi_analyze_payload(flow, src_to_dst_direction, &payload[i], j, packet_id);
      }
    }
  }
}

static u_int8_t is_ndpi_proto(struct ndpi_flow_info *flow, u_int16_t id) {
  if((flow->detected_protocol.master_protocol == id)
     || (flow->detected_protocol.app_protocol == id))
    return(1);
  else
    return(0);
}

/**
 * @brief Clear entropy stats if it meets prereq.
 */
static void
ndpi_clear_entropy_stats(struct ndpi_flow_info *flow) {
  if(enable_flow_stats) {
    if(flow->entropy->src2dst_pkt_count + flow->entropy->dst2src_pkt_count == max_num_packets_per_flow) {
      memcpy(flow->last_entropy, flow->entropy,  sizeof(struct ndpi_entropy));
      memset(flow->entropy, 0x00, sizeof(struct ndpi_entropy));
    }
  }
}

void correct_csv_data_field(char* data) {
  /* Replace , with ; to avoid issues with CSVs */
  u_int i;
  for(i=0; data[i] != '\0'; i++) if(data[i] == ',') data[i] = ';';
}

void process_ndpi_collected_info(struct ndpi_workflow * workflow, struct ndpi_flow_info *flow) {
  u_int i, is_quic = 0;
  char out[128], *s;
  
  if(!flow->ndpi_flow) return;

  flow->info_type = INFO_INVALID;

  s = ndpi_get_flow_risk_info(flow->ndpi_flow, out, sizeof(out), 0 /* text */);

  if(s != NULL)
    flow->risk_str = ndpi_strdup(s);  
  
  flow->confidence = flow->ndpi_flow->confidence;
  flow->num_dissector_calls = flow->ndpi_flow->num_dissector_calls;

  ndpi_snprintf(flow->host_server_name, sizeof(flow->host_server_name), "%s",
	   flow->ndpi_flow->host_server_name);

  ndpi_snprintf(flow->flow_extra_info, sizeof(flow->flow_extra_info), "%s",
	   flow->ndpi_flow->flow_extra_info);

  flow->risk = flow->ndpi_flow->risk;

  if(is_ndpi_proto(flow, NDPI_PROTOCOL_DHCP)) {
    if(flow->ndpi_flow->protos.dhcp.fingerprint[0] != '\0')
      flow->dhcp_fingerprint = ndpi_strdup(flow->ndpi_flow->protos.dhcp.fingerprint);
    if(flow->ndpi_flow->protos.dhcp.class_ident[0] != '\0')
      flow->dhcp_class_ident = ndpi_strdup(flow->ndpi_flow->protos.dhcp.class_ident);
  } else if(is_ndpi_proto(flow, NDPI_PROTOCOL_BITTORRENT) &&
            !is_ndpi_proto(flow, NDPI_PROTOCOL_TLS)) {
    u_int j;

    if(flow->ndpi_flow->protos.bittorrent.hash[0] != '\0') {
      flow->bittorent_hash = ndpi_malloc(sizeof(flow->ndpi_flow->protos.bittorrent.hash) * 2 + 1);
      if(flow->bittorent_hash) {
        for(i=0, j = 0; i < sizeof(flow->ndpi_flow->protos.bittorrent.hash); i++) {
          sprintf(&flow->bittorent_hash[j], "%02x",
	          flow->ndpi_flow->protos.bittorrent.hash[i]);

          j += 2;
        }
        flow->bittorent_hash[j] = '\0';
      }
    }
  }
  /* TIVOCONNECT */
  else if(is_ndpi_proto(flow, NDPI_PROTOCOL_TIVOCONNECT)) {
    flow->info_type = INFO_TIVOCONNECT;
    ndpi_snprintf(flow->tivoconnect.identity_uuid, sizeof(flow->tivoconnect.identity_uuid),
                  "%s", flow->ndpi_flow->protos.tivoconnect.identity_uuid);
    ndpi_snprintf(flow->tivoconnect.machine, sizeof(flow->tivoconnect.machine),
                  "%s", flow->ndpi_flow->protos.tivoconnect.machine);
    ndpi_snprintf(flow->tivoconnect.platform, sizeof(flow->tivoconnect.platform),
                  "%s", flow->ndpi_flow->protos.tivoconnect.platform);
    ndpi_snprintf(flow->tivoconnect.services, sizeof(flow->tivoconnect.services),
                  "%s", flow->ndpi_flow->protos.tivoconnect.services);
  }
  /* SOFTETHER */
  else if(is_ndpi_proto(flow, NDPI_PROTOCOL_SOFTETHER) && !is_ndpi_proto(flow, NDPI_PROTOCOL_HTTP)) {
    flow->info_type = INFO_SOFTETHER;
    ndpi_snprintf(flow->softether.ip, sizeof(flow->softether.ip), "%s",
                  flow->ndpi_flow->protos.softether.ip);
    ndpi_snprintf(flow->softether.port, sizeof(flow->softether.port), "%s",
                  flow->ndpi_flow->protos.softether.port);
    ndpi_snprintf(flow->softether.hostname, sizeof(flow->softether.hostname), "%s",
                  flow->ndpi_flow->protos.softether.hostname);
    ndpi_snprintf(flow->softether.fqdn, sizeof(flow->softether.fqdn), "%s",
                  flow->ndpi_flow->protos.softether.fqdn);
  }
  /* NATPMP */
  else if(is_ndpi_proto(flow, NDPI_PROTOCOL_NATPMP)) {
    flow->info_type = INFO_NATPMP;
    flow->natpmp.result_code = flow->ndpi_flow->protos.natpmp.result_code;
    flow->natpmp.internal_port = flow->ndpi_flow->protos.natpmp.internal_port;
    flow->natpmp.external_port = flow->ndpi_flow->protos.natpmp.external_port;
    inet_ntop(AF_INET, &flow->ndpi_flow->protos.natpmp.external_address.ipv4, &flow->natpmp.ip[0], sizeof(flow->natpmp.ip));
  }
  /* DISCORD */
  else if(is_ndpi_proto(flow, NDPI_PROTOCOL_DISCORD) &&
          !is_ndpi_proto(flow, NDPI_PROTOCOL_TLS) &&
          !is_ndpi_proto(flow, NDPI_PROTOCOL_DTLS) &&
          flow->ndpi_flow->protos.discord.client_ip[0] != '\0') {
    flow->info_type = INFO_GENERIC;
    ndpi_snprintf(flow->info, sizeof(flow->info), "Client IP: %s",
                  flow->ndpi_flow->protos.discord.client_ip);
  }
  /* DNS */
  else if(is_ndpi_proto(flow, NDPI_PROTOCOL_DNS)) {
    if(flow->ndpi_flow->protos.dns.rsp_type == 0x1)
    {
      flow->info_type = INFO_GENERIC;
      inet_ntop(AF_INET, &flow->ndpi_flow->protos.dns.rsp_addr.ipv4, flow->info, sizeof(flow->info));
    } else {
      flow->info_type = INFO_GENERIC;
      inet_ntop(AF_INET6, &flow->ndpi_flow->protos.dns.rsp_addr.ipv6, flow->info, sizeof(flow->info));

      /* For consistency across platforms replace :0: with :: */
      ndpi_patchIPv6Address(flow->info);
    }
  }
  /* MDNS */
  else if(is_ndpi_proto(flow, NDPI_PROTOCOL_MDNS)) {
    flow->info_type = INFO_GENERIC;
    ndpi_snprintf(flow->info, sizeof(flow->info), "%s", flow->ndpi_flow->host_server_name);
  }
  /* UBNTAC2 */
  else if(is_ndpi_proto(flow, NDPI_PROTOCOL_UBNTAC2)) {
    flow->info_type = INFO_GENERIC;
    ndpi_snprintf(flow->info, sizeof(flow->info), "%s", flow->ndpi_flow->protos.ubntac2.version);
  }
  /* FTP */
  else if((is_ndpi_proto(flow, NDPI_PROTOCOL_FTP_CONTROL))
	  || /* IMAP */ is_ndpi_proto(flow, NDPI_PROTOCOL_MAIL_IMAP)
	  || /* POP */  is_ndpi_proto(flow, NDPI_PROTOCOL_MAIL_POP)
	  || /* SMTP */ is_ndpi_proto(flow, NDPI_PROTOCOL_MAIL_SMTP)) {
    flow->info_type = INFO_FTP_IMAP_POP_SMTP;
    ndpi_snprintf(flow->ftp_imap_pop_smtp.username,
                  sizeof(flow->ftp_imap_pop_smtp.username),
                  "%s", flow->ndpi_flow->l4.tcp.ftp_imap_pop_smtp.username);
    ndpi_snprintf(flow->ftp_imap_pop_smtp.password,
                  sizeof(flow->ftp_imap_pop_smtp.password),
                  "%s", flow->ndpi_flow->l4.tcp.ftp_imap_pop_smtp.password);
    flow->ftp_imap_pop_smtp.auth_failed =
      flow->ndpi_flow->l4.tcp.ftp_imap_pop_smtp.auth_failed;
  }
  /* TFTP */
  else if(is_ndpi_proto(flow, NDPI_PROTOCOL_TFTP)) {
    flow->info_type = INFO_GENERIC;
    if(flow->ndpi_flow->protos.tftp.filename[0] != '\0')
      ndpi_snprintf(flow->info, sizeof(flow->info), "Filename: %s",
                    flow->ndpi_flow->protos.tftp.filename);
  }
  /* KERBEROS */
  else if(is_ndpi_proto(flow, NDPI_PROTOCOL_KERBEROS)) {
    flow->info_type = INFO_KERBEROS;
    ndpi_snprintf(flow->kerberos.domain,
                  sizeof(flow->kerberos.domain),
                  "%s", flow->ndpi_flow->protos.kerberos.domain);
    ndpi_snprintf(flow->kerberos.hostname,
                  sizeof(flow->kerberos.hostname),
                  "%s", flow->ndpi_flow->protos.kerberos.hostname);
    ndpi_snprintf(flow->kerberos.username,
                  sizeof(flow->kerberos.username),
                  "%s", flow->ndpi_flow->protos.kerberos.username);
  }
  /* HTTP */
  else if(is_ndpi_proto(flow, NDPI_PROTOCOL_HTTP)
	  || is_ndpi_proto(flow, NDPI_PROTOCOL_HTTP_PROXY)
	  || is_ndpi_proto(flow, NDPI_PROTOCOL_HTTP_CONNECT)) {
    if(flow->ndpi_flow->http.url != NULL) {
      ndpi_snprintf(flow->http.url, sizeof(flow->http.url), "%s", flow->ndpi_flow->http.url);
      flow->http.response_status_code = flow->ndpi_flow->http.response_status_code;
      ndpi_snprintf(flow->http.content_type, sizeof(flow->http.content_type), "%s", flow->ndpi_flow->http.content_type ? flow->ndpi_flow->http.content_type : "");
      ndpi_snprintf(flow->http.server, sizeof(flow->http.server), "%s", flow->ndpi_flow->http.server ? flow->ndpi_flow->http.server : "");
      ndpi_snprintf(flow->http.request_content_type, sizeof(flow->http.request_content_type), "%s", flow->ndpi_flow->http.request_content_type ? flow->ndpi_flow->http.request_content_type : "");
    }
  }
  /* RTP */
  else if(is_ndpi_proto(flow, NDPI_PROTOCOL_RTP)) {
    flow->info_type = INFO_RTP;
    flow->rtp.stream_type = flow->ndpi_flow->protos.rtp.stream_type;
  /* COLLECTD */
  } else if(is_ndpi_proto(flow, NDPI_PROTOCOL_COLLECTD)) {
    flow->info_type = INFO_GENERIC;
    if(flow->ndpi_flow->protos.collectd.client_username[0] != '\0')
      ndpi_snprintf(flow->info, sizeof(flow->info), "Username: %s",
                    flow->ndpi_flow->protos.collectd.client_username);
  }
  /* TELNET */
  else if(is_ndpi_proto(flow, NDPI_PROTOCOL_TELNET)) {
    if(flow->ndpi_flow->protos.telnet.username[0] != '\0')
      flow->telnet.username = ndpi_strdup(flow->ndpi_flow->protos.telnet.username);
    if(flow->ndpi_flow->protos.telnet.password[0] != '\0')
      flow->telnet.password = ndpi_strdup(flow->ndpi_flow->protos.telnet.password);
  } else if(is_ndpi_proto(flow, NDPI_PROTOCOL_SSH)) {
    ndpi_snprintf(flow->host_server_name,
	     sizeof(flow->host_server_name), "%s",
	     flow->ndpi_flow->protos.ssh.client_signature);
    ndpi_snprintf(flow->ssh_tls.server_info, sizeof(flow->ssh_tls.server_info), "%s",
	     flow->ndpi_flow->protos.ssh.server_signature);
    ndpi_snprintf(flow->ssh_tls.client_hassh, sizeof(flow->ssh_tls.client_hassh), "%s",
	     flow->ndpi_flow->protos.ssh.hassh_client);
    ndpi_snprintf(flow->ssh_tls.server_hassh, sizeof(flow->ssh_tls.server_hassh), "%s",
	     flow->ndpi_flow->protos.ssh.hassh_server);
  }
  /* TLS */
  else if(is_ndpi_proto(flow, NDPI_PROTOCOL_TLS)
          || is_ndpi_proto(flow, NDPI_PROTOCOL_DTLS)
          || is_ndpi_proto(flow, NDPI_PROTOCOL_MAIL_SMTPS)
          || is_ndpi_proto(flow, NDPI_PROTOCOL_MAIL_IMAPS)
          || is_ndpi_proto(flow, NDPI_PROTOCOL_MAIL_POPS)
          || is_ndpi_proto(flow, NDPI_PROTOCOL_FTPS)
	  || ((is_quic = is_ndpi_proto(flow, NDPI_PROTOCOL_QUIC)))
	  ) {
    flow->ssh_tls.ssl_version = flow->ndpi_flow->protos.tls_quic.ssl_version;

    if(flow->ndpi_flow->protos.tls_quic.server_names_len > 0 && flow->ndpi_flow->protos.tls_quic.server_names)
      flow->ssh_tls.server_names = ndpi_strdup(flow->ndpi_flow->protos.tls_quic.server_names);

    flow->ssh_tls.notBefore = flow->ndpi_flow->protos.tls_quic.notBefore;
    flow->ssh_tls.notAfter = flow->ndpi_flow->protos.tls_quic.notAfter;
    ndpi_snprintf(flow->ssh_tls.ja3_client, sizeof(flow->ssh_tls.ja3_client), "%s",
	     flow->ndpi_flow->protos.tls_quic.ja3_client);
    ndpi_snprintf(flow->ssh_tls.ja3_server, sizeof(flow->ssh_tls.ja3_server), "%s",
	     flow->ndpi_flow->protos.tls_quic.ja3_server);
    flow->ssh_tls.server_unsafe_cipher = flow->ndpi_flow->protos.tls_quic.server_unsafe_cipher;
    flow->ssh_tls.server_cipher = flow->ndpi_flow->protos.tls_quic.server_cipher;

    if(flow->ndpi_flow->protos.tls_quic.fingerprint_set) {
      memcpy(flow->ssh_tls.sha1_cert_fingerprint,
	     flow->ndpi_flow->protos.tls_quic.sha1_certificate_fingerprint, 20);
      flow->ssh_tls.sha1_cert_fingerprint_set = 1;
    }

    flow->ssh_tls.browser_heuristics = flow->ndpi_flow->protos.tls_quic.browser_heuristics;

    if(flow->ndpi_flow->protos.tls_quic.issuerDN)
      flow->ssh_tls.tls_issuerDN = strdup(flow->ndpi_flow->protos.tls_quic.issuerDN);

    if(flow->ndpi_flow->protos.tls_quic.subjectDN)
      flow->ssh_tls.tls_subjectDN = strdup(flow->ndpi_flow->protos.tls_quic.subjectDN);

    if(flow->ndpi_flow->protos.tls_quic.encrypted_sni.esni) {
      flow->ssh_tls.encrypted_sni.esni = strdup(flow->ndpi_flow->protos.tls_quic.encrypted_sni.esni);
      flow->ssh_tls.encrypted_sni.cipher_suite = flow->ndpi_flow->protos.tls_quic.encrypted_sni.cipher_suite;
    }

    if(flow->ndpi_flow->protos.tls_quic.tls_supported_versions) {
      if((flow->ssh_tls.tls_supported_versions = ndpi_strdup(flow->ndpi_flow->protos.tls_quic.tls_supported_versions)) != NULL)
	correct_csv_data_field(flow->ssh_tls.tls_supported_versions);
    }

    if(flow->ndpi_flow->protos.tls_quic.advertised_alpns) {
      if((flow->ssh_tls.advertised_alpns = ndpi_strdup(flow->ndpi_flow->protos.tls_quic.advertised_alpns)) != NULL)
	correct_csv_data_field(flow->ssh_tls.advertised_alpns);
    }

    if(flow->ndpi_flow->protos.tls_quic.negotiated_alpn) {
      if((flow->ssh_tls.negotiated_alpn = ndpi_strdup(flow->ndpi_flow->protos.tls_quic.negotiated_alpn)) != NULL)
	correct_csv_data_field(flow->ssh_tls.negotiated_alpn);
    }

    if(enable_doh_dot_detection) {
      /* For TLS we use TLS block lenght instead of payload lenght */
      ndpi_reset_bin(&flow->payload_len_bin);

      for(i=0; i<flow->ndpi_flow->l4.tcp.tls.num_tls_blocks; i++) {
	u_int16_t len = abs(flow->ndpi_flow->l4.tcp.tls.tls_application_blocks_len[i]);

	/* printf("[TLS_LEN] %u\n", len); */
	ndpi_inc_bin(&flow->payload_len_bin, plen2slot(len), 1);
      }
    }
  }

  ndpi_snprintf(flow->http.user_agent,
                sizeof(flow->http.user_agent),
                "%s", (flow->ndpi_flow->http.user_agent ? flow->ndpi_flow->http.user_agent : ""));

  if (workflow->ndpi_serialization_format != ndpi_serialization_format_unknown)
  {
    if (ndpi_flow2json(workflow->ndpi_struct, flow->ndpi_flow,
                       flow->ip_version, flow->protocol,
                       flow->src_ip, flow->dst_ip,
                       &flow->src_ip6, &flow->dst_ip6,
                       flow->src_port, flow->dst_port,
                       flow->detected_protocol,
                       &flow->ndpi_flow_serializer) != 0)
    {
      exit(-1);
    }
    ndpi_serialize_string_uint32(&flow->ndpi_flow_serializer, "detection_completed", flow->detection_completed);
    ndpi_serialize_string_uint32(&flow->ndpi_flow_serializer, "check_extra_packets", flow->check_extra_packets);
  }

  if(flow->detection_completed && (!flow->check_extra_packets)) {
   
    flow->flow_payload = flow->ndpi_flow->flow_payload, flow->flow_payload_len = flow->ndpi_flow->flow_payload_len;
    flow->ndpi_flow->flow_payload = NULL; /* We'll free the memory */

    ndpi_free_flow_info_half(flow);
  }
}

/**
   Function to process the packet:
   determine the flow of a packet and try to decode it
   @return: 0 if success; else != 0

   @Note: ipsize = header->len - ip_offset ; rawsize = header->len
*/
static struct ndpi_proto packet_processing(struct ndpi_workflow * workflow,
					   const u_int64_t time_ms,
					   u_int16_t vlan_id,
					   ndpi_packet_tunnel tunnel_type,
					   const struct ndpi_iphdr *iph,
					   struct ndpi_ipv6hdr *iph6,
					   u_int16_t ip_offset,
					   u_int16_t ipsize, u_int16_t rawsize,
					   const struct pcap_pkthdr *header,
					   const u_char *packet,
					   pkt_timeval when,
					   ndpi_risk *flow_risk) {
  struct ndpi_flow_info *flow = NULL;
  struct ndpi_flow_struct *ndpi_flow = NULL;
  u_int8_t proto;
  struct ndpi_tcphdr *tcph = NULL;
  struct ndpi_udphdr *udph = NULL;
  u_int16_t sport, dport, payload_len = 0;
  u_int8_t *payload;
  u_int8_t src_to_dst_direction = 1;
  u_int8_t begin_or_end_tcp = 0;
  struct ndpi_proto nproto = NDPI_PROTOCOL_NULL;

  if(workflow->prefs.ignore_vlanid)
    vlan_id = 0;

  if(iph)
    flow = get_ndpi_flow_info(workflow, IPVERSION, vlan_id,
			      tunnel_type, iph, NULL,
			      ip_offset, ipsize,
			      ntohs(iph->tot_len) ? (ntohs(iph->tot_len) - (iph->ihl * 4)) : ipsize - (iph->ihl * 4) /* TSO */,
			      iph->ihl * 4,
			      &tcph, &udph, &sport, &dport,
			      &proto,
			      &payload, &payload_len, &src_to_dst_direction, when);
  else
    flow = get_ndpi_flow_info6(workflow, vlan_id,
			       tunnel_type, iph6, ip_offset, ipsize,
			       &tcph, &udph, &sport, &dport,
			       &proto,
			       &payload, &payload_len, &src_to_dst_direction, when);

  if(flow != NULL) {
    pkt_timeval tdiff;

    workflow->stats.ip_packet_count++;
    workflow->stats.total_wire_bytes += rawsize + 24 /* CRC etc */,
      workflow->stats.total_ip_bytes += rawsize;
    ndpi_flow = flow->ndpi_flow;

    if(tcph != NULL){
//       update_tcp_flags_count(flow, tcph, src_to_dst_direction);
      if(tcph->syn && !flow->src2dst_bytes){
	flow->c_to_s_init_win = rawsize;
      }else if(tcph->syn && tcph->ack && flow->src2dst_bytes == flow->c_to_s_init_win){
	flow->s_to_c_init_win = rawsize;
      }
    }

    if((tcph != NULL) && (tcph->fin || tcph->rst || tcph->syn))
      begin_or_end_tcp = 1;

    if(flow->flow_last_pkt_time.tv_sec) {
      ndpi_timer_sub(&when, &flow->flow_last_pkt_time, &tdiff);

      if(flow->iat_flow
	 && (tdiff.tv_sec >= 0) /* Discard backward time */
	 ) {
	u_int32_t ms = ndpi_timeval_to_milliseconds(tdiff);

	if(ms > 0)
	  ndpi_data_add_value(flow->iat_flow, ms);
      }
    }

    memcpy(&flow->flow_last_pkt_time, &when, sizeof(when));

    if(src_to_dst_direction) {
      if(flow->src2dst_last_pkt_time.tv_sec) {
	ndpi_timer_sub(&when, &flow->src2dst_last_pkt_time, &tdiff);

	if(flow->iat_c_to_s
	   && (tdiff.tv_sec >= 0) /* Discard backward time */
	   ) {
	  u_int32_t ms = ndpi_timeval_to_milliseconds(tdiff);

	  ndpi_data_add_value(flow->iat_c_to_s, ms);
	}
      }

      ndpi_data_add_value(flow->pktlen_c_to_s, rawsize);
      flow->src2dst_packets++, flow->src2dst_bytes += rawsize, flow->src2dst_goodput_bytes += payload_len;
      memcpy(&flow->src2dst_last_pkt_time, &when, sizeof(when));

#ifdef DIRECTION_BINS
      if(payload_len && (flow->src2dst_packets < MAX_NUM_BIN_PKTS))
	ndpi_inc_bin(&flow->payload_len_bin_src2dst, plen2slot(payload_len));
#endif
    } else {
      if(flow->dst2src_last_pkt_time.tv_sec && (!begin_or_end_tcp)) {
	ndpi_timer_sub(&when, &flow->dst2src_last_pkt_time, &tdiff);

	if(flow->iat_s_to_c) {
	  u_int32_t ms = ndpi_timeval_to_milliseconds(tdiff);

	  ndpi_data_add_value(flow->iat_s_to_c, ms);
	}
      }
      ndpi_data_add_value(flow->pktlen_s_to_c, rawsize);
      flow->dst2src_packets++, flow->dst2src_bytes += rawsize, flow->dst2src_goodput_bytes += payload_len;
      flow->risk &= ~(1ULL << NDPI_UNIDIRECTIONAL_TRAFFIC); /* Clear bit */
      memcpy(&flow->dst2src_last_pkt_time, &when, sizeof(when));

#ifdef DIRECTION_BINS
      if(payload_len && (flow->dst2src_packets < MAX_NUM_BIN_PKTS))
	ndpi_inc_bin(&flow->payload_len_bin_dst2src, plen2slot(payload_len));
#endif
    }

#ifndef DIRECTION_BINS
    if(payload_len && ((flow->src2dst_packets+flow->dst2src_packets) < MAX_NUM_BIN_PKTS)) {
#if 0
      /* Discard packets until the protocol is detected */
      if(flow->detected_protocol.app_protocol != NDPI_PROTOCOL_UNKNOWN)
#endif
	ndpi_inc_bin(&flow->payload_len_bin, plen2slot(payload_len), 1);
    }
#endif

    if(enable_payload_analyzer && (payload_len > 0))
      ndpi_payload_analyzer(flow, src_to_dst_direction,
			    payload, payload_len,
			    workflow->stats.ip_packet_count);

    if(enable_flow_stats) {
      /* Update BD, distribution and mean. */
      ndpi_flow_update_byte_count(flow, payload, payload_len, src_to_dst_direction);
      ndpi_flow_update_byte_dist_mean_var(flow, payload, payload_len, src_to_dst_direction);
      /* Update SPLT scores for first 32 packets. */
      if((flow->entropy->src2dst_pkt_count+flow->entropy->dst2src_pkt_count) <= max_num_packets_per_flow) {
        if(flow->bidirectional)
          flow->entropy->score = ndpi_classify(flow->entropy->src2dst_pkt_len, flow->entropy->src2dst_pkt_time,
					      flow->entropy->dst2src_pkt_len, flow->entropy->dst2src_pkt_time,
					      flow->entropy->src2dst_start, flow->entropy->dst2src_start,
					      max_num_packets_per_flow, flow->src_port, flow->dst_port,
					      flow->src2dst_packets, flow->dst2src_packets,
					      flow->entropy->src2dst_opackets, flow->entropy->dst2src_opackets,
					      flow->entropy->src2dst_l4_bytes, flow->entropy->dst2src_l4_bytes, 1,
					      flow->entropy->src2dst_byte_count, flow->entropy->dst2src_byte_count);
	else
	  flow->entropy->score = ndpi_classify(flow->entropy->src2dst_pkt_len, flow->entropy->src2dst_pkt_time,
					      NULL, NULL, flow->entropy->src2dst_start, flow->entropy->src2dst_start,
					      max_num_packets_per_flow, flow->src_port, flow->dst_port,
					      flow->src2dst_packets, 0,
					      flow->entropy->src2dst_opackets, 0,
					      flow->entropy->src2dst_l4_bytes, 0, 1,
					      flow->entropy->src2dst_byte_count, NULL);
      }
    }

    if(flow->first_seen_ms == 0)
      flow->first_seen_ms = time_ms;

    flow->last_seen_ms = time_ms;

    /* Copy packets entropy if num packets count == 10 */
    ndpi_clear_entropy_stats(flow);
    /* Reset IAT reeference times (see https://github.com/ntop/nDPI/pull/1316) */
    if(((flow->src2dst_packets + flow->dst2src_packets) % max_num_packets_per_flow) == 0) {
      memset(&flow->src2dst_last_pkt_time, '\0', sizeof(flow->src2dst_last_pkt_time));
      memset(&flow->dst2src_last_pkt_time, '\0', sizeof(flow->dst2src_last_pkt_time));
      memset(&flow->flow_last_pkt_time, '\0', sizeof(flow->flow_last_pkt_time));
    }

    if((human_readeable_string_len != 0) && (!flow->has_human_readeable_strings)) {
      u_int8_t skip = 0;

      if((proto == IPPROTO_TCP)
	 && (
	     is_ndpi_proto(flow, NDPI_PROTOCOL_TLS)
	     || (flow->detected_protocol.master_protocol == NDPI_PROTOCOL_TLS)
	     || is_ndpi_proto(flow, NDPI_PROTOCOL_SSH)
	     || (flow->detected_protocol.master_protocol == NDPI_PROTOCOL_SSH))
	 ) {
	if((flow->src2dst_packets+flow->dst2src_packets) < 10 /* MIN_NUM_ENCRYPT_SKIP_PACKETS */)
	  skip = 1; /* Skip initial negotiation packets */
      }

      if((!skip) && ((flow->src2dst_packets+flow->dst2src_packets) < 100)) {
	if(ndpi_has_human_readeable_string(workflow->ndpi_struct, (char*)packet, header->caplen,
					   human_readeable_string_len,
					   flow->human_readeable_string_buffer,
					   sizeof(flow->human_readeable_string_buffer)) == 1)
	  flow->has_human_readeable_strings = 1;
      }
    } else {
      if((proto == IPPROTO_TCP)
	 && (
	     is_ndpi_proto(flow, NDPI_PROTOCOL_TLS)
	     || (flow->detected_protocol.master_protocol == NDPI_PROTOCOL_TLS)
	     || is_ndpi_proto(flow, NDPI_PROTOCOL_SSH)
	     || (flow->detected_protocol.master_protocol == NDPI_PROTOCOL_SSH))
	 )
	flow->has_human_readeable_strings = 0;
    }
  } else { // flow is NULL
    workflow->stats.total_discarded_bytes += header->len;
    return(nproto);
  }

  if(!flow->detection_completed) {
    struct ndpi_flow_input_info input_info;

    u_int enough_packets =
      (((proto == IPPROTO_UDP) && ((flow->src2dst_packets + flow->dst2src_packets) > max_num_udp_dissected_pkts))
       || ((proto == IPPROTO_TCP) && ((flow->src2dst_packets + flow->dst2src_packets) > max_num_tcp_dissected_pkts))) ? 1 : 0;

#if 0
    printf("%s()\n", __FUNCTION__);
#endif

    if(proto == IPPROTO_TCP)
      workflow->stats.dpi_packet_count[0]++;
    else if(proto == IPPROTO_UDP)
      workflow->stats.dpi_packet_count[1]++;
    else
      workflow->stats.dpi_packet_count[2]++;

    memset(&input_info, '\0', sizeof(input_info)); /* To be sure to set to "unknown" any fields */
    /* Set here any information (easily) available; in this trivial example we don't have any */
    input_info.in_pkt_dir = NDPI_IN_PKT_DIR_UNKNOWN;
    input_info.seen_flow_beginning = NDPI_FLOW_BEGINNING_UNKNOWN;
    malloc_size_stats = 1;
    flow->detected_protocol = ndpi_detection_process_packet(workflow->ndpi_struct, ndpi_flow,
							    iph ? (uint8_t *)iph : (uint8_t *)iph6,
							    ipsize, time_ms, &input_info);

    enough_packets |= ndpi_flow->fail_with_unknown;
    if(enough_packets || (flow->detected_protocol.app_protocol != NDPI_PROTOCOL_UNKNOWN)) {
      if((!enough_packets)
	 && ndpi_extra_dissection_possible(workflow->ndpi_struct, ndpi_flow))
	; /* Wait for certificate fingerprint */
      else {
	/* New protocol detected or give up */
	flow->detection_completed = 1;

#if 0
	/* Check if we should keep checking extra packets */
	if(ndpi_flow && ndpi_flow->check_extra_packets)
	  flow->check_extra_packets = 1;
#endif

	if(flow->detected_protocol.app_protocol == NDPI_PROTOCOL_UNKNOWN) {
	  u_int8_t proto_guessed;

	  flow->detected_protocol = ndpi_detection_giveup(workflow->ndpi_struct, flow->ndpi_flow,
							  enable_protocol_guess, &proto_guessed);
	  if(enable_protocol_guess) workflow->stats.guessed_flow_protocols++;
	}

	process_ndpi_collected_info(workflow, flow);
      }
    }
    malloc_size_stats = 0;
  }
  
#if 0
  if(flow->risk != 0) {
    FILE *r = fopen("/tmp/e", "a");

    if(r) {
      fprintf(r, "->>> %u [%08X]\n", flow->risk, flow->risk);
      fclose(r);
    }
  }
#endif

  *flow_risk = flow->risk;

  return(flow->detected_protocol);
}

/* ****************************************************** */

int ndpi_is_datalink_supported(int datalink_type) {
  /* Keep in sync with the similar switch in ndpi_workflow_process_packet */
  switch(datalink_type) {
  case DLT_NULL:
  case DLT_PPP_SERIAL:
  case DLT_C_HDLC:
  case DLT_PPP:
#ifdef DLT_IPV4
  case DLT_IPV4:
#endif
#ifdef DLT_IPV6
  case DLT_IPV6:
#endif
  case DLT_EN10MB:
  case DLT_LINUX_SLL:
  case DLT_IEEE802_11_RADIO:
  case DLT_RAW:
  case DLT_PPI:
    return 1;
  default:
    return 0;
  }
}

struct ndpi_proto ndpi_workflow_process_packet(struct ndpi_workflow * workflow,
					       const struct pcap_pkthdr *header,
					       const u_char *packet,
					       ndpi_risk *flow_risk) {
  /*
   * Declare pointers to packet headers
   */
  /* --- Ethernet header --- */
  const struct ndpi_ethhdr *ethernet;
  /* --- LLC header --- */
  const struct ndpi_llc_header_snap *llc;

  /* --- Cisco HDLC header --- */
  const struct ndpi_chdlc *chdlc;

  /* --- Radio Tap header --- */
  const struct ndpi_radiotap_header *radiotap;
  /* --- Wifi header --- */
  const struct ndpi_wifi_header *wifi;

  /* --- MPLS header --- */
  union mpls {
    uint32_t u32;
    struct ndpi_mpls_header mpls;
  } mpls;

  /** --- IP header --- **/
  struct ndpi_iphdr *iph;
  /** --- IPv6 header --- **/
  struct ndpi_ipv6hdr *iph6;

  struct ndpi_proto nproto = NDPI_PROTOCOL_NULL;
  ndpi_packet_tunnel tunnel_type = ndpi_no_tunnel;

  /* lengths and offsets */
  u_int32_t eth_offset = 0, dlt;
  u_int16_t radio_len, header_length;
  u_int16_t fc;
  u_int16_t type = 0;
  int wifi_len = 0;
  int pyld_eth_len = 0;
  int check;
  u_int64_t time_ms;
  u_int16_t ip_offset = 0, ip_len;
  u_int16_t frag_off = 0, vlan_id = 0;
  u_int8_t proto = 0, recheck_type;
  /*u_int32_t label;*/

  /* counters */
  u_int8_t vlan_packet = 0;

  *flow_risk = 0 /* NDPI_NO_RISK */;

  /* Increment raw packet counter */
  workflow->stats.raw_packet_count++;

  /* setting time */
  time_ms = ((uint64_t) header->ts.tv_sec) * TICK_RESOLUTION + header->ts.tv_usec / (1000000 / TICK_RESOLUTION);

  /* safety check */
  if(workflow->last_time > time_ms) {
    /* printf("\nWARNING: timestamp bug in the pcap file (ts delta: %llu, repairing)\n", ndpi_thread_info[thread_id].last_time - time); */
    time_ms = workflow->last_time;
  }
  /* update last time value */
  workflow->last_time = time_ms;

  /*** check Data Link type ***/
  int datalink_type;

#ifdef USE_DPDK
  datalink_type = DLT_EN10MB;
#else
  datalink_type = DLT_EN10MB;
#endif

 datalink_check:
  // 20 for min iph and 8 for min UDP
  if(header->caplen < eth_offset + 28)
    return(nproto); /* Too short */

  /* Keep in sync with ndpi_is_datalink_supported() */
  switch(datalink_type) {
  case DLT_NULL:
    if(ntohl(*((u_int32_t*)&packet[eth_offset])) == 2)
      type = ETH_P_IP;
    else
      type = ETH_P_IPV6;

    ip_offset = 4 + eth_offset;
    break;

    /* Cisco PPP in HDLC-like framing - 50 */
  case DLT_PPP_SERIAL:
    chdlc = (struct ndpi_chdlc *) &packet[eth_offset];
    ip_offset = eth_offset + sizeof(struct ndpi_chdlc); /* CHDLC_OFF = 4 */
    type = ntohs(chdlc->proto_code);
    break;

    /* Cisco PPP - 9 or 104 */
  case DLT_C_HDLC:
  case DLT_PPP:
    if(packet[0] == 0x0f || packet[0] == 0x8f) {
      chdlc = (struct ndpi_chdlc *) &packet[eth_offset];
      ip_offset = eth_offset + sizeof(struct ndpi_chdlc); /* CHDLC_OFF = 4 */
      type = ntohs(chdlc->proto_code);
    } else {
      ip_offset = eth_offset + 2;
      type = ntohs(*((u_int16_t*)&packet[eth_offset]));
    }
    break;

#ifdef DLT_IPV4
  case DLT_IPV4:
    type = ETH_P_IP;
    ip_offset = eth_offset;
    break;
#endif

#ifdef DLT_IPV6
  case DLT_IPV6:
    type = ETH_P_IPV6;
    ip_offset = eth_offset;
    break;
#endif

    /* IEEE 802.3 Ethernet - 1 */
  case DLT_EN10MB:
    ethernet = (struct ndpi_ethhdr *) &packet[eth_offset];
    ip_offset = sizeof(struct ndpi_ethhdr) + eth_offset;
    check = ntohs(ethernet->h_proto);

    if(check <= 1500)
      pyld_eth_len = check;
    else if(check >= 1536)
      type = check;

    if(pyld_eth_len != 0) {
      llc = (struct ndpi_llc_header_snap *)(&packet[ip_offset]);
      /* check for LLC layer with SNAP extension */
      if(llc->dsap == SNAP || llc->ssap == SNAP) {
	type = llc->snap.proto_ID;
	ip_offset += + 8;
      }
      /* No SNAP extension - Spanning Tree pkt must be discarted */
      else if(llc->dsap == BSTP || llc->ssap == BSTP) {
	goto v4_warning;
      }
    }
    break;

    /* Linux Cooked Capture - 113 */
  case DLT_LINUX_SLL:
    type = (packet[eth_offset+14] << 8) + packet[eth_offset+15];
    ip_offset = 16 + eth_offset;
    break;

    /* Linux Cooked Capture v2 - 276 */
  case LINKTYPE_LINUX_SLL2:
    type = (packet[eth_offset+10] << 8) + packet[eth_offset+11];
    ip_offset = 20 + eth_offset;
    break;

    /* Radiotap link-layer - 127 */
  case DLT_IEEE802_11_RADIO:
    radiotap = (struct ndpi_radiotap_header *) &packet[eth_offset];
    radio_len = radiotap->len;

    /* Check Bad FCS presence */
    if((radiotap->flags & BAD_FCS) == BAD_FCS) {
      workflow->stats.total_discarded_bytes +=  header->len;
      return(nproto);
    }

    if(header->caplen < (eth_offset + radio_len + sizeof(struct ndpi_wifi_header)))
      return(nproto);

    /* Calculate 802.11 header length (variable) */
    wifi = (struct ndpi_wifi_header*)( packet + eth_offset + radio_len);
    fc = wifi->fc;

    /* check wifi data presence */
    if(FCF_TYPE(fc) == WIFI_DATA) {
      if((FCF_TO_DS(fc) && FCF_FROM_DS(fc) == 0x0) ||
	 (FCF_TO_DS(fc) == 0x0 && FCF_FROM_DS(fc)))
	wifi_len = 26; /* + 4 byte fcs */
    } else   /* no data frames */
      return(nproto);

    /* Check ether_type from LLC */
    if(header->caplen < (eth_offset + wifi_len + radio_len + sizeof(struct ndpi_llc_header_snap)))
      return(nproto);
    llc = (struct ndpi_llc_header_snap*)(packet + eth_offset + wifi_len + radio_len);
    if(llc->dsap == SNAP)
      type = ntohs(llc->snap.proto_ID);

    /* Set IP header offset */
    ip_offset = wifi_len + radio_len + sizeof(struct ndpi_llc_header_snap) + eth_offset;
    break;

  case DLT_RAW:
    ip_offset = eth_offset;
    break;

  case DLT_PPI:
    header_length = le16toh(*(u_int16_t *)&packet[eth_offset + 2]);
    dlt = le32toh(*(u_int32_t *)&packet[eth_offset + 4]);
    if(dlt != DLT_EN10MB) /* Handle only standard ethernet, for the time being */
      return(nproto);
    datalink_type = DLT_EN10MB;
    eth_offset += header_length;
    goto datalink_check;

  default:
    /*
     * We shoudn't be here, because we already checked that this datalink is supported.
     * Should ndpi_is_datalink_supported() be updated?
     */
    printf("Unknown datalink %d\n", datalink_type);
    return(nproto);
  }

 ether_type_check:
  recheck_type = 0;

  /* check ether type */
  switch(type) {
  case ETH_P_VLAN:
    if(ip_offset+4 >= (int)header->caplen)
      return(nproto);
    vlan_id = ((packet[ip_offset] << 8) + packet[ip_offset+1]) & 0xFFF;
    type = (packet[ip_offset+2] << 8) + packet[ip_offset+3];
    ip_offset += 4;
    vlan_packet = 1;

    // double tagging for 802.1Q
    while((type == 0x8100) && (((bpf_u_int32)ip_offset+4) < header->caplen)) {
      vlan_id = ((packet[ip_offset] << 8) + packet[ip_offset+1]) & 0xFFF;
      type = (packet[ip_offset+2] << 8) + packet[ip_offset+3];
      ip_offset += 4;
    }
    recheck_type = 1;
    break;

  case ETH_P_MPLS_UNI:
  case ETH_P_MPLS_MULTI:
    if(ip_offset+4 >= (int)header->caplen)
      return(nproto);
    mpls.u32 = *((uint32_t *) &packet[ip_offset]);
    mpls.u32 = ntohl(mpls.u32);
    workflow->stats.mpls_count++;
    type = ETH_P_IP, ip_offset += 4;

    while(!mpls.mpls.s && (((bpf_u_int32)ip_offset) + 4 < header->caplen)) {
      mpls.u32 = *((uint32_t *) &packet[ip_offset]);
      mpls.u32 = ntohl(mpls.u32);
      ip_offset += 4;
    }
    recheck_type = 1;
    break;

  case ETH_P_PPPoE:
    workflow->stats.pppoe_count++;
    type = ETH_P_IP;
    ip_offset += 8;
    recheck_type = 1;
    break;

  default:
    break;
  }

  if(recheck_type)
    goto ether_type_check;

  workflow->stats.vlan_count += vlan_packet;

 iph_check:
  /* Check and set IP header size and total packet length */
  if(header->caplen < ip_offset + sizeof(struct ndpi_iphdr))
    return(nproto); /* Too short for next IP header*/

  iph = (struct ndpi_iphdr *) &packet[ip_offset];

  /* just work on Ethernet packets that contain IP */
  if(type == ETH_P_IP && header->caplen >= ip_offset) {
    frag_off = ntohs(iph->frag_off);

    proto = iph->protocol;
    if(header->caplen < header->len) {
      static u_int8_t cap_warning_used = 0;

      if(cap_warning_used == 0) {
	if(!workflow->prefs.quiet_mode)
	cap_warning_used = 1;
      }
    }
  }

  if(iph->version == IPVERSION) {
    ip_len = ((u_int16_t)iph->ihl * 4);
    iph6 = NULL;

    if(iph->protocol == IPPROTO_IPV6
       || iph->protocol == NDPI_IPIP_PROTOCOL_TYPE
       ) {
      ip_offset += ip_len;
      if(ip_len > 0)
        goto iph_check;
    }

    if((frag_off & 0x1FFF) != 0) {
      static u_int8_t ipv4_frags_warning_used = 0;
      workflow->stats.fragmented_count++;

      if(ipv4_frags_warning_used == 0) {
	if(!workflow->prefs.quiet_mode)
	ipv4_frags_warning_used = 1;
      }

      workflow->stats.total_discarded_bytes +=  header->len;
      return(nproto);
    }
  } else if(iph->version == 6) {
    if(header->caplen < ip_offset + sizeof(struct ndpi_ipv6hdr))
      return(nproto); /* Too short for IPv6 header*/

    iph6 = (struct ndpi_ipv6hdr *)&packet[ip_offset];
    proto = iph6->ip6_hdr.ip6_un1_nxt;
    ip_len = ntohs(iph6->ip6_hdr.ip6_un1_plen);

    if(header->caplen < (ip_offset + sizeof(struct ndpi_ipv6hdr) + ntohs(iph6->ip6_hdr.ip6_un1_plen)))
      return(nproto); /* Too short for IPv6 payload*/

    const u_int8_t *l4ptr = (((const u_int8_t *) iph6) + sizeof(struct ndpi_ipv6hdr));
    u_int16_t ipsize = header->caplen - ip_offset;

    if(ndpi_handle_ipv6_extension_headers(ipsize - sizeof(struct ndpi_ipv6hdr), &l4ptr, &ip_len, &proto) != 0) {
      return(nproto);
    }

    if(proto == IPPROTO_IPV6
       || proto == NDPI_IPIP_PROTOCOL_TYPE
       ) {
      if(l4ptr > packet) { /* Better safe than sorry */
        ip_offset = (l4ptr - packet);
        goto iph_check;
      }
    }

    iph = NULL;
  } else {
    static u_int8_t ipv4_warning_used = 0;

  v4_warning:
    if(ipv4_warning_used == 0) {
      if(!workflow->prefs.quiet_mode)
      ipv4_warning_used = 1;
    }

    workflow->stats.total_discarded_bytes +=  header->len;
    return(nproto);
  }

  if(workflow->prefs.decode_tunnels && (proto == IPPROTO_UDP)) {
    if(header->caplen < ip_offset + ip_len + sizeof(struct ndpi_udphdr))
      return(nproto); /* Too short for UDP header*/
    else {
      struct ndpi_udphdr *udp = (struct ndpi_udphdr *)&packet[ip_offset+ip_len];
      u_int16_t sport = ntohs(udp->source), dport = ntohs(udp->dest);

      if(((sport == GTP_U_V1_PORT) || (dport == GTP_U_V1_PORT)) &&
         (ip_offset + ip_len + sizeof(struct ndpi_udphdr) + 8 /* Minimum GTPv1 header len */ < header->caplen)) {
	/* Check if it's GTPv1 */
	u_int offset = ip_offset+ip_len+sizeof(struct ndpi_udphdr);
	u_int8_t flags = packet[offset];
	u_int8_t message_type = packet[offset+1];
	u_int8_t exts_parsing_error = 0;

	if((((flags & 0xE0) >> 5) == 1 /* GTPv1 */) &&
	   (message_type == 0xFF /* T-PDU */)) {

	  offset += 8; /* GTPv1 header len */
	  if(flags & 0x07)
	    offset += 4; /* sequence_number + pdu_number + next_ext_header fields */
	  /* Extensions parsing */
	  if(flags & 0x04) {
	    unsigned int ext_length = 0;

	    while(offset < header->caplen) {
	      ext_length = packet[offset] << 2;
	      offset += ext_length;
	      if(offset >= header->caplen || ext_length == 0) {
	        exts_parsing_error = 1;
	        break;
	      }
	      if(packet[offset - 1] == 0)
	        break;
	    }
	  }

	  if(offset < header->caplen && !exts_parsing_error) {
	    /* Ok, valid GTP-U */
	    tunnel_type = ndpi_gtp_tunnel;
	    ip_offset = offset;
	    iph = (struct ndpi_iphdr *)&packet[ip_offset];
	    if(iph->version == 6) {
	      iph6 = (struct ndpi_ipv6hdr *)&packet[ip_offset];
	      iph = NULL;
              if(header->caplen < ip_offset + sizeof(struct ndpi_ipv6hdr))
	        return(nproto);
	    } else if(iph->version != IPVERSION) {
	      // printf("WARNING: not good (packet_id=%u)!\n", (unsigned int)workflow->stats.raw_packet_count);
	      goto v4_warning;
	    } else {
              if(header->caplen < ip_offset + sizeof(struct ndpi_iphdr))
	        return(nproto);
	    }
	  }
	}
      } else if((sport == TZSP_PORT) || (dport == TZSP_PORT)) {
	/* https://en.wikipedia.org/wiki/TZSP */
	if(header->caplen < ip_offset + ip_len + sizeof(struct ndpi_udphdr) + 4)
	  return(nproto); /* Too short for TZSP*/

	u_int offset           = ip_offset+ip_len+sizeof(struct ndpi_udphdr);
	u_int8_t version       = packet[offset];
	u_int8_t ts_type       = packet[offset+1];
	u_int16_t encapsulates = ntohs(*((u_int16_t*)&packet[offset+2]));

	tunnel_type = ndpi_tzsp_tunnel;

	if((version == 1) && (ts_type == 0) && (encapsulates == 1)) {
	  u_int8_t stop = 0;

	  offset += 4;

	  while((!stop) && (offset < header->caplen)) {
	    u_int8_t tag_type = packet[offset];
	    u_int8_t tag_len;

	    switch(tag_type) {
	    case 0: /* PADDING Tag */
	      tag_len = 1;
	      break;
	    case 1: /* END Tag */
	      tag_len = 1, stop = 1;
	      break;
	    default:
	      if(offset + 1 >= header->caplen)
	        return(nproto); /* Invalid packet */
	      tag_len = packet[offset+1];
	      break;
	    }

	    offset += tag_len;

	    if(offset >= header->caplen)
	      return(nproto); /* Invalid packet */
	    else {
	      eth_offset = offset;
	      goto datalink_check;
	    }
	  }
	}
      } else if((sport == NDPI_CAPWAP_DATA_PORT) || (dport == NDPI_CAPWAP_DATA_PORT)) {
	/* We dissect ONLY CAPWAP traffic */
	u_int offset           = ip_offset+ip_len+sizeof(struct ndpi_udphdr);

	if((offset+1) < header->caplen) {
	  uint8_t preamble = packet[offset];

	  if((preamble & 0x0F) == 0) { /* CAPWAP header */
	    u_int16_t msg_len = (packet[offset+1] & 0xF8) >> 1;

	    offset += msg_len;

	    if((offset + 32 < header->caplen) &&
	       (packet[offset + 1] == 0x08)) {
	      /* IEEE 802.11 Data */
	      offset += 24;
	      /* LLC header is 8 bytes */
	      type = ntohs((u_int16_t)*((u_int16_t*)&packet[offset+6]));

	      ip_offset = offset + 8;

	      tunnel_type = ndpi_capwap_tunnel;
	      goto iph_check;
	    }
	  }
	}
      }
    }
  }

  /* process the packet */
  return(packet_processing(workflow, time_ms, vlan_id, tunnel_type, iph, iph6,
			   ip_offset, header->caplen - ip_offset,
			   header->caplen, header, packet, header->ts,
			   flow_risk));
}

ndpi_port_range *ndpi_build_default_ports(ndpi_port_range *ports, u_int16_t portA, u_int16_t portB, u_int16_t portC,
                                          u_int16_t portD, u_int16_t portE) {
  int i = 0;

  ports[i].port_low = portA, ports[i].port_high = portA;
  i++;
  ports[i].port_low = portB, ports[i].port_high = portB;
  i++;
  ports[i].port_low = portC, ports[i].port_high = portC;
  i++;
  ports[i].port_low = portD, ports[i].port_high = portD;
  i++;
  ports[i].port_low = portE, ports[i].port_high = portE;

  return(ports);
}

static void addDefaultPort(struct ndpi_detection_module_struct *ndpi_str,
                           ndpi_port_range *range,
                           ndpi_proto_defaults_t *def,
			   u_int8_t customUserProto,
			   ndpi_default_ports_tree_node_t **root,
                           const char *_func,
			   int _line) {
  u_int32_t port;

  for(port = range->port_low; port <= range->port_high; port++) {
    ndpi_default_ports_tree_node_t *node =
      (ndpi_default_ports_tree_node_t *) ndpi_malloc(sizeof(ndpi_default_ports_tree_node_t));
    ndpi_default_ports_tree_node_t *ret;

    if(!node) {
      NDPI_LOG_ERR(ndpi_str, "%s:%d not enough memory\n", _func, _line);
      break;
    }

    node->proto = def, node->default_port = port, node->customUserProto = customUserProto;
    ret = (ndpi_default_ports_tree_node_t *) ndpi_tsearch(node,
							  (void *) root,
							  ndpi_default_ports_tree_node_t_cmp); /* Add it to the tree */

    if(ret == NULL) {
      NDPI_LOG_DBG(ndpi_str, "[NDPI] %s:%d error searching for port %u\n", _func, _line, port);
      ndpi_free(node);
      break;
    }
    if(ret != node) {
      NDPI_LOG_DBG(ndpi_str, "[NDPI] %s:%d found duplicate for port %u: overwriting it with new value\n",
		   _func, _line, port);

      ret->proto = def;
      ndpi_free(node);
    }
  }
}

/* ntop */
void ndpi_set_bitmask_protocol_detection(char *label, struct ndpi_detection_module_struct *ndpi_str,
                                         const u_int32_t idx,
                                         u_int16_t ndpi_protocol_id,
                                         void (*func)(struct ndpi_detection_module_struct *,
                                                      struct ndpi_flow_struct *flow),
                                         const NDPI_SELECTION_BITMASK_PROTOCOL_SIZE ndpi_selection_bitmask,
                                         u_int8_t b_save_bitmask_unknow, u_int8_t b_add_detection_bitmask) {
  /*
    Compare specify protocol bitmask with main detection bitmask
  */
  if(is_proto_enabled(ndpi_str, ndpi_protocol_id)) {
#ifdef DEBUG
    NDPI_LOG_DBG2(ndpi_str,
		  "[NDPI] ndpi_set_bitmask_protocol_detection: %s : [callback_buffer] idx= %u, [proto_defaults] "
		  "protocol_id=%u\n",
		  label, idx, ndpi_protocol_id);
#endif

    if(ndpi_str->proto_defaults[ndpi_protocol_id].protoIdx != 0) {
      NDPI_LOG_DBG2(ndpi_str, "[NDPI] Internal error: protocol %s/%u has been already registered\n", label,
		    ndpi_protocol_id);
#ifdef DEBUG
    } else {
      NDPI_LOG_DBG2(ndpi_str, "[NDPI] Adding %s with protocol id %d\n", label, ndpi_protocol_id);
#endif
    }

    /*
      Set function and index protocol within proto_default structure for port protocol detection
      and callback_buffer function for DPI protocol detection
    */
    ndpi_str->proto_defaults[ndpi_protocol_id].protoIdx = idx;
    ndpi_str->proto_defaults[ndpi_protocol_id].func = ndpi_str->callback_buffer[idx].func = func;
    ndpi_str->callback_buffer[idx].ndpi_protocol_id = ndpi_protocol_id;

    /*
      Set ndpi_selection_bitmask for protocol
    */
    ndpi_str->callback_buffer[idx].ndpi_selection_bitmask = ndpi_selection_bitmask;

    /*
      Reset protocol detection bitmask via NDPI_PROTOCOL_UNKNOWN and than add specify protocol bitmast to callback
      buffer.
    */
    if(b_save_bitmask_unknow)
      NDPI_SAVE_AS_BITMASK(ndpi_str->callback_buffer[idx].detection_bitmask, NDPI_PROTOCOL_UNKNOWN);
    if(b_add_detection_bitmask)
      NDPI_ADD_PROTOCOL_TO_BITMASK(ndpi_str->callback_buffer[idx].detection_bitmask, ndpi_protocol_id);

    NDPI_SAVE_AS_BITMASK(ndpi_str->callback_buffer[idx].excluded_protocol_bitmask, ndpi_protocol_id);
  } else {
      NDPI_LOG_DBG(ndpi_str, "[NDPI] Protocol %s/%u disabled\n", label, ndpi_protocol_id);
  }
}

int ndpi_add_string_value_to_automa(void *_automa, char *str, u_int32_t num) {
  AC_PATTERN_t ac_pattern;
  AC_AUTOMATA_t *automa = (AC_AUTOMATA_t *) _automa;
  AC_ERROR_t rc;

  if(automa == NULL)
    return(-1);

  memset(&ac_pattern, 0, sizeof(ac_pattern));
  ac_pattern.astring    = str;
  ac_pattern.rep.number = num;
  ac_pattern.length     = strlen(ac_pattern.astring);

  rc = ac_automata_add(automa, &ac_pattern);
  return(rc == ACERR_SUCCESS || rc == ACERR_DUPLICATE_PATTERN ? 0 : -1);
}

void ndpi_set_proto_defaults(struct ndpi_detection_module_struct *ndpi_str,
			     u_int8_t is_cleartext, u_int8_t is_app_protocol,
			     ndpi_protocol_breed_t breed,
			     u_int16_t protoId, char *protoName,
			     ndpi_protocol_category_t protoCategory,
			     ndpi_port_range *tcpDefPorts,
			     ndpi_port_range *udpDefPorts) {
  char *name;
  int j;

  if(!ndpi_is_valid_protoId(protoId)) {
#ifdef DEBUG
    NDPI_LOG_ERR(ndpi_str, "[NDPI] %s/protoId=%d: INTERNAL ERROR\n", protoName, protoId);
#endif
    return;
  }

  if(ndpi_str->proto_defaults[protoId].protoName != NULL) {
#ifdef DEBUG
    NDPI_LOG_ERR(ndpi_str, "[NDPI] %s/protoId=%d: already initialized. Ignoring it\n", protoName, protoId);
#endif
    return;
  }

  name = ndpi_strdup(protoName);
  if(!name) {
#ifdef DEBUG
    NDPI_LOG_ERR(ndpi_str, "[NDPI] %s/protoId=%d: mem allocation error\n", protoName, protoId);
#endif
    return;
  }

  if(ndpi_str->proto_defaults[protoId].protoName)
    ndpi_free(ndpi_str->proto_defaults[protoId].protoName);

  ndpi_str->proto_defaults[protoId].isClearTextProto = is_cleartext;
  /*
    is_appprotocol=1 means that this is only an application protocol layered
    on top of a network protocol. Example WhatsApp=1, TLS=0
  */
  ndpi_str->proto_defaults[protoId].isAppProtocol = is_app_protocol;
  ndpi_str->proto_defaults[protoId].protoName = name;
  ndpi_str->proto_defaults[protoId].protoCategory = protoCategory;
  ndpi_str->proto_defaults[protoId].protoId = protoId;
  ndpi_str->proto_defaults[protoId].protoBreed = breed;
  ndpi_str->proto_defaults[protoId].subprotocols = NULL;
  ndpi_str->proto_defaults[protoId].subprotocol_count = 0;

  if(!is_proto_enabled(ndpi_str, protoId)) {
    NDPI_LOG_DBG(ndpi_str, "[NDPI] Skip default ports for %s/protoId=%d: disabled\n", protoName, protoId);
    return;
  }

  for(j = 0; j < MAX_DEFAULT_PORTS; j++) {
    if(udpDefPorts[j].port_low != 0)
      addDefaultPort(ndpi_str, &udpDefPorts[j], &ndpi_str->proto_defaults[protoId], 0, &ndpi_str->udpRoot,
		     __FUNCTION__, __LINE__);

    if(tcpDefPorts[j].port_low != 0)
      addDefaultPort(ndpi_str, &tcpDefPorts[j], &ndpi_str->proto_defaults[protoId], 0, &ndpi_str->tcpRoot,
		     __FUNCTION__, __LINE__);

    /* No port range, just the lower port */
    ndpi_str->proto_defaults[protoId].tcp_default_ports[j] = tcpDefPorts[j].port_low;
    ndpi_str->proto_defaults[protoId].udp_default_ports[j] = udpDefPorts[j].port_low;
  }
}

static void ndpi_xgrams_init(unsigned int *dst,size_t dn, const char **src,size_t sn, unsigned int l) {
  unsigned int i,j,c;
  for(i=0;i < sn && src[i]; i++) {
    for(j=0,c=0; j < l; j++) {
      unsigned char a = (unsigned char)src[i][j];
      if(a < 'a' || a > 'z') { printf("%u: c%u %c\n",i,j,a); abort(); }
      c *= XGRAMS_C;
      c += a - 'a';
    }
    if(src[i][l]) { printf("%u: c[%d] != 0\n",i,l); abort(); }
    if((c >> 3) >= dn) abort();
    dst[c >> 5] |= 1u << (c & 0x1f);
  }
}

int ndpi_match_string_value(void *automa, char *string_to_match,
			    u_int match_len, u_int32_t *num) {
  int rc = ndpi_match_string_common((AC_AUTOMATA_t *)automa, string_to_match,
				    match_len, num, NULL, NULL);
  if(rc < 0) return rc;
  return rc ? 0 : -1;
}

u_int32_t ndpi_bytestream_to_number(const u_int8_t *str, u_int16_t max_chars_to_read, u_int16_t *bytes_read) {
  u_int32_t val;
  val = 0;

  // cancel if eof, ' ' or line end chars are reached
  while(*str >= '0' && *str <= '9' && max_chars_to_read > 0) {
    val *= 10;
    val += *str - '0';
    str++;
    max_chars_to_read = max_chars_to_read - 1;
    *bytes_read = *bytes_read + 1;
  }

  return(val);
}

u_int16_t ntohs_ndpi_bytestream_to_number(const u_int8_t *str,
					  u_int16_t max_chars_to_read, u_int16_t *bytes_read) {
  u_int16_t val = ndpi_bytestream_to_number(str, max_chars_to_read, bytes_read);
  return(ntohs(val));
}

void ndpi_check_subprotocol_risk(struct ndpi_detection_module_struct *ndpi_str,
				 struct ndpi_flow_struct *flow, u_int16_t subprotocol_id) {
  switch(subprotocol_id) {
  case NDPI_PROTOCOL_ANYDESK:
    ndpi_set_risk(ndpi_str, flow, NDPI_DESKTOP_OR_FILE_SHARING_SESSION, "Found AnyDesk"); /* Remote assistance */
    break;
  }
}

u_int32_t ndpi_bytestream_to_ipv4(const u_int8_t *str, u_int16_t max_chars_to_read, u_int16_t *bytes_read) {
  u_int32_t val;
  u_int16_t read = 0;
  u_int16_t oldread;
  u_int32_t c;

  /* ip address must be X.X.X.X with each X between 0 and 255 */
  oldread = read;
  c = ndpi_bytestream_to_number(str, max_chars_to_read, &read);
  if(c > 255 || oldread == read || max_chars_to_read == read || str[read] != '.')
    return(0);

  read++;
  val = c << 24;
  oldread = read;
  c = ndpi_bytestream_to_number(&str[read], max_chars_to_read - read, &read);
  if(c > 255 || oldread == read || max_chars_to_read == read || str[read] != '.')
    return(0);

  read++;
  val = val + (c << 16);
  oldread = read;
  c = ndpi_bytestream_to_number(&str[read], max_chars_to_read - read, &read);
  if(c > 255 || oldread == read || max_chars_to_read == read || str[read] != '.')
    return(0);

  read++;
  val = val + (c << 8);
  oldread = read;
  c = ndpi_bytestream_to_number(&str[read], max_chars_to_read - read, &read);
  if(c > 255 || oldread == read || max_chars_to_read == read)
    return(0);

  val = val + c;

  *bytes_read = *bytes_read + read;

  return(htonl(val));
}

static u_int8_t ndpi_is_more_generic_protocol(u_int16_t previous_proto, u_int16_t new_proto) {
  /* Sometimes certificates are more generic than previously identified protocols */

  if((previous_proto == NDPI_PROTOCOL_UNKNOWN) || (previous_proto == new_proto))
    return(0);

  switch(previous_proto) {
  case NDPI_PROTOCOL_WHATSAPP_CALL:
  case NDPI_PROTOCOL_WHATSAPP_FILES:
    if(new_proto == NDPI_PROTOCOL_WHATSAPP)
      return(1);
    break;
  case NDPI_PROTOCOL_FACEBOOK_VOIP:
    if(new_proto == NDPI_PROTOCOL_FACEBOOK)
      return(1);
    break;
  }

  return(0);
}

static void init_string_based_protocols(struct ndpi_detection_module_struct *ndpi_str) {
  int i;

  for(i = 0; host_match[i].string_to_match != NULL; i++)
    ndpi_init_protocol_match(ndpi_str, &host_match[i]);

  /* ************************ */

  for(i = 0; tls_certificate_match[i].string_to_match != NULL; i++) {

#if 0
    printf("%s() %s / %u\n", __FUNCTION__,
	   tls_certificate_match[i].string_to_match,
	   tls_certificate_match[i].protocol_id);
#endif

    if(!is_proto_enabled(ndpi_str, tls_certificate_match[i].protocol_id)) {
      NDPI_LOG_DBG(ndpi_str, "[NDPI] Skip tls cert match for %s/protoId=%d: disabled\n",
		   tls_certificate_match[i].string_to_match, tls_certificate_match[i].protocol_id);
      continue;
    }
    /* Note: string_to_match is not malloc'ed here as ac_automata_release is
     * called with free_pattern = 0 */
    ndpi_add_string_value_to_automa(ndpi_str->tls_cert_subject_automa.ac_automa,
				    tls_certificate_match[i].string_to_match,
                                    tls_certificate_match[i].protocol_id);
  }

  /* ************************ */

  ndpi_enable_loaded_categories(ndpi_str);

#ifdef MATCH_DEBUG
  // ac_automata_display(ndpi_str->host_automa.ac_automa, 'n');
#endif
  if(!ndpi_xgrams_inited) {
    ndpi_xgrams_inited = 1;
    ndpi_xgrams_init(bigrams_bitmap,sizeof(bigrams_bitmap),
		     ndpi_en_bigrams,sizeof(ndpi_en_bigrams)/sizeof(ndpi_en_bigrams[0]), 2);

    ndpi_xgrams_init(imposible_bigrams_bitmap,sizeof(imposible_bigrams_bitmap),
		     ndpi_en_impossible_bigrams,sizeof(ndpi_en_impossible_bigrams)/sizeof(ndpi_en_impossible_bigrams[0]), 2);
    ndpi_xgrams_init(trigrams_bitmap,sizeof(trigrams_bitmap),
		     ndpi_en_trigrams,sizeof(ndpi_en_trigrams)/sizeof(ndpi_en_trigrams[0]), 3);
  }
}

/*
 * Find the first occurrence of find in s, where the search is limited to the
 * first slen characters of s.
 */
char *ndpi_strnstr(const char *s, const char *find, size_t slen) {
  char c;
  size_t len;

  if((c = *find++) != '\0') {
    len = strnlen(find, slen);
    do {
      char sc;

      do {
	if(slen-- < 1 || (sc = *s++) == '\0')
	  return(NULL);
      } while(sc != c);
      if(len > slen)
	return(NULL);
    } while(strncmp(s, find, len) != 0);
    s--;
  }

  return((char *) s);
}

char *ndpi_user_agent_set(struct ndpi_flow_struct *flow,
			  const u_int8_t *value, size_t value_len) {
  if(flow->http.user_agent != NULL) {
    /* Already set: ignore double set */
    return NULL;
  }
  if(value_len == 0) {
    return NULL;
  }

  flow->http.user_agent = ndpi_malloc(value_len + 1);
  if(flow->http.user_agent != NULL) {
    memcpy(flow->http.user_agent, value, value_len);
    flow->http.user_agent[value_len] = '\0';
  }

  return flow->http.user_agent;
}

int ndpi_match_hostname_protocol(struct ndpi_detection_module_struct *ndpi_struct,
				 struct ndpi_flow_struct *flow,
				 u_int16_t master_protocol, char *name, u_int name_len) {
  ndpi_protocol_match_result ret_match;
  u_int16_t subproto, what_len;
  char *what;

  if((name_len > 2) && (name[0] == '*') && (name[1] == '.'))
    what = &name[1], what_len = name_len - 1;
  else
    what = name, what_len = name_len;

  subproto = ndpi_match_host_subprotocol(ndpi_struct, flow, what, what_len,
					 &ret_match, master_protocol);

  if(subproto != NDPI_PROTOCOL_UNKNOWN) {
    ndpi_set_detected_protocol(ndpi_struct, flow, subproto, master_protocol, NDPI_CONFIDENCE_DPI);
    if(!category_depends_on_master(master_protocol))
      ndpi_int_change_category(ndpi_struct, flow, ret_match.protocol_category);
    return(1);
  } else
    return(0);
}

int ndpi_current_pkt_from_server_to_client(const struct ndpi_packet_struct *packet,
					   const struct ndpi_flow_struct *flow)
{
  return packet->packet_direction != flow->client_packet_direction;
}

void ndpi_parse_single_packet_line(struct ndpi_detection_module_struct *ndpi_str, struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &ndpi_str->packet;

  /* First line of a HTTP response parsing. Expected a "HTTP/1.? ???" */
  if(packet->parsed_lines == 0 && packet->line[0].len >= NDPI_STATICSTRING_LEN("HTTP/1.X 200 ") &&
     strncasecmp((const char *) packet->line[0].ptr, "HTTP/1.", NDPI_STATICSTRING_LEN("HTTP/1.")) == 0 &&
     packet->line[0].ptr[NDPI_STATICSTRING_LEN("HTTP/1.X ")] > '0' && /* response code between 000 and 699 */
     packet->line[0].ptr[NDPI_STATICSTRING_LEN("HTTP/1.X ")] < '6') {
    packet->http_response.ptr = &packet->line[0].ptr[NDPI_STATICSTRING_LEN("HTTP/1.1 ")];
    packet->http_response.len = packet->line[0].len - NDPI_STATICSTRING_LEN("HTTP/1.1 ");
    packet->http_num_headers++;

    /* Set server HTTP response code */
    if(packet->payload_packet_len >= 12) {
      char buf[4];

      /* Set server HTTP response code */
      strncpy(buf, (char *) &packet->payload[9], 3);
      buf[3] = '\0';

      flow->http.response_status_code = atoi(buf);
      /* https://en.wikipedia.org/wiki/List_of_HTTP_status_codes */
      if((flow->http.response_status_code < 100) || (flow->http.response_status_code > 509))
	flow->http.response_status_code = 0; /* Out of range */
    }
  }

  if((packet->parsed_lines == 0) && (packet->line[0].len > 0)) {
    /*
       Check if the file contains a : otherwise ignore the line as this
       line i slike "GET /....
    */

    if(memchr((char*)packet->line[0].ptr, ':', packet->line[0].len) == NULL)
      return;
  }

  /* "Server:" header line in HTTP response */
  if(packet->line[packet->parsed_lines].len > NDPI_STATICSTRING_LEN("Server:") + 1 &&
     strncasecmp((const char *) packet->line[packet->parsed_lines].ptr,
		 "Server:", NDPI_STATICSTRING_LEN("Server:")) == 0) {
    // some stupid clients omit a space and place the servername directly after the colon
    if(packet->line[packet->parsed_lines].ptr[NDPI_STATICSTRING_LEN("Server:")] == ' ') {
      packet->server_line.ptr =
	&packet->line[packet->parsed_lines].ptr[NDPI_STATICSTRING_LEN("Server:") + 1];
      packet->server_line.len =
	packet->line[packet->parsed_lines].len - (NDPI_STATICSTRING_LEN("Server:") + 1);
    } else {
      packet->server_line.ptr = &packet->line[packet->parsed_lines].ptr[NDPI_STATICSTRING_LEN("Server:")];
      packet->server_line.len = packet->line[packet->parsed_lines].len - NDPI_STATICSTRING_LEN("Server:");
    }
    packet->http_num_headers++;
  } else
    /* "Host:" header line in HTTP request */
    if(packet->line[packet->parsed_lines].len > 6 &&
       strncasecmp((const char *) packet->line[packet->parsed_lines].ptr, "Host:", 5) == 0) {
      // some stupid clients omit a space and place the hostname directly after the colon
      if(packet->line[packet->parsed_lines].ptr[5] == ' ') {
	packet->host_line.ptr = &packet->line[packet->parsed_lines].ptr[6];
	packet->host_line.len = packet->line[packet->parsed_lines].len - 6;
      } else {
	packet->host_line.ptr = &packet->line[packet->parsed_lines].ptr[5];
	packet->host_line.len = packet->line[packet->parsed_lines].len - 5;
      }
      packet->http_num_headers++;
    } else
      /* "X-Forwarded-For:" header line in HTTP request. Commonly used for HTTP proxies. */
      if(packet->line[packet->parsed_lines].len > 17 &&
	 strncasecmp((const char *) packet->line[packet->parsed_lines].ptr, "X-Forwarded-For:", 16) == 0) {
	// some stupid clients omit a space and place the hostname directly after the colon
	if(packet->line[packet->parsed_lines].ptr[16] == ' ') {
	  packet->forwarded_line.ptr = &packet->line[packet->parsed_lines].ptr[17];
	  packet->forwarded_line.len = packet->line[packet->parsed_lines].len - 17;
	} else {
	  packet->forwarded_line.ptr = &packet->line[packet->parsed_lines].ptr[16];
	  packet->forwarded_line.len = packet->line[packet->parsed_lines].len - 16;
	}
	packet->http_num_headers++;
      } else

	/* "Authorization:" header line in HTTP. */
	if(packet->line[packet->parsed_lines].len > 15 &&
	   (strncasecmp((const char *) packet->line[packet->parsed_lines].ptr, "Authorization: ", 15) == 0)) {
	  packet->authorization_line.ptr = &packet->line[packet->parsed_lines].ptr[15];
	  packet->authorization_line.len = packet->line[packet->parsed_lines].len - 15;

	  while((packet->authorization_line.len > 0) && (packet->authorization_line.ptr[0] == ' '))
	    packet->authorization_line.len--, packet->authorization_line.ptr++;
	  if(packet->authorization_line.len == 0)
	    packet->authorization_line.ptr = NULL;

	  packet->http_num_headers++;
	} else
	  /* "Accept:" header line in HTTP request. */
	  if(packet->line[packet->parsed_lines].len > 8 &&
	     strncasecmp((const char *) packet->line[packet->parsed_lines].ptr, "Accept: ", 8) == 0) {
	    packet->accept_line.ptr = &packet->line[packet->parsed_lines].ptr[8];
	    packet->accept_line.len = packet->line[packet->parsed_lines].len - 8;
	    packet->http_num_headers++;
	  } else
	    /* "Referer:" header line in HTTP request. */
	    if(packet->line[packet->parsed_lines].len > 9 &&
	       strncasecmp((const char *) packet->line[packet->parsed_lines].ptr, "Referer: ", 9) == 0) {
	      packet->referer_line.ptr = &packet->line[packet->parsed_lines].ptr[9];
	      packet->referer_line.len = packet->line[packet->parsed_lines].len - 9;
	      packet->http_num_headers++;
	    } else
	      /* "User-Agent:" header line in HTTP request. */
	      if(packet->line[packet->parsed_lines].len > 12 &&
		 strncasecmp((const char *) packet->line[packet->parsed_lines].ptr, "User-agent: ", 12) == 0) {
		packet->user_agent_line.ptr = &packet->line[packet->parsed_lines].ptr[12];
		packet->user_agent_line.len = packet->line[packet->parsed_lines].len - 12;
		packet->http_num_headers++;
	      } else
		/* "Content-Encoding:" header line in HTTP response (and request?). */
		if(packet->line[packet->parsed_lines].len > 18 &&
		   strncasecmp((const char *) packet->line[packet->parsed_lines].ptr, "Content-Encoding: ", 18) == 0) {
		  packet->http_encoding.ptr = &packet->line[packet->parsed_lines].ptr[18];
		  packet->http_encoding.len = packet->line[packet->parsed_lines].len - 18;
		  packet->http_num_headers++;
		} else
		  /* "Transfer-Encoding:" header line in HTTP. */
		  if(packet->line[packet->parsed_lines].len > 19 &&
		     strncasecmp((const char *) packet->line[packet->parsed_lines].ptr, "Transfer-Encoding: ", 19) == 0) {
		    packet->http_transfer_encoding.ptr = &packet->line[packet->parsed_lines].ptr[19];
		    packet->http_transfer_encoding.len = packet->line[packet->parsed_lines].len - 19;
		    packet->http_num_headers++;
		  } else
		    /* "Content-Length:" header line in HTTP. */
		    if(packet->line[packet->parsed_lines].len > 16 &&
		       strncasecmp((const char *) packet->line[packet->parsed_lines].ptr, "content-length: ", 16) == 0) {
		      packet->http_contentlen.ptr = &packet->line[packet->parsed_lines].ptr[16];
		      packet->http_contentlen.len = packet->line[packet->parsed_lines].len - 16;
		      packet->http_num_headers++;
		    } else
		      /* "Content-Disposition"*/
		      if(packet->line[packet->parsed_lines].len > 21 &&
			 ((strncasecmp((const char *) packet->line[packet->parsed_lines].ptr, "Content-Disposition: ", 21) == 0))) {
			packet->content_disposition_line.ptr = &packet->line[packet->parsed_lines].ptr[21];
			packet->content_disposition_line.len = packet->line[packet->parsed_lines].len - 21;
			packet->http_num_headers++;
		      } else
			/* "Cookie:" header line in HTTP. */
			if(packet->line[packet->parsed_lines].len > 8 &&
			   strncasecmp((const char *) packet->line[packet->parsed_lines].ptr, "Cookie: ", 8) == 0) {
			  packet->http_cookie.ptr = &packet->line[packet->parsed_lines].ptr[8];
			  packet->http_cookie.len = packet->line[packet->parsed_lines].len - 8;
			  packet->http_num_headers++;
			} else
			  /* "Origin:" header line in HTTP. */
			  if(packet->line[packet->parsed_lines].len > 8 &&
			     strncasecmp((const char *) packet->line[packet->parsed_lines].ptr, "Origin: ", 8) == 0) {
			    packet->http_origin.ptr = &packet->line[packet->parsed_lines].ptr[8];
			    packet->http_origin.len = packet->line[packet->parsed_lines].len - 8;
			    packet->http_num_headers++;
			  } else
			    /* "X-Session-Type:" header line in HTTP. */
			    if(packet->line[packet->parsed_lines].len > 16 &&
			       strncasecmp((const char *) packet->line[packet->parsed_lines].ptr, "X-Session-Type: ", 16) == 0) {
			      packet->http_x_session_type.ptr = &packet->line[packet->parsed_lines].ptr[16];
			      packet->http_x_session_type.len = packet->line[packet->parsed_lines].len - 16;
			      packet->http_num_headers++;
			    } else
			      /* Identification and counting of other HTTP headers.
			       * We consider the most common headers, but there are many others,
			       * which can be seen at references below:
			       * - https://tools.ietf.org/html/rfc7230
			       * - https://en.wikipedia.org/wiki/List_of_HTTP_header_fields
			       */
			      if((packet->line[packet->parsed_lines].len > 6 &&
				  (strncasecmp((const char *) packet->line[packet->parsed_lines].ptr, "Date: ", 6) == 0 ||
				   strncasecmp((const char *) packet->line[packet->parsed_lines].ptr, "Vary: ", 6) == 0 ||
				   strncasecmp((const char *) packet->line[packet->parsed_lines].ptr, "ETag: ", 6) == 0)) ||
				 (packet->line[packet->parsed_lines].len > 8 &&
				  strncasecmp((const char *) packet->line[packet->parsed_lines].ptr, "Pragma: ", 8) == 0) ||
				 (packet->line[packet->parsed_lines].len > 9 &&
				  strncasecmp((const char *) packet->line[packet->parsed_lines].ptr, "Expires: ", 9) == 0) ||
				 (packet->line[packet->parsed_lines].len > 12 &&
				  (strncasecmp((const char *) packet->line[packet->parsed_lines].ptr, "Set-Cookie: ", 12) == 0 ||
				   strncasecmp((const char *) packet->line[packet->parsed_lines].ptr, "Keep-Alive: ", 12) == 0 ||
				   strncasecmp((const char *) packet->line[packet->parsed_lines].ptr, "Connection: ", 12) == 0)) ||
				 (packet->line[packet->parsed_lines].len > 15 &&
				  (strncasecmp((const char *) packet->line[packet->parsed_lines].ptr, "Last-Modified: ", 15) == 0 ||
				   strncasecmp((const char *) packet->line[packet->parsed_lines].ptr, "Accept-Ranges: ", 15) == 0)) ||
				 (packet->line[packet->parsed_lines].len > 17 &&
				  (strncasecmp((const char *) packet->line[packet->parsed_lines].ptr, "Accept-Language: ", 17) == 0 ||
				   strncasecmp((const char *) packet->line[packet->parsed_lines].ptr, "Accept-Encoding: ", 17) == 0)) ||
				 (packet->line[packet->parsed_lines].len > 27 &&
				  strncasecmp((const char *) packet->line[packet->parsed_lines].ptr,
					      "Upgrade-Insecure-Requests: ", 27) == 0)) {
				/* Just count. In the future, if needed, this if can be splited to parse these headers */
				packet->http_num_headers++;
			      } else
				/* "Content-Type:" header line in HTTP. */
				if(packet->line[packet->parsed_lines].len > 14 &&
				   strncasecmp((const char *) packet->line[packet->parsed_lines].ptr, "Content-Type: ", 14) == 0 ) {
				  packet->content_line.ptr = &packet->line[packet->parsed_lines].ptr[14];
				  packet->content_line.len = packet->line[packet->parsed_lines].len - 14;

				  while((packet->content_line.len > 0) && (packet->content_line.ptr[0] == ' '))
				    packet->content_line.len--, packet->content_line.ptr++;
				  if(packet->content_line.len == 0)
				    packet->content_line.ptr = NULL;;

				  packet->http_num_headers++;
				} else

				  /* "Content-Type:" header line in HTTP AGAIN. Probably a bogus response without space after ":" */
				  if((packet->content_line.len == 0) && (packet->line[packet->parsed_lines].len > 13) &&
				     (strncasecmp((const char *) packet->line[packet->parsed_lines].ptr, "Content-type:", 13) == 0)) {
				    packet->content_line.ptr = &packet->line[packet->parsed_lines].ptr[13];
				    packet->content_line.len = packet->line[packet->parsed_lines].len - 13;
				    packet->http_num_headers++;
				  }

  if(packet->content_line.len > 0) {
    /* application/json; charset=utf-8 */
    char separator[] = {';', '\r', '\0'};
    int i;

    for(i = 0; separator[i] != '\0'; i++) {
      char *c = memchr((char *) packet->content_line.ptr, separator[i], packet->content_line.len);

      if(c != NULL)
	packet->content_line.len = c - (char *) packet->content_line.ptr;
    }
  }
}

static u_int16_t ndpi_automa_match_string_subprotocol(struct ndpi_detection_module_struct *ndpi_str,
						      struct ndpi_flow_struct *flow, char *string_to_match,
						      u_int string_to_match_len, u_int16_t master_protocol_id,
						      ndpi_protocol_match_result *ret_match) {
  int matching_protocol_id;

  matching_protocol_id =
    ndpi_match_string_subprotocol(ndpi_str, string_to_match, string_to_match_len, ret_match);

  if(matching_protocol_id < 0)
    return NDPI_PROTOCOL_UNKNOWN;

#ifdef DEBUG
  {
    char m[256];
    int len = ndpi_min(sizeof(m), string_to_match_len);

    strncpy(m, string_to_match, len);
    m[len] = '\0';

    NDPI_LOG_DBG2(ndpi_str, "[NDPI] ndpi_match_host_subprotocol(%s): %s\n", m,
		  ndpi_str->proto_defaults[matching_protocol_id].protoName);
  }
#endif

  if((matching_protocol_id != NDPI_PROTOCOL_UNKNOWN) &&
     (!ndpi_is_more_generic_protocol(flow->detected_protocol_stack[0], matching_protocol_id))) {
    /* Move the protocol on slot 0 down one position */
    flow->detected_protocol_stack[1] = master_protocol_id,
    flow->detected_protocol_stack[0] = matching_protocol_id;
    flow->confidence = NDPI_CONFIDENCE_DPI;
    if(!category_depends_on_master(master_protocol_id) &&
       flow->category == NDPI_PROTOCOL_CATEGORY_UNSPECIFIED)
      flow->category = ret_match->protocol_category;

    return(flow->detected_protocol_stack[0]);
  }

#ifdef DEBUG
  {
    char m[256];
    int len = ndpi_min(sizeof(m), string_to_match_len);

    strncpy(m, string_to_match, len);
    m[len] = '\0';

    NDPI_LOG_DBG2(ndpi_str, "[NTOP] Unable to find a match for '%s'\n", m);
  }
#endif

  ret_match->protocol_id = NDPI_PROTOCOL_UNKNOWN, ret_match->protocol_category = NDPI_PROTOCOL_CATEGORY_UNSPECIFIED,
    ret_match->protocol_breed = NDPI_PROTOCOL_UNRATED;

  return(NDPI_PROTOCOL_UNKNOWN);
}

int ndpi_get_custom_category_match(struct ndpi_detection_module_struct *ndpi_str,
				   char *name_or_ip, u_int name_len,
				   ndpi_protocol_category_t *id) {
  char ipbuf[64], *ptr;
  struct in_addr pin;
  u_int cp_len = ndpi_min(sizeof(ipbuf) - 1, name_len);

  if(!ndpi_str->custom_categories.categories_loaded)
    return(-1);

  if(cp_len > 0) {
    memcpy(ipbuf, name_or_ip, cp_len);
    ipbuf[cp_len] = '\0';
  } else
    ipbuf[0] = '\0';

  ptr = strrchr(ipbuf, '/');

  if(ptr)
    ptr[0] = '\0';

  if(inet_pton(AF_INET, ipbuf, &pin) == 1) {
    /* Search IP */
    ndpi_prefix_t prefix;
    ndpi_patricia_node_t *node;

    /* Make sure all in network byte order otherwise compares wont work */
    ndpi_fill_prefix_v4(&prefix, &pin, 32, ((ndpi_patricia_tree_t *) ndpi_str->protocols_ptree)->maxbits);
    node = ndpi_patricia_search_best(ndpi_str->custom_categories.ipAddresses, &prefix);

    if(node) {
      *id = node->value.u.uv32.user_value;

      return(0);
    }

    return(-1);
  } else {
    /* Search Host */
    return(ndpi_match_custom_category(ndpi_str, name_or_ip, name_len, id));
  }
}

void ndpi_int_change_category(struct ndpi_detection_module_struct *ndpi_str, struct ndpi_flow_struct *flow,
			      ndpi_protocol_category_t protocol_category) {
  flow->category = protocol_category;
}

static int ndpi_is_trigram_char(char c) {
  if(isdigit(c) || (c == '.') || (c == '-'))
    return(0);
  else
    return(1);
}

/* ******************************************************************** */

static int ndpi_is_vowel(char c) {
  switch(c) {
  case 'a':
  case 'e':
  case 'i':
  case 'o':
  case 'u':
  case 'y': // Not a real vowel...
  case 'x': // Not a real vowel...
    return(1);
    break;

  default:
    return(0);
  }
}

int ndpi_match_string_subprotocol(struct ndpi_detection_module_struct *ndpi_str, char *string_to_match,
				  u_int string_to_match_len, ndpi_protocol_match_result *ret_match) {
  ndpi_automa *automa = &ndpi_str->host_automa;
  int rc;

  if((automa->ac_automa == NULL) || (string_to_match_len == 0))
    return(NDPI_PROTOCOL_UNKNOWN);

  rc = ndpi_match_string_common(((AC_AUTOMATA_t *) automa->ac_automa),
				string_to_match,string_to_match_len, &ret_match->protocol_id,
				&ret_match->protocol_category, &ret_match->protocol_breed);
  return rc < 0 ? rc : (int)ret_match->protocol_id;
}

/* **************************************** */

static int enough(int a, int b) {
  u_int8_t percentage = 20;

  if(b <= 1) return(0);
  if(a == 0) return(1);

  if(b > (((a+1)*percentage)/100)) return(1);

  return(0);
}

int ndpi_match_prefix(const u_int8_t *payload,
		      size_t payload_len, const char *str, size_t str_len) {
  int rc = str_len <= payload_len ? memcmp(payload, str, str_len) == 0 : 0;

  return(rc);
}

int ndpi_seen_flow_beginning(const struct ndpi_flow_struct *flow)
{
  if(flow->l4_proto == IPPROTO_TCP &&
     (flow->l4.tcp.seen_syn == 0 || flow->l4.tcp.seen_syn_ack == 0 ||
      flow->l4.tcp.seen_ack == 0))
    return 0;
  return 1;
}

/*
 * Same as ndpi_strnstr but case-insensitive
 */
const char * ndpi_strncasestr(const char *str1, const char *str2, size_t len) {
  size_t str1_len = strnlen(str1, len);
  size_t str2_len = strlen(str2);
  int i; /* signed! */

  for(i = 0; i < (int)(str1_len - str2_len + 1); i++){
    if(str1[0] == '\0')
      return NULL;
    else if(strncasecmp(str1, str2, str2_len) == 0)
      return(str1);

    str1++;
  }

  return NULL;
}

u_int8_t ndpi_ends_with(char *str, char *ends) {
  u_int str_len = str ? strlen(str) : 0;
  u_int8_t ends_len = strlen(ends);
  u_int8_t rc;


  if(str_len < ends_len) return(0);

  rc = (strncmp(&str[str_len-ends_len], ends, ends_len) != 0) ? 0 : 1;

#ifdef DGA_DEBUG
  printf("[DGA] %s / %s [rc: %u]\n", str, ends, rc);
#endif

  return(rc);
}

void ndpi_parse_packet_line_info_any(struct ndpi_detection_module_struct *ndpi_str, struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &ndpi_str->packet;
  u_int32_t a;
  u_int16_t end = packet->payload_packet_len;

  if(packet->packet_lines_parsed_complete != 0)
    return;

  packet->packet_lines_parsed_complete = 1;
  packet->parsed_lines = 0;

  if(packet->payload_packet_len == 0)
    return;

  packet->line[packet->parsed_lines].ptr = packet->payload;
  packet->line[packet->parsed_lines].len = 0;

  for(a = 0; a < end; a++) {
    if(packet->payload[a] == 0x0a) {
      packet->line[packet->parsed_lines].len = (u_int16_t)(
							   ((size_t) &packet->payload[a]) - ((size_t) packet->line[packet->parsed_lines].ptr));

      if(a > 0 && packet->payload[a - 1] == 0x0d)
	packet->line[packet->parsed_lines].len--;

      if(packet->parsed_lines >= (NDPI_MAX_PARSE_LINES_PER_PACKET - 1))
	break;

      packet->parsed_lines++;
      packet->line[packet->parsed_lines].ptr = &packet->payload[a + 1];
      packet->line[packet->parsed_lines].len = 0;

      if((a + 1) >= packet->payload_packet_len)
	break;

      //a++;
    }
  }
}


void ndpi_parse_packet_line_info(struct ndpi_detection_module_struct *ndpi_str, struct ndpi_flow_struct *flow) {
  u_int32_t a;
  struct ndpi_packet_struct *packet = &ndpi_str->packet;

  if((packet->payload_packet_len < 3) || (packet->payload == NULL))
    return;

  if(packet->packet_lines_parsed_complete != 0)
    return;

  packet->packet_lines_parsed_complete = 1;
  ndpi_reset_packet_line_info(packet);

  packet->line[packet->parsed_lines].ptr = packet->payload;
  packet->line[packet->parsed_lines].len = 0;

  for(a = 0; ((a+1) < packet->payload_packet_len) && (packet->parsed_lines < NDPI_MAX_PARSE_LINES_PER_PACKET); a++) {
    if((packet->payload[a] == 0x0d) && (packet->payload[a+1] == 0x0a)) {
      /* If end of line char sequence CR+NL "\r\n", process line */

      if(((a + 3) < packet->payload_packet_len)
	 && (packet->payload[a+2] == 0x0d)
	 && (packet->payload[a+3] == 0x0a)) {
	/* \r\n\r\n */
	int diff; /* No unsigned ! */
	u_int32_t a1 = a + 4;

	diff = packet->payload_packet_len - a1;

	if(diff > 0) {
	  diff = ndpi_min((unsigned int)diff, sizeof(flow->initial_binary_bytes));
	  memcpy(&flow->initial_binary_bytes, &packet->payload[a1], diff);
	  flow->initial_binary_bytes_len = diff;
	}
      }

      packet->line[packet->parsed_lines].len =
	(u_int16_t)(((size_t) &packet->payload[a]) - ((size_t) packet->line[packet->parsed_lines].ptr));

      ndpi_parse_single_packet_line(ndpi_str, flow);

      if(packet->line[packet->parsed_lines].len == 0) {
	packet->empty_line_position = a;
	packet->empty_line_position_set = 1;
      }

      if(packet->parsed_lines >= (NDPI_MAX_PARSE_LINES_PER_PACKET - 1))
	return;

      packet->parsed_lines++;
      packet->line[packet->parsed_lines].ptr = &packet->payload[a + 2];
      packet->line[packet->parsed_lines].len = 0;

      a++; /* next char in the payload */
    }
  }

  if(packet->parsed_lines >= 1) {
    packet->line[packet->parsed_lines].len =
      (u_int16_t)(((size_t) &packet->payload[packet->payload_packet_len]) -
		  ((size_t) packet->line[packet->parsed_lines].ptr));

    ndpi_parse_single_packet_line(ndpi_str, flow);
    packet->parsed_lines++;
  }
}

char *ndpi_hostname_sni_set(struct ndpi_flow_struct *flow,
			    const u_int8_t *value, size_t value_len) {
  char *dst;
  size_t len, i;

  len = ndpi_min(value_len, sizeof(flow->host_server_name) - 1);
  dst = flow->host_server_name;

  for(i = 0; i < len; i++)
    dst[i] = tolower(value[value_len - len + i]);
  dst[i] = '\0';

  return dst;
}

u_int16_t ndpi_match_host_subprotocol(struct ndpi_detection_module_struct *ndpi_str,
				      struct ndpi_flow_struct *flow,
				      char *string_to_match, u_int string_to_match_len,
				      ndpi_protocol_match_result *ret_match,
				      u_int16_t master_protocol_id) {
  u_int16_t rc;
  ndpi_protocol_category_t id;

  memset(ret_match, 0, sizeof(*ret_match));

  rc = ndpi_automa_match_string_subprotocol(ndpi_str, flow,
					    string_to_match, string_to_match_len,
					    master_protocol_id, ret_match);
  id = ret_match->protocol_category;

  if(ndpi_get_custom_category_match(ndpi_str, string_to_match,
				    string_to_match_len, &id) != -1) {
    /* if(id != -1) */ {
      flow->category = ret_match->protocol_category = id;
      rc = master_protocol_id;
    }
  }

  if(ndpi_str->risky_domain_automa.ac_automa != NULL) {
    u_int32_t proto_id;
    u_int16_t rc1 = ndpi_match_string_common(ndpi_str->risky_domain_automa.ac_automa,
					     string_to_match, string_to_match_len,
					     &proto_id, NULL, NULL);
    if(rc1 > 0) {
      char str[64] = { '\0' };

      strncpy(str, string_to_match, ndpi_min(string_to_match_len, sizeof(str)-1));
      ndpi_set_risk(ndpi_str, flow, NDPI_RISKY_DOMAIN, str);
    }
  }

  /* Add punycode check */
  if(ndpi_strnstr(string_to_match, "xn--", string_to_match_len)) {
    char str[64] = { '\0' };

    strncpy(str, string_to_match, ndpi_min(string_to_match_len, sizeof(str)-1));
    ndpi_set_risk(ndpi_str, flow, NDPI_PUNYCODE_IDN, str);
  }

  return(rc);
}

int ndpi_check_dga_name(struct ndpi_detection_module_struct *ndpi_str,
			struct ndpi_flow_struct *flow,
			char *name, u_int8_t is_hostname, u_int8_t check_subproto) {
  if(ndpi_dga_function != NULL) {
    /* A custom DGA function is defined */
    int rc = ndpi_dga_function(name, is_hostname);

    if(rc) {
      if(flow)
	ndpi_set_risk(ndpi_str, flow, NDPI_SUSPICIOUS_DGA_DOMAIN, name);
    }

    return(rc);
  } else {
    int len, rc = 0, trigram_char_skip = 0;
    u_int8_t max_num_char_repetitions = 0, last_char = 0, num_char_repetitions = 0, num_dots = 0, num_trigram_dots = 0;
    u_int8_t max_domain_element_len = 0, curr_domain_element_len = 0, first_element_is_numeric = 1;
    ndpi_protocol_match_result ret_match;

    if((!name)
       || (strchr(name, '_') != NULL)
       || (strchr(name, '-') != NULL)
       || (ndpi_ends_with(name, "in-addr.arpa"))
       || (ndpi_ends_with(name, "ip6.arpa"))
       /* Ignore TLD .local .lan and .home */
       || (ndpi_ends_with(name, ".local"))
       || (ndpi_ends_with(name, ".lan"))
       || (ndpi_ends_with(name, ".home"))
       )
      return(0);

    if(flow && (flow->detected_protocol_stack[1] != NDPI_PROTOCOL_UNKNOWN))
      return(0); /* Ignore DGA check for protocols already fully detected */

    if(check_subproto &&
       ndpi_match_string_subprotocol(ndpi_str, name, strlen(name), &ret_match) > 0)
      return(0); /* Ignore DGA for known domain names */

    if(isdigit((int)name[0])) {
      struct in_addr ip_addr;

      ip_addr.s_addr = inet_addr(name);
      if(strcmp(inet_ntoa(ip_addr), name) == 0)
	return(0); /* Ignore numeric IPs */
    }

    if(strncmp(name, "www.", 4) == 0)
      name = &name[4];

    if(ndpi_verbose_dga_detection)
      printf("[DGA check] %s\n", name);

    len = strlen(name);

    if(len >= 5) {
      int num_found = 0, num_impossible = 0, num_bigram_checks = 0,
	num_trigram_found = 0, num_trigram_checked = 0, num_dash = 0,
	num_digits = 0, num_vowels = 0, num_trigram_vowels = 0, num_words = 0, skip_next_bigram = 0;
      char tmp[128], *word, *tok_tmp;
      u_int i, j, max_tmp_len = sizeof(tmp)-1;

      len = ndpi_snprintf(tmp, max_tmp_len, "%s", name);
      if(len < 0) {

	if(ndpi_verbose_dga_detection)
	  printf("[DGA] Too short");

	return(0);
      } else
	tmp[(u_int)len < max_tmp_len ? (u_int)len : max_tmp_len] = '\0';

      for(i=0, j=0; (i<(u_int)len) && (j<max_tmp_len); i++) {
	tmp[j] = tolower(name[i]);

	if(tmp[j] == '.') {
	  num_dots++;
	} else if(num_dots == 0) {
	  if(!isdigit((int)tmp[j]))
	    first_element_is_numeric = 0;
	}

	if(ndpi_is_vowel(tmp[j]))
	  num_vowels++;

	if(last_char == tmp[j]) {
	  if(++num_char_repetitions > max_num_char_repetitions)
	    max_num_char_repetitions = num_char_repetitions;
	} else
	  num_char_repetitions = 1, last_char = tmp[j];

	if(isdigit((int)tmp[j])) {
	  num_digits++;

	  if(((j+2)<(u_int)len) && isdigit((int)tmp[j+1]) && (tmp[j+2] == '.')) {
	    /* Check if there are too many digits */
	    if(num_digits < 4)
	      return(0); /* Double digits */
	  }
	}

	switch(tmp[j]) {
	case '.':
	case '-':
	case '_':
	case '/':
	case ')':
	case '(':
	case ';':
	case ':':
	case '[':
	case ']':
	case ' ':
	  /*
	    Domain/word separator chars

	    NOTE:
	    this function is used also to detect other type of issues
	    such as invalid/suspiciuous user agent
	  */
	  if(curr_domain_element_len > max_domain_element_len)
	    max_domain_element_len = curr_domain_element_len;

	  curr_domain_element_len = 0;
	  break;

	default:
	  curr_domain_element_len++;
	  break;
	}

	j++;
      }

      if(num_dots == 0) /* Doesn't look like a domain name */
	return(0);

      if(curr_domain_element_len > max_domain_element_len)
	max_domain_element_len = curr_domain_element_len;

      if(ndpi_verbose_dga_detection)
	printf("[DGA] [max_num_char_repetitions: %u][max_domain_element_len: %u]\n",
	       max_num_char_repetitions, max_domain_element_len);

      if(
	 (is_hostname
	  && (num_dots > 5)
	  && (!first_element_is_numeric)
	  )
	 || (max_num_char_repetitions > 5 /* num or consecutive repeated chars */)
	 /*
	   In case of a name with too many consecutive chars an alert is triggered
	   This is the case for instance of the wildcard DNS query used by NetBIOS
	   (ckaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa) and that can be exploited
	   for reflection attacks
	   - https://www.akamai.com/uk/en/multimedia/documents/state-of-the-internet/ddos-reflection-netbios-name-server-rpc-portmap-sentinel-udp-threat-advisory.pdf
	   - http://ubiqx.org/cifs/NetBIOS.html
	 */
	 || ((max_domain_element_len >= 19 /* word too long. Example bbcbedxhgjmdobdprmen.com */) && ((num_char_repetitions > 1) || (num_digits > 1)))
	 ) {
	if(flow) {
	  ndpi_set_risk(ndpi_str, flow, NDPI_SUSPICIOUS_DGA_DOMAIN, name);
	}

	if(ndpi_verbose_dga_detection)
	  printf("[DGA] Found!");

	return(1);
      }

      tmp[j] = '\0';
      len = j;

      u_int max_num_consecutive_digits_first_word = 0, num_word = 0;

      for(word = strtok_r(tmp, ".", &tok_tmp); ; word = strtok_r(NULL, ".", &tok_tmp)) {
	u_int num_consecutive_digits = 0;

	if(!word) break; else num_word++;

	num_words++;

	if(num_words > 2)
	  break; /* Stop after the 2nd word of the domain name */

	if(strlen(word) < 5) continue;

	if(ndpi_verbose_dga_detection)
	  printf("-> word(%s) [%s][len: %u]\n", word, name, (unsigned int)strlen(word));

	trigram_char_skip = 0;

	for(i = 0; word[i+1] != '\0'; i++) {
	  if(isdigit((int)word[i]))
	    num_consecutive_digits++;
	  else {
	    if((num_word == 1) && (num_consecutive_digits > max_num_consecutive_digits_first_word))
	      max_num_consecutive_digits_first_word = num_consecutive_digits;

	    num_consecutive_digits = 0;
	  }

	  switch(word[i]) {
	  case '-':
	    num_dash++;
	    /*
	      Let's check for double+consecutive --
	      that are usually ok
	      r2---sn-uxaxpu5ap5-2n5e.gvt1.com
	    */
	    if(word[i+1] == '-')
	      return(0); /* Double dash */
	    continue;

	  case '_':
	  case ':':
	    continue;
	    break;

	  case '.':
	    continue;
	    break;
	  }

	  num_bigram_checks++;

	  if(ndpi_verbose_dga_detection)
	    printf("-> Checking %c%c\n", word[i], word[i+1]);

	  if(ndpi_match_impossible_bigram(&word[i])) {
	    if(ndpi_verbose_dga_detection)
	      printf("IMPOSSIBLE %s\n", &word[i]);

	    num_impossible++;
	  } else {
	    if(!skip_next_bigram) {
	      if(ndpi_match_bigram(&word[i])) {
		num_found++, skip_next_bigram = 1;
	      }
	    } else
	      skip_next_bigram = 0;
	  }

	  if((num_trigram_dots < 2) && (word[i+2] != '\0')) {
	    if(ndpi_verbose_dga_detection)
	      printf("***> %s [trigram_char_skip: %u]\n", &word[i], trigram_char_skip);

	    if(ndpi_is_trigram_char(word[i]) && ndpi_is_trigram_char(word[i+1]) && ndpi_is_trigram_char(word[i+2])) {
	      if(trigram_char_skip) {
		trigram_char_skip--;
	      } else {
		num_trigram_checked++;

		if(ndpi_match_trigram(&word[i]))
		  num_trigram_found++, trigram_char_skip = 2 /* 1 char overlap */;
		else if(ndpi_verbose_dga_detection)
		  printf("[NDPI] NO Trigram %c%c%c\n", word[i], word[i+1], word[i+2]);

		/* Count vowels */
		num_trigram_vowels += ndpi_is_vowel(word[i]) + ndpi_is_vowel(word[i+1]) + ndpi_is_vowel(word[i+2]);
	      }
	    } else {
	      if(word[i] == '.')
		num_trigram_dots++;

	      trigram_char_skip = 0;
	    }
	  }
	} /* for */

	if((num_word == 1) && (num_consecutive_digits > max_num_consecutive_digits_first_word))
	  max_num_consecutive_digits_first_word = num_consecutive_digits;
      } /* for */

      if(ndpi_verbose_dga_detection)
	printf("[NDPI] max_num_consecutive_digits_first_word=%u\n", max_num_consecutive_digits_first_word);

      if(ndpi_verbose_dga_detection)
	printf("[%s][num_found: %u][num_impossible: %u][num_digits: %u][num_bigram_checks: %u][num_vowels: %u/%u][num_trigram_vowels: %u][num_trigram_found: %u/%u][vowels: %u][rc: %u]\n",
	       name, num_found, num_impossible, num_digits, num_bigram_checks, num_vowels, len, num_trigram_vowels,
	       num_trigram_checked, num_trigram_found, num_vowels, rc);

      if((len > 16) && (num_dots < 3) && ((num_vowels*4) < (len-num_dots))) {
	if((num_trigram_checked > 2) && (num_trigram_vowels >= (num_trigram_found-1)))
	  ; /* skip me */
	else
	  rc = 1;
      }

      if(num_bigram_checks
	 /* We already checked num_dots > 0 */
	 && ((num_found == 0) || ((num_digits > 5) && (num_words <= 3) && (num_impossible > 0))
	     || enough(num_found, num_impossible)
	     || ((num_trigram_checked > 2)
		 && ((num_trigram_found < (num_trigram_checked/2))
		     || ((num_trigram_vowels < (num_trigram_found-1)) && (num_dash == 0) && (num_dots > 1) && (num_impossible > 0)))
		 )
	     )
	 )
	rc = 1;

      if((num_trigram_checked > 2) && (num_vowels == 0))
	rc = 1;

      if(num_dash > 2)
	rc = 0;

      /* Skip names whose first word item has at least 3 consecutive digits */
      if(max_num_consecutive_digits_first_word > 2)
	rc = 0;

      if(ndpi_verbose_dga_detection) {
	if(rc)
	  printf("DGA %s [num_found: %u][num_impossible: %u]\n",
		 name, num_found, num_impossible);
      }
    }

    if(ndpi_verbose_dga_detection)
      printf("[DGA] Result: %u\n", rc);

    if(rc && flow)
      ndpi_set_risk(ndpi_str, flow, NDPI_SUSPICIOUS_DGA_DOMAIN, name);

    return(rc);
  }
}

static void ndpi_validate_protocol_initialization(struct ndpi_detection_module_struct *ndpi_str) {
  u_int i, val;

  for(i = 0; i < ndpi_str->ndpi_num_supported_protocols; i++) {
    if(ndpi_str->proto_defaults[i].protoName == NULL) {
      NDPI_LOG_ERR(ndpi_str,
		   "[NDPI] INTERNAL ERROR missing protoName initialization for [protoId=%d]: recovering\n", i);
    } else {
      if((i != NDPI_PROTOCOL_UNKNOWN) &&
	 (ndpi_str->proto_defaults[i].protoCategory == NDPI_PROTOCOL_CATEGORY_UNSPECIFIED)) {
	NDPI_LOG_ERR(ndpi_str,
		     "[NDPI] INTERNAL ERROR missing category [protoId=%d/%s] initialization: recovering\n", i,
		     ndpi_str->proto_defaults[i].protoName ? ndpi_str->proto_defaults[i].protoName : "???");
      }
    }
  }

  /* Sanity check for risks initialization */
  val = (sizeof(ndpi_known_risks) / sizeof(ndpi_risk_info)) - 1;
  if(val != NDPI_MAX_RISK) {
    NDPI_LOG_ERR(ndpi_str,  "[NDPI] INTERNAL ERROR Invalid ndpi_known_risks[] initialization [%u != %u]\n", val, NDPI_MAX_RISK);
    exit(0);
  }
}

void ndpi_set_proto_subprotocols(struct ndpi_detection_module_struct *ndpi_str, int protoId, ...)
{
  va_list ap;
  int current_arg = protoId;
  size_t i = 0;

  if(!is_proto_enabled(ndpi_str, protoId)) {
      NDPI_LOG_DBG(ndpi_str, "[NDPI] Skip subprotocols for %d (disabled)\n", protoId);
      return;
  }

  va_start(ap, protoId);
  while (current_arg != NDPI_PROTOCOL_NO_MORE_SUBPROTOCOLS) {
    if(!is_proto_enabled(ndpi_str, current_arg)) {
      NDPI_LOG_DBG(ndpi_str, "[NDPI] Skip subprotocol %d (disabled)\n", protoId);
    } else {
      ndpi_str->proto_defaults[protoId].subprotocol_count++;
    }
    current_arg = va_arg(ap, int);
  }
  va_end(ap);

  ndpi_str->proto_defaults[protoId].subprotocols = NULL;

  /* The last protocol is not a subprotocol. */
  ndpi_str->proto_defaults[protoId].subprotocol_count--;
  /* No subprotocol was set before NDPI_NO_MORE_SUBPROTOCOLS. */
  if(ndpi_str->proto_defaults[protoId].subprotocol_count == 0) {
      return;
    }

  ndpi_str->proto_defaults[protoId].subprotocols =
    ndpi_malloc(sizeof(protoId) * ndpi_str->proto_defaults[protoId].subprotocol_count);
  if(!ndpi_str->proto_defaults[protoId].subprotocols) {
    ndpi_str->proto_defaults[protoId].subprotocol_count = 0;
    return;
  }

  va_start(ap, protoId);
  current_arg = va_arg(ap, int);

  while (current_arg != NDPI_PROTOCOL_NO_MORE_SUBPROTOCOLS) {
    if(is_proto_enabled(ndpi_str, current_arg)) {
      ndpi_str->proto_defaults[protoId].subprotocols[i++] = current_arg;
    }
    current_arg = va_arg(ap, int);
  }

  va_end(ap);
}

/* This function is used to map protocol name and default ports and it MUST
   be updated whenever a new protocol is added to NDPI.

   Do NOT add web services (NDPI_SERVICE_xxx) here.
*/
static void ndpi_init_protocol_defaults(struct ndpi_detection_module_struct *ndpi_str) {
  ndpi_port_range ports_a[MAX_DEFAULT_PORTS], ports_b[MAX_DEFAULT_PORTS];

  /* Reset all settings */
  memset(ndpi_str->proto_defaults, 0, sizeof(ndpi_str->proto_defaults));

#if 1
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_UNRATED, NDPI_PROTOCOL_UNKNOWN,
			  "Unknown", NDPI_PROTOCOL_CATEGORY_UNSPECIFIED,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_UNSAFE, NDPI_PROTOCOL_FTP_CONTROL,
			  "FTP_CONTROL", NDPI_PROTOCOL_CATEGORY_DOWNLOAD_FT,
			  ndpi_build_default_ports(ports_a, 21, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_FTP_DATA,
			  "FTP_DATA", NDPI_PROTOCOL_CATEGORY_DOWNLOAD_FT,
			  ndpi_build_default_ports(ports_a, 20, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_UNSAFE, NDPI_PROTOCOL_MAIL_POP,
			  "POP3", NDPI_PROTOCOL_CATEGORY_MAIL,
			  ndpi_build_default_ports(ports_a, 110, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_SAFE, NDPI_PROTOCOL_MAIL_POPS,
			  "POPS", NDPI_PROTOCOL_CATEGORY_MAIL,
			  ndpi_build_default_ports(ports_a, 995, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_MAIL_SMTP,
			  "SMTP", NDPI_PROTOCOL_CATEGORY_MAIL,
			  ndpi_build_default_ports(ports_a, 25, 587, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_SAFE, NDPI_PROTOCOL_MAIL_SMTPS,
			  "SMTPS", NDPI_PROTOCOL_CATEGORY_MAIL,
			  ndpi_build_default_ports(ports_a, 465, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_UNSAFE, NDPI_PROTOCOL_MAIL_IMAP,
			  "IMAP", NDPI_PROTOCOL_CATEGORY_MAIL,
			  ndpi_build_default_ports(ports_a, 143, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_SAFE, NDPI_PROTOCOL_MAIL_IMAPS,
			  "IMAPS", NDPI_PROTOCOL_CATEGORY_MAIL,
			  ndpi_build_default_ports(ports_a, 993, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_DNS,
			  "DNS", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 53, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 53, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_subprotocols(ndpi_str, NDPI_PROTOCOL_DNS,
			      NDPI_PROTOCOL_MATCHED_BY_CONTENT,
			      NDPI_PROTOCOL_NO_MORE_SUBPROTOCOLS); /* NDPI_PROTOCOL_DNS can have (content-matched) subprotocols */
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_IPP,
			  "IPP", NDPI_PROTOCOL_CATEGORY_SYSTEM_OS,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_IMO,
			  "IMO", NDPI_PROTOCOL_CATEGORY_VOIP,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_HTTP,
			  "HTTP", NDPI_PROTOCOL_CATEGORY_WEB,
			  ndpi_build_default_ports(ports_a, 80, 0 /* ntop */, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_subprotocols(ndpi_str, NDPI_PROTOCOL_HTTP,
			      NDPI_PROTOCOL_CROSSFIRE, NDPI_PROTOCOL_SOAP,
			      NDPI_PROTOCOL_BITTORRENT, NDPI_PROTOCOL_GNUTELLA,
			      NDPI_PROTOCOL_MAPLESTORY, NDPI_PROTOCOL_ZATTOO, NDPI_PROTOCOL_WORLDOFWARCRAFT,
			      NDPI_PROTOCOL_IRC,
			      NDPI_PROTOCOL_IPP,
			      NDPI_PROTOCOL_MPEGDASH,
			      NDPI_PROTOCOL_RTSP,
			      NDPI_PROTOCOL_MATCHED_BY_CONTENT,
			      NDPI_PROTOCOL_NO_MORE_SUBPROTOCOLS); /* NDPI_PROTOCOL_HTTP can have (content-matched) subprotocols */
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_MDNS,
			  "MDNS", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 5353, 5354, 0, 0, 0) /* UDP */);
  ndpi_set_proto_subprotocols(ndpi_str, NDPI_PROTOCOL_MDNS,
			      NDPI_PROTOCOL_MATCHED_BY_CONTENT,
			      NDPI_PROTOCOL_NO_MORE_SUBPROTOCOLS); /* NDPI_PROTOCOL_MDNS can have (content-matched) subprotocols */
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_NTP,
			  "NTP", NDPI_PROTOCOL_CATEGORY_SYSTEM_OS,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 123, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_NETBIOS,
			  "NetBIOS", NDPI_PROTOCOL_CATEGORY_SYSTEM_OS,
			  ndpi_build_default_ports(ports_a, 139, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 137, 138, 139, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_NFS,
			  "NFS", NDPI_PROTOCOL_CATEGORY_DATA_TRANSFER,
			  ndpi_build_default_ports(ports_a, 2049, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 2049, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_SSDP,
			  "SSDP", NDPI_PROTOCOL_CATEGORY_SYSTEM_OS,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_BGP,
			  "BGP", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 179, 2605, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_SNMP,
			  "SNMP", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 161, 162, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_XDMCP,
			  "XDMCP", NDPI_PROTOCOL_CATEGORY_REMOTE_ACCESS,
			  ndpi_build_default_ports(ports_a, 177, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 177, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_DANGEROUS, NDPI_PROTOCOL_SMBV1,
			  "SMBv1", NDPI_PROTOCOL_CATEGORY_SYSTEM_OS,
			  ndpi_build_default_ports(ports_a, 445, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_SYSLOG,
			  "Syslog", NDPI_PROTOCOL_CATEGORY_SYSTEM_OS,
			  ndpi_build_default_ports(ports_a, 514, 601, 6514, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 514, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_DHCP,
			  "DHCP", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 67, 68, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_POSTGRES,
			  "PostgreSQL", NDPI_PROTOCOL_CATEGORY_DATABASE,
			  ndpi_build_default_ports(ports_a, 5432, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_MYSQL,
			  "MySQL", NDPI_PROTOCOL_CATEGORY_DATABASE,
			  ndpi_build_default_ports(ports_a, 3306, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_POTENTIALLY_DANGEROUS, NDPI_PROTOCOL_FREE_22,
			  "Free22", NDPI_PROTOCOL_CATEGORY_DOWNLOAD_FT,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_POTENTIALLY_DANGEROUS, NDPI_PROTOCOL_FREE_25,
			  "Free25", NDPI_PROTOCOL_CATEGORY_DOWNLOAD_FT,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_NATS,
			  "Nats", NDPI_PROTOCOL_CATEGORY_RPC,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 1 /* app proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_AMONG_US,
			  "AmongUs", NDPI_PROTOCOL_CATEGORY_GAME,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 22023, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 1 /* app proto */, NDPI_PROTOCOL_SAFE, NDPI_PROTOCOL_NTOP,
			  "ntop", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_VMWARE,
			  "VMware", NDPI_PROTOCOL_CATEGORY_REMOTE_ACCESS,
			  ndpi_build_default_ports(ports_a, 903, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 902, 903, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_POTENTIALLY_DANGEROUS, NDPI_PROTOCOL_KONTIKI,
			  "Kontiki", NDPI_PROTOCOL_CATEGORY_MEDIA,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_POTENTIALLY_DANGEROUS, NDPI_PROTOCOL_FREE_33,
			  "Free33", NDPI_PROTOCOL_CATEGORY_DOWNLOAD_FT,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_POTENTIALLY_DANGEROUS, NDPI_PROTOCOL_FREE_34,
			  "Free34", NDPI_PROTOCOL_CATEGORY_DOWNLOAD_FT,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_POTENTIALLY_DANGEROUS, NDPI_PROTOCOL_GNUTELLA,
			  "Gnutella", NDPI_PROTOCOL_CATEGORY_DOWNLOAD_FT,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_UNSAFE, NDPI_PROTOCOL_EDONKEY,
			  "eDonkey", NDPI_PROTOCOL_CATEGORY_DOWNLOAD_FT,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_BITTORRENT,
			  "BitTorrent", NDPI_PROTOCOL_CATEGORY_DOWNLOAD_FT,
			  ndpi_build_default_ports(ports_a, 51413, 53646, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 6771, 51413, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_SKYPE_TEAMS,
			  "Skype_Teams", NDPI_PROTOCOL_CATEGORY_VOIP,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_GOOGLE,
                          "Google", NDPI_PROTOCOL_CATEGORY_WEB,
                          ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
                          ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_SKYPE_TEAMS_CALL,
			  "Skype_TeamsCall", NDPI_PROTOCOL_CATEGORY_VOIP,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_TIKTOK,
			  "TikTok", NDPI_PROTOCOL_CATEGORY_SOCIAL_NETWORK,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_TEREDO,
			  "Teredo", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_WECHAT,
			  "WeChat", NDPI_PROTOCOL_CATEGORY_CHAT,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_MEMCACHED,
			  "Memcached", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 11211, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 11211, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_SMBV23,
			  "SMBv23", NDPI_PROTOCOL_CATEGORY_SYSTEM_OS,
			  ndpi_build_default_ports(ports_a, 445, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 1 /* app proto */, NDPI_PROTOCOL_UNSAFE, NDPI_PROTOCOL_MINING,
			  "Mining", CUSTOM_CATEGORY_MINING,
			  ndpi_build_default_ports(ports_a, 8333, 30303, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 1 /* app proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_NEST_LOG_SINK,
			  "NestLogSink", NDPI_PROTOCOL_CATEGORY_CLOUD,
			  ndpi_build_default_ports(ports_a, 11095, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_MODBUS,
			  "Modbus", NDPI_PROTOCOL_CATEGORY_IOT_SCADA,
			  ndpi_build_default_ports(ports_a, 502, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_WHATSAPP_CALL,
			  "WhatsAppCall", NDPI_PROTOCOL_CATEGORY_VOIP,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_DATASAVER,
			  "DataSaver", NDPI_PROTOCOL_CATEGORY_WEB /* dummy */,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_SIGNAL,
			  "Signal", NDPI_PROTOCOL_CATEGORY_CHAT,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_DOH_DOT,
			  "DoH_DoT", NDPI_PROTOCOL_CATEGORY_NETWORK /* dummy */,
			  ndpi_build_default_ports(ports_a, 853, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 784, 853, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_REDDIT,
			  "Reddit", NDPI_PROTOCOL_CATEGORY_SOCIAL_NETWORK,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_WIREGUARD,
			  "WireGuard", NDPI_PROTOCOL_CATEGORY_VPN,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 51820, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 1 /* app proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_PPSTREAM,
			  "PPStream", NDPI_PROTOCOL_CATEGORY_STREAMING,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 1 /* app proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_XBOX,
			  "Xbox", NDPI_PROTOCOL_CATEGORY_GAME,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 1 /* app proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_PLAYSTATION,
			  "Playstation", NDPI_PROTOCOL_CATEGORY_GAME,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_QQ,
			  "QQ", NDPI_PROTOCOL_CATEGORY_CHAT,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_RTSP,
			  "RTSP", NDPI_PROTOCOL_CATEGORY_MEDIA,
			  ndpi_build_default_ports(ports_a, 554, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 554, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_ICECAST,
			  "IceCast", NDPI_PROTOCOL_CATEGORY_MEDIA,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 1 /* app proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_CPHA,
			  "CPHA", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 8116, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 1 /* app proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_ZATTOO,
			  "Zattoo", NDPI_PROTOCOL_CATEGORY_VIDEO,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_FREE_56,
			  "Free56", NDPI_PROTOCOL_CATEGORY_MUSIC,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_FREE_57,
			  "Free57", NDPI_PROTOCOL_CATEGORY_VIDEO,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_DISCORD,
			  "Discord", NDPI_PROTOCOL_CATEGORY_COLLABORATIVE,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_TVUPLAYER,
			  "TVUplayer", NDPI_PROTOCOL_CATEGORY_VIDEO,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 1 /* app proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_PLURALSIGHT,
			  "Pluralsight", NDPI_PROTOCOL_CATEGORY_VIDEO,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 1 /* app proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_FREE_62,
			  "Free62", NDPI_PROTOCOL_CATEGORY_DOWNLOAD_FT,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 1 /* app proto */, NDPI_PROTOCOL_SAFE, NDPI_PROTOCOL_OCSP,
			  "OCSP", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_VXLAN,
			  "VXLAN", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 4789, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_UNSAFE, NDPI_PROTOCOL_IRC,
			  "IRC", NDPI_PROTOCOL_CATEGORY_CHAT,
			  ndpi_build_default_ports(ports_a, 194, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 194, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_MERAKI_CLOUD,
			  "MerakiCloud", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_JABBER,
			  "Jabber", NDPI_PROTOCOL_CATEGORY_WEB,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_DISNEYPLUS,
			  "DisneyPlus", NDPI_PROTOCOL_CATEGORY_STREAMING,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_IP_VRRP,
			  "VRRP", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_STEAM,
			  "Steam", NDPI_PROTOCOL_CATEGORY_GAME,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_HALFLIFE2,
			  "HalfLife2", NDPI_PROTOCOL_CATEGORY_GAME,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 1 /* app proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_WORLDOFWARCRAFT,
			  "WorldOfWarcraft", NDPI_PROTOCOL_CATEGORY_GAME,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_POTENTIALLY_DANGEROUS, NDPI_PROTOCOL_HOTSPOT_SHIELD,
			  "HotspotShield", NDPI_PROTOCOL_CATEGORY_VPN,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_UNSAFE, NDPI_PROTOCOL_TELNET,
			  "Telnet", NDPI_PROTOCOL_CATEGORY_REMOTE_ACCESS,
			  ndpi_build_default_ports(ports_a, 23, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_STUN,
			  "STUN", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 3478, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 0 /* nw proto */, NDPI_PROTOCOL_SAFE, NDPI_PROTOCOL_IPSEC,
			  "IPSec", NDPI_PROTOCOL_CATEGORY_VPN,
			  ndpi_build_default_ports(ports_a, 500, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 500, 4500, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_IP_GRE,
			  "GRE", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_IP_ICMP,
			  "ICMP", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_IP_IGMP,
			  "IGMP", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_IP_EGP,
			  "EGP", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_IP_PGM,
			  "PGM", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_IP_SCTP,
			  "SCTP", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_IP_OSPF,
			  "OSPF", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 2604, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_IP_IP_IN_IP,
			  "IP_in_IP", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_RTP,
			  "RTP", NDPI_PROTOCOL_CATEGORY_MEDIA,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_RDP,
			  "RDP", NDPI_PROTOCOL_CATEGORY_REMOTE_ACCESS,
			  ndpi_build_default_ports(ports_a, 3389, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 3389, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_VNC,
			  "VNC", NDPI_PROTOCOL_CATEGORY_REMOTE_ACCESS,
			  ndpi_build_default_ports(ports_a, 5900, 5901, 5800, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 1 /* app proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_TUMBLR,
			  "Tumblr", NDPI_PROTOCOL_CATEGORY_SOCIAL_NETWORK,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_ZOOM,
			  "Zoom", NDPI_PROTOCOL_CATEGORY_VIDEO,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_WHATSAPP_FILES,
			  "WhatsAppFiles", NDPI_PROTOCOL_CATEGORY_DOWNLOAD_FT,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_WHATSAPP,
			  "WhatsApp", NDPI_PROTOCOL_CATEGORY_CHAT,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 0 /* nw proto */, NDPI_PROTOCOL_SAFE, NDPI_PROTOCOL_TLS,
			  "TLS", NDPI_PROTOCOL_CATEGORY_WEB,
			  ndpi_build_default_ports(ports_a, 443, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_subprotocols(ndpi_str, NDPI_PROTOCOL_TLS,
			      NDPI_PROTOCOL_MATCHED_BY_CONTENT,
			      NDPI_PROTOCOL_NO_MORE_SUBPROTOCOLS); /* NDPI_PROTOCOL_TLS can have (content-matched) subprotocols */
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 0 /* nw proto */, NDPI_PROTOCOL_SAFE, NDPI_PROTOCOL_DTLS,
			  "DTLS", NDPI_PROTOCOL_CATEGORY_WEB,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_subprotocols(ndpi_str, NDPI_PROTOCOL_DTLS,
			      NDPI_PROTOCOL_MATCHED_BY_CONTENT,
			      NDPI_PROTOCOL_NO_MORE_SUBPROTOCOLS); /* NDPI_PROTOCOL_DTLS can have (content-matched) subprotocols */
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 0 /* app proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_SSH,
			  "SSH", NDPI_PROTOCOL_CATEGORY_REMOTE_ACCESS,
			  ndpi_build_default_ports(ports_a, 22, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_USENET,
			  "Usenet", NDPI_PROTOCOL_CATEGORY_WEB,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_MGCP,
			  "MGCP", NDPI_PROTOCOL_CATEGORY_VOIP,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_IAX,
			  "IAX", NDPI_PROTOCOL_CATEGORY_VOIP,
			  ndpi_build_default_ports(ports_a, 4569, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 4569, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_AFP,
			  "AFP", NDPI_PROTOCOL_CATEGORY_DATA_TRANSFER,
			  ndpi_build_default_ports(ports_a, 548, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 548, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_HULU,
			  "Hulu", NDPI_PROTOCOL_CATEGORY_STREAMING,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_CHECKMK,
			  "CHECKMK", NDPI_PROTOCOL_CATEGORY_DATA_TRANSFER,
			  ndpi_build_default_ports(ports_a, 6556, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_POTENTIALLY_DANGEROUS, NDPI_PROTOCOL_FREE_98,
			  "Free98", NDPI_PROTOCOL_CATEGORY_DOWNLOAD_FT,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 1 /* app proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_FREE_99,
			  "Free99", NDPI_PROTOCOL_CATEGORY_DOWNLOAD_FT,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_SIP,
			  "SIP", NDPI_PROTOCOL_CATEGORY_VOIP,
			  ndpi_build_default_ports(ports_a, 5060, 5061, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 5060, 5061, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 1 /* app proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_TRUPHONE,
			  "TruPhone", NDPI_PROTOCOL_CATEGORY_VOIP,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_IP_ICMPV6,
			  "ICMPV6", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_DHCPV6,
			  "DHCPV6", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_ARMAGETRON,
			  "Armagetron", NDPI_PROTOCOL_CATEGORY_GAME,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 1 /* app proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_CROSSFIRE,
			  "Crossfire", NDPI_PROTOCOL_CATEGORY_RPC,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_DOFUS,
			  "Dofus", NDPI_PROTOCOL_CATEGORY_GAME,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_FREE_107,
			  "Free107", NDPI_PROTOCOL_CATEGORY_GAME,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_FREE_108,
			  "Free108", NDPI_PROTOCOL_CATEGORY_GAME,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_GUILDWARS,
			  "Guildwars", NDPI_PROTOCOL_CATEGORY_GAME,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_AMAZON_ALEXA,
			  "AmazonAlexa", NDPI_PROTOCOL_CATEGORY_VIRTUAL_ASSISTANT,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_KERBEROS,
			  "Kerberos", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 88, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 88, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_LDAP,
			  "LDAP", NDPI_PROTOCOL_CATEGORY_SYSTEM_OS,
			  ndpi_build_default_ports(ports_a, 389, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 389, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 1 /* app proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_MAPLESTORY,
			  "MapleStory", NDPI_PROTOCOL_CATEGORY_GAME,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_MSSQL_TDS,
			  "MsSQL-TDS", NDPI_PROTOCOL_CATEGORY_DATABASE,
			  ndpi_build_default_ports(ports_a, 1433, 1434, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_PPTP,
			  "PPTP", NDPI_PROTOCOL_CATEGORY_VPN,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_WARCRAFT3,
			  "Warcraft3", NDPI_PROTOCOL_CATEGORY_GAME,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_WORLD_OF_KUNG_FU,
			  "WorldOfKungFu", NDPI_PROTOCOL_CATEGORY_GAME,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_RPC,
			  "RPC", NDPI_PROTOCOL_CATEGORY_RPC,
			  ndpi_build_default_ports(ports_a, 135, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_NETFLOW,
			  "NetFlow", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 2055, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_SFLOW,
			  "sFlow", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 6343, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_HTTP_CONNECT,
			  "HTTP_Connect", NDPI_PROTOCOL_CATEGORY_WEB,
			  ndpi_build_default_ports(ports_a, 8080, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_subprotocols(ndpi_str, NDPI_PROTOCOL_HTTP_CONNECT,
			      NDPI_PROTOCOL_MATCHED_BY_CONTENT,
			      NDPI_PROTOCOL_NO_MORE_SUBPROTOCOLS); /* NDPI_PROTOCOL_HTTP_CONNECT can have (content-matched) subprotocols */
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_HTTP_PROXY,
			  "HTTP_Proxy", NDPI_PROTOCOL_CATEGORY_WEB,
			  ndpi_build_default_ports(ports_a, 8080, 3128, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_subprotocols(ndpi_str, NDPI_PROTOCOL_HTTP_PROXY,
			      NDPI_PROTOCOL_MATCHED_BY_CONTENT,
			      NDPI_PROTOCOL_NO_MORE_SUBPROTOCOLS); /* NDPI_PROTOCOL_HTTP_PROXY can have (content-matched) subprotocols */
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_CITRIX,
			  "Citrix", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 1494, 2598, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_WEBEX,
			  "Webex", NDPI_PROTOCOL_CATEGORY_VOIP,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_RADIUS,
			  "Radius", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 1812, 1813, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 1812, 1813, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_TEAMVIEWER,
			  "TeamViewer", NDPI_PROTOCOL_CATEGORY_REMOTE_ACCESS,
			  ndpi_build_default_ports(ports_a, 5938, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 5938, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_LOTUS_NOTES,
			  "LotusNotes", NDPI_PROTOCOL_CATEGORY_COLLABORATIVE,
			  ndpi_build_default_ports(ports_a, 1352, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_SAP,
			  "SAP", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 3201, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */); /* Missing dissector: port based only */
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_GTP,
			  "GTP", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 2152, 2123, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_GTP_C,
			  "GTP_C", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_GTP_U,
			  "GTP_U", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_GTP_PRIME,
			  "GTP_PRIME", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_HSRP,
			  "HSRP", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 1985, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_WSD,
			  "WSD", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 3702, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_ETHERNET_IP,
			  "EthernetIP", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 44818, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_TELEGRAM,
			  "Telegram", NDPI_PROTOCOL_CATEGORY_CHAT,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_QUIC,
			  "QUIC", NDPI_PROTOCOL_CATEGORY_WEB,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 443, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_subprotocols(ndpi_str, NDPI_PROTOCOL_QUIC,
			      NDPI_PROTOCOL_MATCHED_BY_CONTENT,
			      NDPI_PROTOCOL_NO_MORE_SUBPROTOCOLS); /* NDPI_PROTOCOL_QUIC can have (content-matched) subprotocols */
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_DIAMETER,
			  "Diameter", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 3868, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_APPLE_PUSH,
			  "ApplePush", NDPI_PROTOCOL_CATEGORY_CLOUD,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 1 /* app proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_DROPBOX,
			  "Dropbox", NDPI_PROTOCOL_CATEGORY_CLOUD,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 17500, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_SPOTIFY,
			  "Spotify", NDPI_PROTOCOL_CATEGORY_MUSIC,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_MESSENGER,
			  "Messenger", NDPI_PROTOCOL_CATEGORY_CHAT,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_LISP,
			  "LISP", NDPI_PROTOCOL_CATEGORY_CLOUD,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 4342, 4341, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_EAQ,
			  "EAQ", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 6000, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_KAKAOTALK_VOICE,
			  "KakaoTalk_Voice", NDPI_PROTOCOL_CATEGORY_VOIP,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_MPEGTS,
			  "MPEG_TS", NDPI_PROTOCOL_CATEGORY_MEDIA,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  /* http://en.wikipedia.org/wiki/Link-local_Multicast_Name_Resolution */
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_LLMNR,
			  "LLMNR", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 5355, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 5355, 0, 0, 0, 0) /* UDP */); /* Missing dissector: port based only */
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_TOCA_BOCA,
			  "TocaBoca", NDPI_PROTOCOL_CATEGORY_GAME,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 5055, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_H323,
			  "H323", NDPI_PROTOCOL_CATEGORY_VOIP,
			  ndpi_build_default_ports(ports_a, 1719, 1720, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 1719, 1720, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_OPENVPN,
			  "OpenVPN", NDPI_PROTOCOL_CATEGORY_VPN,
			  ndpi_build_default_ports(ports_a, 1194, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 1194, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_NOE,
			  "NOE", NDPI_PROTOCOL_CATEGORY_VOIP,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_CISCOVPN,
			  "CiscoVPN", NDPI_PROTOCOL_CATEGORY_VPN,
			  ndpi_build_default_ports(ports_a, 10000, 8008, 8009, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 10000, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_TEAMSPEAK,
			  "TeamSpeak", NDPI_PROTOCOL_CATEGORY_VOIP,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_POTENTIALLY_DANGEROUS, NDPI_PROTOCOL_TOR,
			  "Tor", NDPI_PROTOCOL_CATEGORY_VPN,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_SKINNY,
			  "CiscoSkinny", NDPI_PROTOCOL_CATEGORY_VOIP,
			  ndpi_build_default_ports(ports_a, 2000, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_RTCP,
			  "RTCP", NDPI_PROTOCOL_CATEGORY_VOIP,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_RSYNC,
			  "RSYNC", NDPI_PROTOCOL_CATEGORY_DATA_TRANSFER,
			  ndpi_build_default_ports(ports_a, 873, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_ORACLE,
			  "Oracle", NDPI_PROTOCOL_CATEGORY_DATABASE,
			  ndpi_build_default_ports(ports_a, 1521, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_CORBA,
			  "Corba", NDPI_PROTOCOL_CATEGORY_RPC,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 1 /* app proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_UBUNTUONE,
			  "UbuntuONE", NDPI_PROTOCOL_CATEGORY_CLOUD,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_WHOIS_DAS,
			  "Whois-DAS", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 43, 4343, 0, 0, 0), /* TCP */
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0));    /* UDP */
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_SD_RTN,
			  "SD-RTN", NDPI_PROTOCOL_CATEGORY_MEDIA,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0),  /* TCP */
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0)); /* UDP */
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_SOCKS,
			  "SOCKS", NDPI_PROTOCOL_CATEGORY_WEB,
			  ndpi_build_default_ports(ports_a, 1080, 0, 0, 0, 0),  /* TCP */
			  ndpi_build_default_ports(ports_b, 1080, 0, 0, 0, 0)); /* UDP */
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_TFTP,
			  "TFTP", NDPI_PROTOCOL_CATEGORY_DATA_TRANSFER,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0),   /* TCP */
			  ndpi_build_default_ports(ports_b, 69, 0, 0, 0, 0)); /* UDP */
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_RTMP,
			  "RTMP", NDPI_PROTOCOL_CATEGORY_MEDIA,
			  ndpi_build_default_ports(ports_a, 1935, 0, 0, 0, 0), /* TCP */
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0));   /* UDP */
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_PINTEREST,
			  "Pinterest", NDPI_PROTOCOL_CATEGORY_SOCIAL_NETWORK,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0),  /* TCP */
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0)); /* UDP */
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_MEGACO,
			  "Megaco", NDPI_PROTOCOL_CATEGORY_VOIP,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0),     /* TCP */
			  ndpi_build_default_ports(ports_b, 2944, 0, 0, 0, 0)); /* UDP */
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_REDIS,
			  "Redis", NDPI_PROTOCOL_CATEGORY_DATABASE,
			  ndpi_build_default_ports(ports_a, 6379, 0, 0, 0, 0), /* TCP */
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0));   /* UDP */
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_ZMQ,
			  "ZeroMQ", NDPI_PROTOCOL_CATEGORY_RPC,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0),  /* TCP */
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0)); /* UDP */
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_VHUA,
			  "VHUA", NDPI_PROTOCOL_CATEGORY_VOIP,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0),      /* TCP */
			  ndpi_build_default_ports(ports_b, 58267, 0, 0, 0, 0)); /* UDP */
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_STARCRAFT,
			  "Starcraft", NDPI_PROTOCOL_CATEGORY_GAME,
			  ndpi_build_default_ports(ports_a, 1119, 0, 0, 0, 0),  /* TCP */
			  ndpi_build_default_ports(ports_b, 1119, 0, 0, 0, 0)); /* UDP */
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_SAFE, NDPI_PROTOCOL_UBNTAC2,
			  "UBNTAC2", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0),      /* TCP */
			  ndpi_build_default_ports(ports_b, 10001, 0, 0, 0, 0)); /* UDP */
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_VIBER,
			  "Viber", NDPI_PROTOCOL_CATEGORY_VOIP,
			  ndpi_build_default_ports(ports_a, 7985, 5242, 5243, 4244, 0),     /* TCP */
			  ndpi_build_default_ports(ports_b, 7985, 7987, 5242, 5243, 4244)); /* UDP */
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_SAFE, NDPI_PROTOCOL_COAP,
			  "COAP", NDPI_PROTOCOL_CATEGORY_RPC,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0),        /* TCP */
			  ndpi_build_default_ports(ports_b, 5683, 5684, 0, 0, 0)); /* UDP */
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_MQTT,
			  "MQTT", NDPI_PROTOCOL_CATEGORY_RPC,
			  ndpi_build_default_ports(ports_a, 1883, 8883, 0, 0, 0), /* TCP */
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0));      /* UDP */
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_SOMEIP,
			  "SOMEIP", NDPI_PROTOCOL_CATEGORY_RPC,
			  ndpi_build_default_ports(ports_a, 30491, 30501, 0, 0, 0),      /* TCP */
			  ndpi_build_default_ports(ports_b, 30491, 30501, 30490, 0, 0)); /* UDP */
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_RX,
			  "RX", NDPI_PROTOCOL_CATEGORY_RPC,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0),  /* TCP */
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0)); /* UDP */
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_SAFE, NDPI_PROTOCOL_GIT,
			  "Git", NDPI_PROTOCOL_CATEGORY_COLLABORATIVE,
			  ndpi_build_default_ports(ports_a, 9418, 0, 0, 0, 0), /* TCP */
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0));   /* UDP */
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_DRDA,
			  "DRDA", NDPI_PROTOCOL_CATEGORY_DATABASE,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0),  /* TCP */
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0)); /* UDP */
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_HANGOUT_DUO,
			  "GoogleHangoutDuo", NDPI_PROTOCOL_CATEGORY_VOIP,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_BJNP,
			  "BJNP", NDPI_PROTOCOL_CATEGORY_SYSTEM_OS,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 8612, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_SMPP,
			  "SMPP", NDPI_PROTOCOL_CATEGORY_DOWNLOAD_FT,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0),  /* TCP */
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0)); /* UDP */
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 1 /* app proto */, NDPI_PROTOCOL_SAFE, NDPI_PROTOCOL_OOKLA,
			  "Ookla", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0),  /* TCP */
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0)); /* UDP */
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_AMQP,
			  "AMQP", NDPI_PROTOCOL_CATEGORY_RPC,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0),  /* TCP */
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0)); /* UDP */
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_DNSCRYPT,
			  "DNScrypt", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0),  /* TCP */
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0)); /* UDP */
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_TINC,
			  "TINC", NDPI_PROTOCOL_CATEGORY_VPN,
			  ndpi_build_default_ports(ports_a, 655, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 655, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_SAFE, NDPI_PROTOCOL_FIX,
			  "FIX", NDPI_PROTOCOL_CATEGORY_RPC,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 1 /* app proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_NINTENDO,
			  "Nintendo", NDPI_PROTOCOL_CATEGORY_GAME,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_CSGO,
			  "CSGO", NDPI_PROTOCOL_CATEGORY_GAME,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_AJP,
			  "AJP", NDPI_PROTOCOL_CATEGORY_WEB,
			  ndpi_build_default_ports(ports_a, 8009, 8010, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_TARGUS_GETDATA,
			  "TargusDataspeed", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 5001, 5201, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 5001, 5201, 0, 0, 0) /* UDP */); /* Missing dissector: port based only */
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_AMAZON_VIDEO,
			  "AmazonVideo", NDPI_PROTOCOL_CATEGORY_CLOUD,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_DNP3,
			  "DNP3", NDPI_PROTOCOL_CATEGORY_IOT_SCADA,
			  ndpi_build_default_ports(ports_a, 20000, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_IEC60870,
			  "IEC60870", NDPI_PROTOCOL_CATEGORY_IOT_SCADA,
			  ndpi_build_default_ports(ports_a, 2404, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 1 /* app proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_BLOOMBERG,
			  "Bloomberg", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_CAPWAP,
			  "CAPWAP", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 5246, 5247, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_ZABBIX,
			  "Zabbix", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 10050, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_S7COMM,
			  "s7comm", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 102, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_SAFE, NDPI_PROTOCOL_MSTEAMS,
			  "Teams", NDPI_PROTOCOL_CATEGORY_COLLABORATIVE,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_WEBSOCKET,
			  "WebSocket", NDPI_PROTOCOL_CATEGORY_WEB,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 1 /* app proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_ANYDESK,
			  "AnyDesk", NDPI_PROTOCOL_CATEGORY_REMOTE_ACCESS,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_SOAP,
			  "SOAP", NDPI_PROTOCOL_CATEGORY_RPC,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_MONGODB,
			  "MongoDB", NDPI_PROTOCOL_CATEGORY_DATABASE,
			  ndpi_build_default_ports(ports_a, 27017, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_APPLE_SIRI,
			  "AppleSiri", NDPI_PROTOCOL_CATEGORY_VIRTUAL_ASSISTANT,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 1 /* app proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_SNAPCHAT_CALL,
			  "SnapchatCall", NDPI_PROTOCOL_CATEGORY_VOIP,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_HPVIRTGRP,
			  "HP_VIRTGRP", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_GENSHIN_IMPACT,
			  "GenshinImpact", NDPI_PROTOCOL_CATEGORY_GAME,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 22102, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 1 /* app proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_ACTIVISION,
			  "Activision", NDPI_PROTOCOL_CATEGORY_GAME,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_SAFE, NDPI_PROTOCOL_FORTICLIENT,
			  "FortiClient", NDPI_PROTOCOL_CATEGORY_VPN,
			  ndpi_build_default_ports(ports_a, 8013, 8014, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_Z3950,
			  "Z3950", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 210, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 1 /* app proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_LIKEE,
			  "Likee", NDPI_PROTOCOL_CATEGORY_SOCIAL_NETWORK,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 1 /* app proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_GITLAB,
			  "GitLab", NDPI_PROTOCOL_CATEGORY_COLLABORATIVE,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_SAFE, NDPI_PROTOCOL_AVAST_SECUREDNS,
			  "AVASTSecureDNS", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0),  /* TCP */
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0)); /* UDP */
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_CASSANDRA,
			  "Cassandra", NDPI_PROTOCOL_CATEGORY_DATABASE,
			  ndpi_build_default_ports(ports_a, 9042, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_FACEBOOK_VOIP,
			  "FacebookVoip", NDPI_PROTOCOL_CATEGORY_VOIP,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_SIGNAL_VOIP,
			  "SignalVoip", NDPI_PROTOCOL_CATEGORY_VOIP,
                          ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_MICROSOFT_AZURE,
			  "Azure", NDPI_PROTOCOL_CATEGORY_CLOUD,
                          ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_GOOGLE_CLOUD,
			  "GoogleCloud", NDPI_PROTOCOL_CATEGORY_CLOUD,
                          ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 1 /* app proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_TENCENT,
                          "Tencent", NDPI_PROTOCOL_CATEGORY_SOCIAL_NETWORK,
                          ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
                          ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_RAKNET,
                          "RakNet", NDPI_PROTOCOL_CATEGORY_GAME,
                          ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0), /* TCP */
                          ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_XIAOMI,
                          "Xiaomi", NDPI_PROTOCOL_CATEGORY_WEB,
                          ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
                          ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_EDGECAST,
                          "Edgecast", NDPI_PROTOCOL_CATEGORY_CLOUD,
                          ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
                          ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_CACHEFLY,
                          "Cachefly", NDPI_PROTOCOL_CATEGORY_CLOUD,
                          ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
                          ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_SOFTETHER,
                          "Softether", NDPI_PROTOCOL_CATEGORY_VPN,
                          ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
                          ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 1 /* app proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_MPEGDASH,
                          "MpegDash", NDPI_PROTOCOL_CATEGORY_MEDIA,
                          ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
                          ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  /*
     Note: removed RSH port 514 as TCP/514 is often used for syslog and RSH is as such on;y
     if both source and destination ports are 514. So we removed the default for RSH and used with syslog
  */
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_UNSAFE, NDPI_PROTOCOL_RSH,
                          "RSH", NDPI_PROTOCOL_CATEGORY_REMOTE_ACCESS,
                          ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
                          ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_IP_PIM,
                          "IP_PIM", NDPI_PROTOCOL_CATEGORY_NETWORK,
                          ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
                          ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_COLLECTD,
                          "collectd", NDPI_PROTOCOL_CATEGORY_SYSTEM_OS,
                          ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
                          ndpi_build_default_ports(ports_b, 25826, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_I3D,
                          "i3D", NDPI_PROTOCOL_CATEGORY_GAME,
                          ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
                          ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_RIOTGAMES,
                          "RiotGames", NDPI_PROTOCOL_CATEGORY_GAME,
                           ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
                           ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_ULTRASURF,
                          "UltraSurf", NDPI_PROTOCOL_CATEGORY_VPN,
                          ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
                          ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 0 /* nw proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_THREEMA,
                          "Threema", NDPI_PROTOCOL_CATEGORY_CHAT,
                          ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
                          ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_ALICLOUD,
                          "AliCloud", NDPI_PROTOCOL_CATEGORY_CLOUD,
                          ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
                          ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 0 /* nw proto */, NDPI_PROTOCOL_SAFE, NDPI_PROTOCOL_AVAST,
                          "AVAST", NDPI_PROTOCOL_CATEGORY_NETWORK,
                          ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
                          ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_TIVOCONNECT,
                          "TiVoConnect", NDPI_PROTOCOL_CATEGORY_NETWORK,
                          ndpi_build_default_ports(ports_a, 2190, 0, 0, 0, 0) /* TCP */,
                          ndpi_build_default_ports(ports_b, 2190, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_KISMET,
                          "Kismet", NDPI_PROTOCOL_CATEGORY_NETWORK,
                          ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
                          ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_SAFE, NDPI_PROTOCOL_FASTCGI,
                          "FastCGI", NDPI_PROTOCOL_CATEGORY_NETWORK,
                          ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
                          ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 0 /* nw proto */, NDPI_PROTOCOL_UNSAFE, NDPI_PROTOCOL_FTPS,
                          "FTPS", NDPI_PROTOCOL_CATEGORY_DOWNLOAD_FT,
                          ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
                          ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_NATPMP,
                          "NAT-PMP", NDPI_PROTOCOL_CATEGORY_NETWORK,
                          ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
                          ndpi_build_default_ports(ports_b, 5351, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 0 /* nw proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_SYNCTHING,
                          "Syncthing", NDPI_PROTOCOL_CATEGORY_DOWNLOAD_FT,
                          ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
                          ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 0 /* nw proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_CRYNET,
                          "CryNetwork", NDPI_PROTOCOL_CATEGORY_GAME,
                          ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
                          ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_LINE,
                         "Line", NDPI_PROTOCOL_CATEGORY_CHAT,
                          ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
                          ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_LINE_CALL,
                         "LineCall", NDPI_PROTOCOL_CATEGORY_VOIP,
                          ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
                          ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_MUNIN,
                          "Munin", NDPI_PROTOCOL_CATEGORY_SYSTEM_OS,
                          ndpi_build_default_ports(ports_a, 4949, 0, 0, 0, 0) /* TCP */,
                          ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_ELASTICSEARCH,
                          "Elasticsearch", NDPI_PROTOCOL_CATEGORY_SYSTEM_OS,
                          ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
                          ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* encrypted */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_TUYA_LP,
                          "TuyaLP", NDPI_PROTOCOL_CATEGORY_IOT_SCADA,
                          ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
                          ndpi_build_default_ports(ports_b, 6667, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* encrypted */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_TPLINK_SHP,
                          "TPLINK_SHP", NDPI_PROTOCOL_CATEGORY_IOT_SCADA,
                          ndpi_build_default_ports(ports_a, 9999, 0, 0, 0, 0) /* TCP */,
                          ndpi_build_default_ports(ports_b, 9999, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_TAILSCALE,
			  "Tailscale", NDPI_PROTOCOL_CATEGORY_VPN,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 41641, 0, 0, 0, 0) /* UDP */);
#endif


#ifdef CUSTOM_NDPI_PROTOCOLS
#include "../../../nDPI-custom/custom_ndpi_main.c"
#endif

  /* calling function for host and content matched protocols */
  init_string_based_protocols(ndpi_str);

  ndpi_validate_protocol_initialization(ndpi_str);
}

static void ndpi_enabled_callbacks_init(struct ndpi_detection_module_struct *ndpi_str,
	  const NDPI_PROTOCOL_BITMASK *dbm, int count_only) {
  uint32_t a;

  /* now build the specific buffer for tcp, udp and non_tcp_udp */
  ndpi_str->callback_buffer_size_tcp_payload = 0;
  ndpi_str->callback_buffer_size_tcp_no_payload = 0;
  for(a = 0; a < ndpi_str->callback_buffer_size; a++) {
    if(!NDPI_ISSET(dbm,ndpi_str->callback_buffer[a].ndpi_protocol_id)) continue;
    if(!ndpi_proto_cb_tcp_payload(ndpi_str,a)) continue;
    if(!count_only) {
          memcpy(&ndpi_str->callback_buffer_tcp_payload[ndpi_str->callback_buffer_size_tcp_payload],
	         &ndpi_str->callback_buffer[a], sizeof(struct ndpi_call_function_struct));
    }
    ndpi_str->callback_buffer_size_tcp_payload++;
  }
  for(a = 0; a < ndpi_str->callback_buffer_size; a++) {
    if(!NDPI_ISSET(dbm,ndpi_str->callback_buffer[a].ndpi_protocol_id)) continue;
    if(!ndpi_proto_cb_tcp_nopayload(ndpi_str,a)) continue;
    if(!count_only) {
	  memcpy(&ndpi_str->callback_buffer_tcp_no_payload[ndpi_str->callback_buffer_size_tcp_no_payload],
	         &ndpi_str->callback_buffer[a], sizeof(struct ndpi_call_function_struct));
    }
    ndpi_str->callback_buffer_size_tcp_no_payload++;
  }

  ndpi_str->callback_buffer_size_udp = 0;
  for(a = 0; a < ndpi_str->callback_buffer_size; a++) {
    if(!NDPI_ISSET(dbm,ndpi_str->callback_buffer[a].ndpi_protocol_id)) continue;
    if(!ndpi_proto_cb_udp(ndpi_str,a)) continue;
    if(!count_only) {
      memcpy(&ndpi_str->callback_buffer_udp[ndpi_str->callback_buffer_size_udp], &ndpi_str->callback_buffer[a],
	     sizeof(struct ndpi_call_function_struct));
    }
    ndpi_str->callback_buffer_size_udp++;
  }

  ndpi_str->callback_buffer_size_non_tcp_udp = 0;
  for(a = 0; a < ndpi_str->callback_buffer_size; a++) {
    if(!NDPI_ISSET(dbm,ndpi_str->callback_buffer[a].ndpi_protocol_id)) continue;
    if(!ndpi_proto_cb_other(ndpi_str,a)) continue;
    if(!count_only) {
            memcpy(&ndpi_str->callback_buffer_non_tcp_udp[ndpi_str->callback_buffer_size_non_tcp_udp],
	     &ndpi_str->callback_buffer[a], sizeof(struct ndpi_call_function_struct));
    }
    ndpi_str->callback_buffer_size_non_tcp_udp++;
  }
}

static int ndpi_callback_init(struct ndpi_detection_module_struct *ndpi_str) {

  NDPI_PROTOCOL_BITMASK *detection_bitmask = &ndpi_str->detection_bitmask;
  struct ndpi_call_function_struct *all_cb = NULL;
  u_int32_t a = 0;

  if(ndpi_str->callback_buffer) return 0;

  ndpi_str->callback_buffer = ndpi_calloc(NDPI_MAX_SUPPORTED_PROTOCOLS+1,sizeof(struct ndpi_call_function_struct));
  if(!ndpi_str->callback_buffer) return 1;

  /* set this here to zero to be interrupt safe */
  ndpi_str->callback_buffer_size = 0;

  /* HTTP */
  init_http_dissector(ndpi_str, &a);

  /* STARCRAFT */
  init_starcraft_dissector(ndpi_str, &a);

  /* TLS+DTLS */
  init_tls_dissector(ndpi_str, &a);

  /* RTP */
  init_rtp_dissector(ndpi_str, &a);

  /* RTSP */
  init_rtsp_dissector(ndpi_str, &a);

  /* RDP */
  init_rdp_dissector(ndpi_str, &a);

  /* STUN */
  init_stun_dissector(ndpi_str, &a);

  /* SIP */
  init_sip_dissector(ndpi_str, &a);

  /* IMO */
  init_imo_dissector(ndpi_str, &a);

  /* Teredo */
  init_teredo_dissector(ndpi_str, &a);

  /* EDONKEY */
  init_edonkey_dissector(ndpi_str, &a);

  /* GNUTELLA */
  init_gnutella_dissector(ndpi_str, &a);

  /* NATS */
  init_nats_dissector(ndpi_str, &a);

  /* SOCKS */
  init_socks_dissector(ndpi_str, &a);

  /* IRC */
  init_irc_dissector(ndpi_str, &a);

  /* JABBER */
  init_jabber_dissector(ndpi_str, &a);

  /* MAIL_POP */
  init_mail_pop_dissector(ndpi_str, &a);

  /* MAIL_IMAP */
  init_mail_imap_dissector(ndpi_str, &a);

  /* MAIL_SMTP */
  init_mail_smtp_dissector(ndpi_str, &a);

  /* USENET */
  init_usenet_dissector(ndpi_str, &a);

  /* DNS */
  init_dns_dissector(ndpi_str, &a);

  /* VMWARE */
  init_vmware_dissector(ndpi_str, &a);

  /* NON_TCP_UDP */
  init_non_tcp_udp_dissector(ndpi_str, &a);

  /* TVUPLAYER */
  init_tvuplayer_dissector(ndpi_str, &a);

  /* PPSTREAM */
  init_ppstream_dissector(ndpi_str, &a);

  /* IAX */
  init_iax_dissector(ndpi_str, &a);

  /* Media Gateway Control Protocol */
  init_mgcp_dissector(ndpi_str, &a);

  /* ZATTOO */
  init_zattoo_dissector(ndpi_str, &a);

  /* QQ */
  init_qq_dissector(ndpi_str, &a);

  /* SSH */
  init_ssh_dissector(ndpi_str, &a);

  /* VNC */
  init_vnc_dissector(ndpi_str, &a);

  /* VXLAN */
  init_vxlan_dissector(ndpi_str, &a);

  /* TEAMVIEWER */
  init_teamviewer_dissector(ndpi_str, &a);

  /* DHCP */
  init_dhcp_dissector(ndpi_str, &a);

  /* STEAM */
  init_steam_dissector(ndpi_str, &a);

  /* HALFLIFE2 */
  init_halflife2_dissector(ndpi_str, &a);

  /* XBOX */
  init_xbox_dissector(ndpi_str, &a);

  /* SMB */
  init_smb_dissector(ndpi_str, &a);

  /* MINING */
  init_mining_dissector(ndpi_str, &a);

  /* TELNET */
  init_telnet_dissector(ndpi_str, &a);

  /* NTP */
  init_ntp_dissector(ndpi_str, &a);

  /* NFS */
  init_nfs_dissector(ndpi_str, &a);

  /* SSDP */
  init_ssdp_dissector(ndpi_str, &a);

  /* WORLD_OF_WARCRAFT */
  init_world_of_warcraft_dissector(ndpi_str, &a);

  /* POSTGRES */
  init_postgres_dissector(ndpi_str, &a);

  /* MYSQL */
  init_mysql_dissector(ndpi_str, &a);

  /* BGP */
  init_bgp_dissector(ndpi_str, &a);

  /* SNMP */
  init_snmp_dissector(ndpi_str, &a);

  /* KONTIKI */
  init_kontiki_dissector(ndpi_str, &a);

  /* ICECAST */
  init_icecast_dissector(ndpi_str, &a);

  /* KERBEROS */
  init_kerberos_dissector(ndpi_str, &a);

  /* SYSLOG */
  init_syslog_dissector(ndpi_str, &a);

  /* NETBIOS */
  init_netbios_dissector(ndpi_str, &a);

  /* IPP */
  init_ipp_dissector(ndpi_str, &a);

  /* LDAP */
  init_ldap_dissector(ndpi_str, &a);

  /* WARCRAFT3 */
  init_warcraft3_dissector(ndpi_str, &a);

  /* XDMCP */
  init_xdmcp_dissector(ndpi_str, &a);

  /* TFTP */
  init_tftp_dissector(ndpi_str, &a);

  /* MSSQL_TDS */
  init_mssql_tds_dissector(ndpi_str, &a);

  /* PPTP */
  init_pptp_dissector(ndpi_str, &a);

  /* DHCPV6 */
  init_dhcpv6_dissector(ndpi_str, &a);

  /* AFP */
  init_afp_dissector(ndpi_str, &a);

  /* check_mk */
  init_checkmk_dissector(ndpi_str, &a);

  /* cpha */
  init_cpha_dissector(ndpi_str, &a);

  /* MAPLESTORY */
  init_maplestory_dissector(ndpi_str, &a);

  /* DOFUS */
  init_dofus_dissector(ndpi_str, &a);

  /* WORLD_OF_KUNG_FU */
  init_world_of_kung_fu_dissector(ndpi_str, &a);

  /* CROSSIFIRE */
  init_crossfire_dissector(ndpi_str, &a);

  /* GUILDWARS */
  init_guildwars_dissector(ndpi_str, &a);

  /* ARMAGETRON */
  init_armagetron_dissector(ndpi_str, &a);

  /* DROPBOX */
  init_dropbox_dissector(ndpi_str, &a);

  /* SPOTIFY */
  init_spotify_dissector(ndpi_str, &a);

  /* RADIUS */
  init_radius_dissector(ndpi_str, &a);

  /* CITRIX */
  init_citrix_dissector(ndpi_str, &a);

  /* LOTUS_NOTES */
  init_lotus_notes_dissector(ndpi_str, &a);

  /* GTP */
  init_gtp_dissector(ndpi_str, &a);

  /* HSRP */
  init_hsrp_dissector(ndpi_str, &a);

  /* DCERPC */
  init_dcerpc_dissector(ndpi_str, &a);

  /* NETFLOW */
  init_netflow_dissector(ndpi_str, &a);

  /* SFLOW */
  init_sflow_dissector(ndpi_str, &a);

  /* H323 */
  init_h323_dissector(ndpi_str, &a);

  /* OPENVPN */
  init_openvpn_dissector(ndpi_str, &a);

  /* NOE */
  init_noe_dissector(ndpi_str, &a);

  /* CISCOVPN */
  init_ciscovpn_dissector(ndpi_str, &a);

  /* TEAMSPEAK */
  init_teamspeak_dissector(ndpi_str, &a);

  /* SKINNY */
  init_skinny_dissector(ndpi_str, &a);

  /* RTCP */
  init_rtcp_dissector(ndpi_str, &a);

  /* RSYNC */
  init_rsync_dissector(ndpi_str, &a);

  /* WHOIS_DAS */
  init_whois_das_dissector(ndpi_str, &a);

  /* ORACLE */
  init_oracle_dissector(ndpi_str, &a);

  /* CORBA */
  init_corba_dissector(ndpi_str, &a);

  /* RTMP */
  init_rtmp_dissector(ndpi_str, &a);

  /* FTP_CONTROL */
  init_ftp_control_dissector(ndpi_str, &a);

  /* FTP_DATA */
  init_ftp_data_dissector(ndpi_str, &a);

  /* MEGACO */
  init_megaco_dissector(ndpi_str, &a);

  /* REDIS */
  init_redis_dissector(ndpi_str, &a);

  /* VHUA */
  init_vhua_dissector(ndpi_str, &a);

  /* ZMQ */
  init_zmq_dissector(ndpi_str, &a);

  /* TELEGRAM */
  init_telegram_dissector(ndpi_str, &a);

  /* QUIC */
  init_quic_dissector(ndpi_str, &a);

  /* DIAMETER */
  init_diameter_dissector(ndpi_str, &a);

  /* APPLE_PUSH */
  init_apple_push_dissector(ndpi_str, &a);

  /* EAQ */
  init_eaq_dissector(ndpi_str, &a);

  /* KAKAOTALK_VOICE */
  init_kakaotalk_voice_dissector(ndpi_str, &a);

  /* MPEGTS */
  init_mpegts_dissector(ndpi_str, &a);

  /* UBNTAC2 */
  init_ubntac2_dissector(ndpi_str, &a);

  /* COAP */
  init_coap_dissector(ndpi_str, &a);

  /* MQTT */
  init_mqtt_dissector(ndpi_str, &a);

  /* SOME/IP */
  init_someip_dissector(ndpi_str, &a);

  /* RX */
  init_rx_dissector(ndpi_str, &a);

  /* GIT */
  init_git_dissector(ndpi_str, &a);

  /* HANGOUT */
  init_hangout_dissector(ndpi_str, &a);

  /* DRDA */
  init_drda_dissector(ndpi_str, &a);

  /* BJNP */
  init_bjnp_dissector(ndpi_str, &a);

  /* SMPP */
  init_smpp_dissector(ndpi_str, &a);

  /* TINC */
  init_tinc_dissector(ndpi_str, &a);

  /* FIX */
  init_fix_dissector(ndpi_str, &a);

  /* NINTENDO */
  init_nintendo_dissector(ndpi_str, &a);

  /* MODBUS */
  init_modbus_dissector(ndpi_str, &a);

  /* CAPWAP */
  init_capwap_dissector(ndpi_str, &a);

  /* ZABBIX */
  init_zabbix_dissector(ndpi_str, &a);

  /*** Put false-positive sensitive protocols at the end ***/

  /* VIBER */
  init_viber_dissector(ndpi_str, &a);

  /* SKYPE */
  init_skype_dissector(ndpi_str, &a);

  /* BITTORRENT */
  init_bittorrent_dissector(ndpi_str, &a);

  /* WHATSAPP */
  init_whatsapp_dissector(ndpi_str, &a);

  /* OOKLA */
  init_ookla_dissector(ndpi_str, &a);

  /* AMQP */
  init_amqp_dissector(ndpi_str, &a);

  /* CSGO */
  init_csgo_dissector(ndpi_str, &a);

  /* LISP */
  init_lisp_dissector(ndpi_str, &a);

  /* AJP */
  init_ajp_dissector(ndpi_str, &a);

  /* Memcached */
  init_memcached_dissector(ndpi_str, &a);

  /* Nest Log Sink */
  init_nest_log_sink_dissector(ndpi_str, &a);

  /* WireGuard VPN */
  init_wireguard_dissector(ndpi_str, &a);

  /* Amazon_Video */
  init_amazon_video_dissector(ndpi_str, &a);

  /* S7 comm */
  init_s7comm_dissector(ndpi_str, &a);

  /* IEC 60870-5-104 */
  init_104_dissector(ndpi_str, &a);

  /* DNP3 */
  init_dnp3_dissector(ndpi_str, &a);

  /* WEBSOCKET */
  init_websocket_dissector(ndpi_str, &a);

  /* SOAP */
  init_soap_dissector(ndpi_str, &a);

  /* DNScrypt */
  init_dnscrypt_dissector(ndpi_str, &a);

  /* MongoDB */
  init_mongodb_dissector(ndpi_str, &a);

  /* AmongUS */
  init_among_us_dissector(ndpi_str, &a);

  /* HP Virtual Machine Group Management */
  init_hpvirtgrp_dissector(ndpi_str, &a);

  /* Genshin Impact */
  init_genshin_impact_dissector(ndpi_str, &a);

  /* Z39.50 international standard client–server, application layer communications protocol */
  init_z3950_dissector(ndpi_str, &a);

  /* AVAST SecureDNS */
  init_avast_securedns_dissector(ndpi_str, &a);

  /* Cassandra */
  init_cassandra_dissector(ndpi_str, &a);

  /* EthernetIP */
  init_ethernet_ip_dissector(ndpi_str, &a);

  /* WSD */
  init_wsd_dissector(ndpi_str, &a);

  /* TocaBoca */
  init_toca_boca_dissector(ndpi_str, &a);

  /* SD-RTN Software Defined Real-time Network */
  init_sd_rtn_dissector(ndpi_str, &a);

  /* RakNet */
  init_raknet_dissector(ndpi_str, &a);

  /* Xiaomi */
  init_xiaomi_dissector(ndpi_str, &a);

  /* MpegDash */
  init_mpegdash_dissector(ndpi_str, &a);

  /* RSH */
  init_rsh_dissector(ndpi_str, &a);

  /* IPsec */
  init_ipsec_dissector(ndpi_str, &a);

  /* collectd */
  init_collectd_dissector(ndpi_str, &a);

  /* i3D */
  init_i3d_dissector(ndpi_str, &a);

  /* RiotGames */
  init_riotgames_dissector(ndpi_str, &a);

  /* UltraSurf */
  init_ultrasurf_dissector(ndpi_str, &a);

  /* Threema */
  init_threema_dissector(ndpi_str, &a);

  /* AliCloud */
  init_alicloud_dissector(ndpi_str, &a);

  /* AVAST */
  init_avast_dissector(ndpi_str, &a);

  /* Softether */
  init_softether_dissector(ndpi_str, &a);

  /* Activision */
  init_activision_dissector(ndpi_str, &a);

  /* Discord */
  init_discord_dissector(ndpi_str, &a);

  /* TiVoConnect */
  init_tivoconnect_dissector(ndpi_str, &a);

  /* Kismet */
  init_kismet_dissector(ndpi_str, &a);

  /* FastCGI */
  init_fastcgi_dissector(ndpi_str, &a);

  /* NATPMP */
  init_natpmp_dissector(ndpi_str, &a);

  /* Syncthing */
  init_syncthing_dissector(ndpi_str, &a);

  /* CryNetwork */
  init_crynet_dissector(ndpi_str, &a);

  /* Line voip */
  init_line_dissector(ndpi_str, &a);

  /* Munin */
  init_munin_dissector(ndpi_str, &a);

  /* Elasticsearch */
  init_elasticsearch_dissector(ndpi_str, &a);

  /* TUYA LP */
  init_tuya_lp_dissector(ndpi_str, &a);

  /* TPLINK_SHP */
  init_tplink_shp_dissector(ndpi_str, &a);

  /* Meraki Cloud */
  init_merakicloud_dissector(ndpi_str, &a);

  /* Tailscale */
  init_tailscale_dissector(ndpi_str, &a);

#ifdef CUSTOM_NDPI_PROTOCOLS
#include "../../../nDPI-custom/custom_ndpi_main_init.c"
#endif

  /* ----------------------------------------------------------------- */

  ndpi_str->callback_buffer_size = a;

  /* Resize callback_buffer */
  all_cb = ndpi_calloc(a+1,sizeof(struct ndpi_call_function_struct));
  if(all_cb) {
    memcpy((char *)all_cb,(char *)ndpi_str->callback_buffer, (a+1) * sizeof(struct ndpi_call_function_struct));
    ndpi_free(ndpi_str->callback_buffer);
    ndpi_str->callback_buffer = all_cb;
  }

  NDPI_LOG_DBG2(ndpi_str, "callback_buffer_size is %u\n", ndpi_str->callback_buffer_size);
  /* Calculating the size of an array for callback functions */
  ndpi_enabled_callbacks_init(ndpi_str,detection_bitmask,1);
  all_cb = ndpi_calloc(ndpi_str->callback_buffer_size_tcp_payload +
		       ndpi_str->callback_buffer_size_tcp_no_payload +
		       ndpi_str->callback_buffer_size_udp +
		       ndpi_str->callback_buffer_size_non_tcp_udp,
		       sizeof(struct ndpi_call_function_struct));
  if(!all_cb) return 1;

  ndpi_str->callback_buffer_tcp_payload = all_cb;
  all_cb += ndpi_str->callback_buffer_size_tcp_payload;
  ndpi_str->callback_buffer_tcp_no_payload = all_cb;
  all_cb += ndpi_str->callback_buffer_size_tcp_no_payload;
  ndpi_str->callback_buffer_udp = all_cb;
  all_cb += ndpi_str->callback_buffer_size_udp;
  ndpi_str->callback_buffer_non_tcp_udp = all_cb;

  ndpi_enabled_callbacks_init(ndpi_str,detection_bitmask,0);

  /*   When the module ends, it is necessary to free the memory ndpi_str->callback_buffer and
       ndpi_str->callback_buffer_tcp_payload  */

  return 0;
}

int ndpi_set_protocol_detection_bitmask2(struct ndpi_detection_module_struct *ndpi_str,
                                          const NDPI_PROTOCOL_BITMASK *dbm) {
  if(!ndpi_str)
    return -1;

  NDPI_BITMASK_SET(ndpi_str->detection_bitmask, *dbm);

  ndpi_init_protocol_defaults(ndpi_str);

  ndpi_enabled_callbacks_init(ndpi_str,dbm,0);

  if(ndpi_callback_init(ndpi_str)) {
    NDPI_LOG_ERR(ndpi_str, "[NDPI] Error allocating callbacks\n");
    return -1;
  }

  return 0;
}

void
setup_ndpi(void) {
        NDPI_PROTOCOL_BITMASK all;
        struct ndpi_workflow_prefs prefs;

        memset(&prefs, 0, sizeof(prefs));
        prefs.decode_tunnels = decode_tunnels;
        prefs.num_roots = NUM_ROOTS;
        prefs.max_ndpi_flows = MAX_NDPI_FLOWS;
        prefs.quiet_mode = quiet_mode;

        workflow = ndpi_workflow_init(&prefs);

        NDPI_BITMASK_SET_ALL(all);
        ndpi_set_protocol_detection_bitmask2(workflow->ndpi_struct, &all);

        memset(workflow->stats.protocol_counter, 0, sizeof(workflow->stats.protocol_counter));
        memset(workflow->stats.protocol_counter_bytes, 0, sizeof(workflow->stats.protocol_counter_bytes));
        memset(workflow->stats.protocol_flows, 0, sizeof(workflow->stats.protocol_flows));
}

int
packet_handler(const char *pkt, int len) {
        struct pcap_pkthdr pkt_hdr;
        struct timeval time;
        ndpi_protocol prot;

        time.tv_usec = 0;
        time.tv_sec = 0;

        pkt_hdr.ts = time;
        pkt_hdr.caplen = len;
        pkt_hdr.len = len;

	ndpi_risk flow_risk;

        prot = ndpi_workflow_process_packet(workflow, &pkt_hdr, pkt, &flow_risk);
        workflow->stats.protocol_counter[prot.app_protocol]++;
        workflow->stats.protocol_counter_bytes[prot.app_protocol] += pkt_hdr.len;

        return 0;
}
