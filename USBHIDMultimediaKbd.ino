#include <hidcomposite.h>
#include <usbhub.h>
#include <ESP8266WiFi.h>
#include <stdlib.h>

#pragma GCC diagnostic warning "-fpermissive"

// Satisfy the IDE, which needs to see the include statment in the ino too.
#ifdef dobogusinclude
#include <spi4teensy3.h>
#endif
#include <SPI.h>

#include "scanner.h"
#include "types.h"
#include "bearssl_tools.h"
#include "cert.h"

using namespace BearSSL;

br_x509_pkey* pkey = NULL;
enc_cart_t*  encrypted_cart = NULL;
unsigned int need_send;
unsigned int need_encrypt;
cart_t* cart = NULL;
unsigned int cart_index;

const char* x509_cert_start = "-----BEGIN CERTIFICATE-----";
const char* x509_cert_end   = "-----END CERTIFICATE-----";

char usbscancodes_1[] =
{'0', '0', '0', '0', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't',
 'u', 'v', 'w', 'x', 'y', 'z', '1', '2', '3', '4', '5', '6',
 '7', '8', '9', '0'};

char usbscancodes_1shift[] =
{'0', '0', '0', '0', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',
 'U', 'V', 'W', 'X', 'Y', 'Z', '1', '2', '3', '4', '5', '6',
 '7', '8', '9', '0'};

/* Start at scancode decimal 44 */
char usbscancodes_2[] =
{' ', '-', '=', '[', ']', '\\', ' ', ';', '\'', '`', ',', '.', '/'};
char usbscancodes_2shift[] =
{' ', '_', '+', '{', '}', '|', ' ', ':', '"', '~', '<', '>', '?'};

char* cert = R"(-----BEGIN CERTIFICATE-----
MIIDPDCCAiSgAwIBAgIUWNq6Ns3toNpcEDNzjgxkknmSrwMwDQYJKoZIhvcNAQELBQAwJzELMAkG
A1UEBhMCQ0ExGDAWBgNVBAMTD0ludGVybWVkaWF0ZSBDQTAeFw0xMDAxMDEwMDAwMDBaFw0zNzEy
MzEyMzU5NTlaMCExCzAJBgNVBAYTAkNBMRIwEAYDVQQDEwlsb2NhbGhvc3QwggEiMA0GCSqGSIb3
DQEBAQUAA4IBDwAwggEKAoIBAQDUeh0nuis6Z7KRavvng0TK7Rx1rd1Ng2LWqmiVsiQhexWuKplo
Fe1m8LhY59P1LsbZKl7nDi7n/GdZwMhhfUukb92f2ciFh2THuhoPKdSWqHiaa2IgqTLQ7qmMKGFH
olAqY/Yh3trY1fB/xQCCcOajv1yJJ09RkncDw7DMLjvsI/IvU0GviZP/0oCxQ5fe1hmgkhJ6PWZ5
4cG84Xdwoos9RoRTP+ROQkE3kh4f/Tiz9++HOYDTVs/04BPeZLBypAOExEHtb/o+4soEINLX3CyC
K3ribaEcSNvPiU80lz0oqFPa58HhcxWjMHZ/jyNCFD1RNNJarTyby8j+f26OQPO9AgMBAAGjZjBk
MB8GA1UdIwQYMBaAFMUBrXzmY8mcF1/FoqfhUF/o9ajGMB0GA1UdDgQWBBTFAa185mPJnBdfxaKn
4VBf6PWoxjAMBgNVHRMBAf8EAjAAMBQGA1UdEQQNMAuCCWxvY2FsaG9zdDANBgkqhkiG9w0BAQsF
AAOCAQEAcbNdIcIO19DG+Epzh00iAifQx/j9Gm1iWIIIdiAHwEiS8+mYWusNTlaVY2hNq9QAduA3
zwsRYVlc3valFFnZJZ9Z2dNehqwdpiwyQhkyE0ALVM1nJra9tJakyh9/N9aodes6gVEwuflKAW/R
1u1P3z8wYAZnko5hhV8atYyzD2Gp+t9dxGQA6oexM199y6OFJG4sZTvqcz+G0/3o5ALGYWomF1IB
JVx/qM5pH6xhLLcEr/2kepnLJhVM/3TUcwxXDCbr1yrcXMNBu8Lzzha9jnv76d+rIQ2Rs43Yz8j0
SbnQ4xZwP7Pe1Acl+kZEUolNicjiyrUzf8chvSjv/mZ0Aw==
-----END CERTIFICATE-----)";


// Override HIDComposite to be able to select which interface we want to hook into
class HIDSelector : public HIDComposite
{
public:
    HIDSelector(USB *p) : HIDComposite(p) {};

protected:
    void ParseHIDData(USBHID *hid, uint8_t ep, bool is_rpt_id, uint8_t len, uint8_t *buf); // Called by the HIDComposite library
    bool SelectInterface(uint8_t iface, uint8_t proto);
};

// Return true for the interface we want to hook into
bool HIDSelector::SelectInterface(uint8_t iface, uint8_t proto)
{
  if (proto != 0)
    return true;

  return false;
}


#define ACCUM_SIZE 2048
char input[ACCUM_SIZE]; /* Local buffer for input copy */
typedef struct input {
    char          accum[ACCUM_SIZE];
    unsigned int  index;
} input_t;

input_t in;

void reset_input(input_t* in)
{
    memset(in->accum, 0, ACCUM_SIZE);
    in->index = 0;
}

unsigned int accumulator_full(input_t* in)
{
    return in->index == ACCUM_SIZE-1;
}

int accumulate_input(input_t* in, unsigned char c)
{
    if (in->index < ACCUM_SIZE)
    {
        in->accum[in->index] = c;
        in->index++;
    }
    else
    {
        Serial.println("Accumulator full!\n");
        return -1;
    }
    return in->index;
}

void flush_input(input_t* in, char* out)
{
    memset(out, 0, ACCUM_SIZE);
    memcpy(out, in->accum, ACCUM_SIZE);
    reset_input(in);
}

void flush_cart(cart_t* cart_p)
{
    memset(cart_p, 0, sizeof(cart_t));
}

// static inline void cert_fun(char* cert_pem)
// {
//     unsigned int i = 0;
//     pem_object* pems = NULL;
//     size_t num_pems  = 0;


//     pems = decode_pem(cert2, strlen(cert2), &num_pems);
//     for (i = 0; i < num_pems; i++)
//     {
//         Serial.printf("PEM: Name %s\n", pems[i].name);
//         br_x509_certificate     cert;
//         br_x509_decoder_context dc;
//         bvector                 vdn = VEC_INIT;

//         cert.data     = pems[i].data;
//         cert.data_len = pems[i].data_len;

//         br_x509_decoder_init(&dc, dn_append, &vdn, 0, 0);
//         br_x509_decoder_push(&dc, cert.data, cert.data_len);

//         pkey = *(br_x509_decoder_get_pkey(&dc));
//     }

// }

const char* ssid    = "FiOS-9NQ0N";
const char* passwd  = "wand7980toe0285wit";

const char* host    = "192.168.1.222";
const uint16_t port = 13579;

unsigned int send_cart(enc_cart_t* encrypted_cart)
{
    unsigned int ret     = 0;
    size_t       written = 0;

    Serial.printf("Trying to connect to anonymizer\n");
    WiFiClient client;
    if (!client.connect(host, port))
    {
        Serial.printf("Couldn't connect to anonymizer\n");
        ret = 1;
        goto out;
    }

    Serial.printf("Connected to anonymizer\n");
    if (client.connected())
    {
        written = client.write((uint8_t*)encrypted_cart, sizeof(enc_cart_t));

        if (written != sizeof(enc_cart_t))
        {
            Serial.println("Couldn't write full encrypted cart\n");
            ret = 2;
            goto out;
        }
    }

    need_send = 0;

out:
    client.stop();

    return ret;
}

void finish_cart(cart_t* cart_p, char* cert_pem)
{
    chunked_cart_t* chunked_cart = chunk_cart(cart_p);
    //memset(encrypted_cart, 0, sizeof(enc_cart_t));

    pem_object* pems = NULL;
    size_t num_pems  = 0;

    unsigned int i = 0;

    pems = decode_pem(cert_pem, strlen(cert_pem), &num_pems);
    for (i = 0; i < num_pems; i++)
    {
        printf("PEM: Name %s\n", pems[i].name);
        br_x509_certificate     cert;
        br_x509_decoder_context dc;
        bvector                 vdn = VEC_INIT;

        cert.data     = pems[i].data;
        cert.data_len = pems[i].data_len;

        br_x509_decoder_init(&dc, dn_append, &vdn, 0, 0);
        br_x509_decoder_push(&dc, cert.data, cert.data_len);

        *pkey = *(br_x509_decoder_get_pkey(&dc));
    }
    ESP.wdtFeed();

    print_hex((void*)pkey, sizeof(br_x509_pkey));
    ESP.wdtFeed();

    if (pkey->key_type != BR_KEYTYPE_RSA)
    {
        Serial.printf("Public key is not an RSA key. Can't encrypt!\n");
    }
    else
    {
        unsigned int i = 0;
        Serial.printf("Encrypting cart...\n");
//        hw_wdt_disable();
        for (i = 0; i < CHUNKS_PER_CART; i++)
        {
            ESP.wdtFeed();
            //encrypt_cart(encrypted_cart, chunk_cart(cart), &pkey->key.rsa, i);
        }
        //hw_wdt_enable();
        Serial.printf("Fuck\n");
        //      need_encrypt = 1;
        //need_send = 1;
    }
}

void process_input(char* input)
{
    if (input[0] == 'U' || input[0] == 'u')
    {
        flush_cart(cart);
        cart->user_id = atoi(input+1);
        cart_index = 0;
        Serial.printf("Resetting cart and setting User ID to %u\n", cart->user_id);
    }
    else if (input[0] == 'P' || input[0] == 'p')
    {
        cart->security_policy = atoi(input+1);
        Serial.printf("Setting security policy to %u\n", cart->security_policy);
    }
    /* Found an x509 cert */
    else if (strncmp(x509_cert_start, input, strlen(x509_cert_start)) == 0)
    {
        unsigned int pem_len           = strlen(input);
        char*        fixed_cert_pem    = (char*)calloc(pem_len*2, sizeof(char));
        unsigned int cert_contents_len = pem_len - strlen(x509_cert_start) - strlen(x509_cert_end);

        /* sprintf with format strings is awesome */
        sprintf(fixed_cert_pem, "%s\n%.*s\n%s", x509_cert_start, cert_contents_len, input+strlen(x509_cert_start), x509_cert_end);

        Serial.printf("Certificate read:\n%s\n", fixed_cert_pem);
        finish_cart(cart, fixed_cert_pem);
        Serial.printf("Done\n");
    }
    else
    {
        Serial.printf("Barcode scanned: %s\n", input);
        cart->code[cart_index++] = atol(input);
        //sprintf(cart.code[cart_index++], "%s", atol(input));
    }
    Serial.printf("Leaving processing\n");
}

// Will be called for all HID data received from the USB interface
void HIDSelector::ParseHIDData(USBHID *hid, uint8_t ep, bool is_rpt_id, uint8_t len, uint8_t *buf) {
    if (len && buf)  {
        if (buf[2] != 0) {
            //Serial.printf("mod 0x%x scancode %u\n", buf[0], buf[2]);
            switch (buf[2]) {
            case 40: {
                /* Newline, flush input */
                Serial.println("<Ent>");
                Serial.printf("%s\n", (char*)&in.accum);
                flush_input(&in, input);
                process_input(input);
                Serial.printf("Leaving switch\n");
                break;
            }
            default: {
                /* Shift is held */
                if (buf[0] == 2)
                {
                    if (buf[2] > 3 && buf[2] < 40) {
                        accumulate_input(&in, usbscancodes_1shift[buf[2]]);
                        //Serial.print(usbscancodes_1[buf[2]]);
                    }
                    else if (buf[2] > 43 && buf[2] < 57)
                    {
                        accumulate_input(&in, usbscancodes_2shift[buf[2]-44]);
                    }
                }
                /* No modifiers held */
                else
                {
                    if (buf[2] > 3 && buf[2] < 40) {
                        accumulate_input(&in, usbscancodes_1[buf[2]]);
                        //Serial.print(usbscancodes_1[buf[2]]);
                    }
                    else if (buf[2] > 43 && buf[2] < 57)
                    {
                        accumulate_input(&in, usbscancodes_2[buf[2]-44]);
                    }
                }

                break;
            }
            }
        }
    }
}

USB                       Usb;
HIDSelector  hidSelector(&Usb);

void setup()
{
  Serial.begin( 115200 );
#if !defined(__MIPSEL__)
  while (!Serial); // Wait for serial port to connect - used on Leonardo, Teensy and other boards with built-in USB CDC serial connection
#endif
  Serial.println("\nStart");

  if (Usb.Init() == -1)
    Serial.println("OSC did not start.");

  // Set this to higher values to enable more debug information
  // minimum 0x00, maximum 0xff, default 0x80
  UsbDEBUGlvl = 0xff;

  need_send    = 0;
  need_encrypt = 0;
  encrypted_cart = calloc(1, sizeof(enc_cart_t));
  cart           = calloc(1, sizeof(cart_t));
  pkey           = calloc(1, sizeof(br_x509_pkey));

  // WiFi.mode(WIFI_STA);
  // WiFi.begin(ssid, passwd);

  // Serial.printf("Connecting to %s\n", ssid);
  // while (WiFi.status() != WL_CONNECTED)
  // {
  //     delay(500);
  //     Serial.print(".");
  // }

  // Serial.print("Connected with IP address: ");
  // Serial.println(WiFi.localIP());

  delay( 200 );
}

unsigned int chunk_num = 0;

void loop()
{
    Serial.printf("Entering task\n");
  Usb.Task();
  Serial.printf("Leaving task\n");
  // if (need_encrypt)
  // {
  //     memset(encrypted_cart, 0, sizeof(enc_cart_t));
  //     print_hex((void*)pkey, sizeof(br_x509_pkey));
  //     encrypt_cart(encrypted_cart, chunk_cart(cart), &pkey->key.rsa, chunk_num);
  //     chunk_num += 1;
  //     if (chunk_num == CHUNKS_PER_CART)
  //     {
  //         need_encrypt = 0;
  //     }
  // }
  // if (need_send)
  // {
  //     send_cart(encrypted_cart);
  // }
}
