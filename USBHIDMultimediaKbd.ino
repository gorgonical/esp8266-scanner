#include <hidcomposite.h>
#include <usbhub.h>

// Satisfy the IDE, which needs to see the include statment in the ino too.
#ifdef dobogusinclude
#include <spi4teensy3.h>
#endif
#include <SPI.h>

#include <ESP8266WiFi.h>

using namespace BearSSL;

char usbscancodes_1[] =
{'0', '0', '0', '0', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',
 'U', 'V', 'W', 'X', 'Y', 'Z', '1', '2', '3', '4', '5', '6',
 '7', '8', '9', '0'};

char usbscancodes_2[] =
{' ', '-', '=', '[', ']', '\\', ' ', ';', '\'', '`', ',', '.', '/'};

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

unsigned int user_id;
unsigned int security_policy;


#define ACCUM_SIZE 256
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

void process_input(char* input)
{
    if (input[0] == 'U')
    {
        user_id = atoi(input+1);
        Serial.printf("Setting User ID to %u\n", user_id);
    }
    else if (input[0] == 'P')
    {
        security_policy = atoi(input+1);
        Serial.printf("Setting security policy to %u\n", security_policy);
    }
    else
    {
        Serial.printf("Barcode scanned: %u.\n", atoi(input));
    }
}

char input[256];

// Will be called for all HID data received from the USB interface
void HIDSelector::ParseHIDData(USBHID *hid, uint8_t ep, bool is_rpt_id, uint8_t len, uint8_t *buf) {
    if (len && buf)  {
        if (buf[2] != 0) {
            Serial.print(buf[2]);
            switch (buf[2]) {
            case 40: {
                /* Newline, flush input */
                Serial.println("<Ent>");
                Serial.printf("%s\n", (char*)&in.accum);
                flush_input(&in, input);
                process_input(input);
                break;
            }
            default: {
                if (buf[2] > 3 && buf[2] < 40) {
                    accumulate_input(&in, usbscancodes_1[buf[2]]);
                    //Serial.print(usbscancodes_1[buf[2]]);
                } else if (buf[2] > 43 && buf[2] < 57) {
                    accumulate_input(&in, usbscancodes_2[buf[2]-44]);
                    //Serial.print(usbscancodes_2[buf[2]-44]);
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

  delay( 200 );
}

void loop()
{
  Usb.Task();
}
