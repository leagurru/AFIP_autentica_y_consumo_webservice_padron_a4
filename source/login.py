import sys
import os
import time
import pytz
import datetime
from lxml import etree
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend


from asn1crypto.cms import ContentInfo, SignedData, SignerInfo, CMSAttribute, CMSAttributes, CertificateSet, CertificateChoices
from asn1crypto.core import OctetString, UTCTime
from asn1crypto import x509

from zeep import Client, Settings
from zeep.transports import Transport

# Constants
# WSDL = "https://awshomo.afip.gov.ar/sr-padron/webservices/personaServiceA4?WSDL"  # conexión al ambiente de testing
WSDL = "wsaa.wsdl"
CERT = "lg.pem"
PRIVATEKEY = "lg.pk"
PASSPHRASE = None  # No passphrase is needed if the private key is not encrypted

# PASSPHRASE = b"jfkjkerkeri3kmnr4rj3reurodfoidarieroieroier"
PROXY_HOST = "10.1.1.10"
PROXY_PORT = 51966
URL = "https://wsaahomo.afip.gov.ar/ws/services/LoginCms"


def create_TRA(service):
    root = etree.Element('loginTicketRequest', version='1.0')
    header = etree.SubElement(root, 'header')
    etree.SubElement(header, 'uniqueId').text = str(int(time.time()))
    etree.SubElement(header, 'generationTime').text = (
                datetime.datetime.now() - datetime.timedelta(seconds=60)).isoformat()
    etree.SubElement(header, 'expirationTime').text = (
                datetime.datetime.now() + datetime.timedelta(seconds=60)).isoformat()
    etree.SubElement(root, 'service').text = service
    tree = etree.ElementTree(root)
    tree.write('TRA.xml', xml_declaration=True, encoding='UTF-8', pretty_print=True)


def sign_TRA():
    with open("TRA.xml", "rb") as f:
        data = f.read()

    # Load the certificate and private key
    cert = load_pem_x509_certificate(open(CERT, 'rb').read())
    key = load_pem_private_key(open(PRIVATEKEY, 'rb').read(), password=PASSPHRASE, backend=default_backend())

    # key = load_pem_private_key(open(PRIVATEKEY, 'rb').read(), password=PASSPHRASE)

    signature = key.sign(
        data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )

    # Calculate the message digest
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    message_digest = digest.finalize()

    # Encode the certificate as DER
    cert_der = cert.public_bytes(serialization.Encoding.DER)

    # certificate = CertificateChoices('certificate')
    certificates = CertificateSet('certificate', default=None, contents=cert_der)
    # certificates = CertificateSet([CertificateChoices(cert_der)])

    # Convert issuer to an instance of asn1crypto.x509.Name
    issuer = convert_name(cert.issuer)

    # Create the CertificateSet object with the CertificateChoices object
    # certificates = CertificateSet([certificate])

    # Create the SignedData structure (assuming `SignedData` is defined elsewhere)
    signed_data = SignedData({
        'version': 'v1',
        'digest_algorithms': [{'algorithm': 'sha256'}],
        'encap_content_info': {
            'content_type': 'data',
            'content': OctetString(data)
        },
        'certificates': certificates,
        'signer_infos': [{
            'version': 'v1',
            'sid': {'issuer_and_serial_number': {
                'issuer': cert.issuer,
                'serial_number': cert.serial_number,
            }},
            'digest_algorithm': {'algorithm': 'sha256'},
            'signed_attrs': CMSAttributes([
                CMSAttribute({'type': 'content_type', 'values': ['data']}),
                CMSAttribute({'type': 'message_digest', 'values': [OctetString(message_digest)]}),
                CMSAttribute({
                    'type': 'signing_time',
                    'values': [UTCTime(datetime.datetime.now(datetime.timezone.utc))]
                })
            ]),
            'signature_algorithm': {'algorithm': 'rsassa_pkcs1v15'},
            'signature': OctetString(signature)
        }]
    })

    # Create the ContentInfo structure
    content_info = ContentInfo({
        'content_type': 'signed_data',
        'content': signed_data
    })

    # Dump the CMS structure to a file
    cms = content_info.dump()
    with open("TRA.tmp", "wb") as f:
        f.write(cms)

    os.remove("TRA.xml")

    return cms.decode('latin1')


def call_WSAA(cms):
    settings = Settings(strict=False, xml_huge_tree=True)
    transport = Transport(proxy_url=f"{PROXY_HOST}:{PROXY_PORT}")
    # transport = Transport(proxy_url=f"http://{PROXY_HOST}:{PROXY_PORT}")
    client = Client(wsdl=WSDL, settings=settings, transport=transport)
    response = client.service.loginCms(in0=cms)

    with open("request-loginCms.xml", "w") as f:
        f.write(str(client.history.last_sent))

    with open("response-loginCms.xml", "w") as f:
        f.write(str(client.history.last_received))

    return response


def show_usage(my_path):
    print(f"Uso  : {my_path} Arg#1")
    print(f"donde: Arg#1 debe ser el service name del WS de negocio.")
    print(f"  Ej.: {my_path} wsfe")


def main():
    if not os.path.exists(CERT):
        print(f"Failed to open {CERT}")
        sys.exit(1)

    if not os.path.exists(PRIVATEKEY):
        print(f"Failed to open {PRIVATEKEY}")
        sys.exit(1)

    if not os.path.exists(WSDL):
        print(f"Failed to open {WSDL}")
        sys.exit(1)

    # if len(sys.argv) < 2:
    #     show_usage(sys.argv[0])
    #     sys.exit(1)

    service = "ws_sr_padron_a4"
    # service = sys.argv[1]
    create_TRA(service)
    cms = sign_TRA()
    ta = call_WSAA(cms)

    with open("TA.xml", "w") as f:
        f.write(ta)


if __name__ == "__main__":
    main()
