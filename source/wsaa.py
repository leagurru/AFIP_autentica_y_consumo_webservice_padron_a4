####################################################################
# Author: Leandro Gurruchaga
# Date: 2024-05-29
# Function: Get an authorization ticket (TA) from AFIP WSAA
# Input:
#        WSDL, CERT, PRIVATEKEY, PASSPHRASE, SERVICE, URL
#        Check below for its definitions
# Output:
#        TA.xml: the authorization ticket as granted by WSAA.
####################################################################
import datetime
import os
import sys
import time
import base64
import xml.etree.ElementTree as ET

from lxml import etree
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.serialization.pkcs7 import PKCS7Options
from cryptography.hazmat.primitives.serialization.pkcs7 import PKCS7SignatureBuilder
from cryptography.x509 import load_pem_x509_certificate
from zeep import Client
from zeep.transports import Transport
from zeep.exceptions import Fault
from requests import Session

####################################################################################
# Constantes: definición
####################################################################################
WSDL_HOMOLOGACION = "docs/wsaa_homologacion.wsdl"
ARCHIVO_CERTIFICADO_X509 = "certificados/certificado_x509.pem"                # a definir en cada caso
ARCHIVO_CERTIFICADO_CLAVEPRIVADA = "certificados/claveprivada.pk"             # a definir en cada caso
PASSPHRASE = None  # Sin passphrase si la clave privada no está encriptada    # a definir en cada caso
PROXY_HOST = "10.1.1.10"                                                      # a definir en cada caso
PROXY_PORT = 51966                                                            # a definir en cada caso
# URL_TESTING_LOGIN = "https://wsaahomo.afip.gov.ar/ws/services/LoginCms"     # incluido en wsaa.wsdl
# URL_PRODUCCION_LOGIN = "https://wsaa.afip.gov.ar/ws/services/LoginCms"
SERVICIO = "ws_sr_padron_a4"
ARCHIVO_TRA = "docs/LoginTicketRequest.xml"
ARCHIVO_XML_CMS = "docs/LoginTicketRequest.xml.cms"
ARCHIVO_TICKET_DE_ACCESO_AFIP = "docs/TicketAFIP.xml"
####################################################################################

#########################################################################################################
# Flujo Principal
# A continuación se describen los pasos que se deberán seguir para solicitar un TA al WSAA.
# Cada uno de los puntos es explicado detalladamente en los apartados siguientes.
# 1. Generar el mensaje del TRA (LoginTicketRequest.xml)
# 2. Generar un CMS que contenga el TRA, su firma electrónica y el certificado
# X.509 (LoginTicketRequest.xml.cms)
# 3. Codificar en Base64 el CMS (LoginTicketRequest.xml.cms.bse64)
# 4. Invocar WSAA con el CMS y recibir LoginTicketResponse.xml
# 5. Extraer y validar la información de autorización (TA).
#########################################################################################################


def call_wsaa(request):

    # Configurar el proxy
    session = Session()
    session.proxies = {
        'http': f'http://{PROXY_HOST}:{PROXY_PORT}',
        'https': f'http://{PROXY_HOST}:{PROXY_PORT}',
    }

    # Crear el cliente SOAP
    client = Client(WSDL_HOMOLOGACION, transport=Transport(session=session))

    try:
        # Llamar al método loginCms del servicio
        result = client.service.loginCms(in0=request)

        # se genera el archivo con el ticket de acceso a la afip
        with open(ARCHIVO_TICKET_DE_ACCESO_AFIP, "w") as response_file:
            response_file.write(result)

        return result

    except Fault as fault:
        print(f"SOAP Fault: {fault.code}\n{fault.message}\n")
        return None


def crear_tra(servicio, hoy, tra):

    hoy_iso = (hoy - datetime.timedelta(seconds=60)).isoformat()
    maniana = hoy + + datetime.timedelta(days=1)
    maniana_iso = (maniana - datetime.timedelta(seconds=60)).isoformat()

    root = etree.Element('loginTicketRequest', version='1.0')
    header = etree.SubElement(root, 'header')
    etree.SubElement(header, 'uniqueId').text = str(int(time.time()))

    etree.SubElement(header, 'generationTime').text = hoy_iso
    etree.SubElement(header, 'expirationTime').text = maniana_iso

    etree.SubElement(root, 'service').text = servicio
    tree = etree.ElementTree(root)
    tree.write(tra, xml_declaration=True, encoding='UTF-8', pretty_print=True)


def create_embeded_pkcs7_signature(tra_hoy: str, cert: bytes, key: bytes) -> bytes:
    # def create_embeded_pkcs7_signature(data: bytes, cert: bytes, key: bytes) -> bytes:
    """Creates an embedded ("nodetached") PKCS7 signature.

    This is equivalent to the output of::

        openssl smime -sign -signer cert -inkey key -outform DER -nodetach < data
    """

    with open(tra_hoy, "r") as xml_login_file:
        xml_login_data = xml_login_file.read()

    # Convert the XML data to bytes using encode() method
    xml_login_bytes_data = xml_login_data.encode('utf-8')

    with open(cert, "rb") as cert_file:
        cert_data = cert_file.read()

    with open(key, "rb") as pk_file:
        pk_data = pk_file.read()

    try:
        pkey = load_pem_private_key(pk_data, None)
        signcert = load_pem_x509_certificate(cert_data)
    except Exception as e:
        print(f"{e}")
        return None

    return (
        PKCS7SignatureBuilder()
        .set_data(xml_login_bytes_data)
        .add_signer(signcert, pkey, hashes.SHA256())
        .sign(Encoding.DER, [PKCS7Options.Binary])
    )


# Function to parse the XML and check expiration time
def verifico_vigencia_del_ticket(xml_file_path):
    # Parse the XML file
    tree = ET.parse(xml_file_path)
    root = tree.getroot()

    # Find the expirationTime element, le saco la info de la TimeZone
    expiration_time_str = root.find('.//expirationTime').text

    # Parse the expiration time string into a datetime object
    expiration_time = datetime.datetime.strptime(expiration_time_str, '%Y-%m-%dT%H:%M:%S.%f%z').replace(tzinfo=None)

    # Get the current time
    now = datetime.datetime.now()

    # Compare expiration time with current time
    if expiration_time > now:
        return True
    else:
        return False


def main():

    if not os.path.exists(ARCHIVO_CERTIFICADO_X509):
        print(
            f"No se pudo abrir el archivo con el Certificado X509, que debe estar ubicado en "
            f"{ARCHIVO_CERTIFICADO_X509}"
        )
        sys.exit(1)

    if not os.path.exists(ARCHIVO_CERTIFICADO_CLAVEPRIVADA):
        print(
            f"No se pudo abrir el archivo con la Clave Privada, que debe estar ubicado en "
            f"{ARCHIVO_CERTIFICADO_CLAVEPRIVADA}"
        )
        sys.exit(1)

    if not os.path.exists(WSDL_HOMOLOGACION):
        print(
            f"No se pudo abrir del WSDL del entorno de homologación, que debe estar ubicado en "
            f"{WSDL_HOMOLOGACION}"
        )
        sys.exit(1)

    # if len(sys.argv) < 2:
    #     show_usage(sys.argv[0])
    #     sys.exit(1)

    # service = sys.argv[1]

    ####################################################
    # Verifico si tengo un ticket de acceso vigente
    ####################################################
    # Verifico si hay un archivo con ticket de acceso y si se encuentra vigente
    # si no fuera así, se regenera
    ####################################################
    if not os.path.exists(ARCHIVO_TICKET_DE_ACCESO_AFIP) or \
        not verifico_vigencia_del_ticket(ARCHIVO_TICKET_DE_ACCESO_AFIP):

        print("Ticket de acceso a la AFIP Vencido -> se regenera")

        ############################
        # genero el ARCHIVO_TRA
        ############################
        crear_tra(SERVICIO, datetime.datetime.today(), ARCHIVO_TRA)

        cms_signed_data = create_embeded_pkcs7_signature(
            ARCHIVO_TRA,
            ARCHIVO_CERTIFICADO_X509,
            ARCHIVO_CERTIFICADO_CLAVEPRIVADA
        )

        request = base64.b64encode(cms_signed_data).decode()

        call_wsaa(request)

    # en este punto ya tenemos el ticket de acceso a la afip
    # en el archivo ARCHIVO_TICKET_DE_ACCESO_AFIP


if __name__ == "__main__":
    main()
