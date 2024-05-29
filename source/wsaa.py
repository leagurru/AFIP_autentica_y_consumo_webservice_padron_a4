# Author: Gerardo Fisanotti - DvSHyS/DiOPIN/AFIP - 13-apr-07
# Function: Get an authorization ticket (TA) from AFIP WSAA
# Input:
#        WSDL, CERT, PRIVATEKEY, PASSPHRASE, SERVICE, URL
#        Check below for its definitions
# Output:
#        TA.xml: the authorization ticket as granted by WSAA.
#==============================================================================
import datetime
import os
import sys
import time

from lxml import etree
import xml.etree.ElementTree as ET

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.serialization.pkcs7 import PKCS7Options
from cryptography.hazmat.primitives.serialization.pkcs7 import PKCS7SignatureBuilder
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509 import load_pem_x509_certificate
import base64
from zeep import Client
from zeep.transports import Transport
from zeep.exceptions import Fault

from requests import Session

####################################################################################
# Constantes: definición
####################################################################################
WSDL = "docs/wsaa.wsdl"
ARCHIVO_CERTIFICADO_X509 = "certificados/certificado_x509.pem"
ARCHIVO_CERTIFICADO_CLAVEPRIVADA = "certificados/claveprivada.pk"
PASSPHRASE = None  # Sin passphrase si la clave privada no está encriptada
PROXY_HOST = "10.1.1.10"
PROXY_PORT = 51966
URL_TESTING_LOGIN = "https://wsaahomo.afip.gov.ar/ws/services/LoginCms"
URL_PRODUCCION_LOGIN = "https://wsaa.afip.gov.ar/ws/services/LoginCms"
SERVICIO = "ws_sr_padron_a4"
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
    client = Client(WSDL, transport=Transport(session=session))

    try:
        # Llamar al método loginCms del servicio
        result = client.service.loginCms(in0=request)

        # Guardar las solicitudes y respuestas SOAP en archivos
        # with open("request-loginCms.xml", "w") as request_file:
        #     request_file.write(str(client.transport.last_sent))

        with open("response-loginCms.xml", "w") as response_file:
            response_file.write(result)
            # response_file.write(str(client.transport.last_received))

        return result

    except Fault as fault:
        print(f"SOAP Fault: {fault.code}\n{fault.message}\n")
        return None


def obtener_o_crear_tra(servicio, hoy, tra):

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
    # expiration_time = datetime.datetime.strptime(expiration_time_str, '%Y-%m-%dT%H:%M:%S')
    expiration_time = datetime.datetime.strptime(expiration_time_str, '%Y-%m-%dT%H:%M:%S.%f%z').replace(tzinfo=None)

    # Get the current time
    # Get the current time with timezone info
    now = datetime.datetime.now()

    # Format the datetime object to the desired string format
    formatted_now = now.strftime('%Y-%m-%dT%H:%M:%S.%f%z')

    # now = datetime.datetime.now().isoformat()  # Use the same timezone as the expiration time
    # now = datetime.datetime.now(expiration_time.tzinfo)  # Use the same timezone as the expiration time

    # Compare expiration time with current time
    if expiration_time > now:
        return True
    else:
        return False


def main():

    if not os.path.exists(ARCHIVO_CERTIFICADO_X509):
        print(f"Failed to open {ARCHIVO_CERTIFICADO_X509}")
        sys.exit(1)

    if not os.path.exists(ARCHIVO_CERTIFICADO_CLAVEPRIVADA):
        print(f"Failed to open {ARCHIVO_CERTIFICADO_CLAVEPRIVADA}")
        sys.exit(1)

    if not os.path.exists(WSDL):
        print(f"Failed to open {WSDL}")
        sys.exit(1)

    # if len(sys.argv) < 2:
    #     show_usage(sys.argv[0])
    #     sys.exit(1)

    # service = sys.argv[1]

    ####################################################
    # Verifico si tengo un ticket de acceso vigente
    ####################################################
    # Verifico si hay un archivo con ticket de acceso
    # si existe, verifico que se encuentre vigente
    ####################################################
    if os.path.exists(ARCHIVO_TICKET_DE_ACCESO_AFIP):
        if verifico_vigencia_del_ticket(ARCHIVO_TICKET_DE_ACCESO_AFIP):
            print(f"Ticket Vigente en el archivo {ARCHIVO_TICKET_DE_ACCESO_AFIP}: no se requiere regenerarlo")
            sys.exit(1)
        else:
            print("Ticket Vencido")

    # en este punto, o no hay archivo con el ticket de acceso o se encuentra vencido

    # Verifico si existe el tra.xml del día de hoy, si no existe lo genero
    # para reutilizarlo ya que tiene una duración de un día entre generación y expiración
    hoy_str = datetime.datetime.today().strftime("%Y-%m-%d")
    tra_hoy = f"docs/{hoy_str}-tra.xml"
    if not os.path.exists(tra_hoy):
        obtener_o_crear_tra(SERVICIO, datetime.datetime.today(), tra_hoy)

    cms_signed_data = create_embeded_pkcs7_signature(tra_hoy, ARCHIVO_CERTIFICADO_X509, ARCHIVO_CERTIFICADO_CLAVEPRIVADA)
    request = base64.b64encode(cms_signed_data).decode()

    ticket_de_acceso = call_wsaa(request)
    print(ticket_de_acceso)


if __name__ == "__main__":
    main()
