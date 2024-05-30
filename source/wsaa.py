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
import json
import os
import sys
import time
import base64
import xml.etree.ElementTree as ET
import configparser

from pathlib import Path
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
from zeep.helpers import serialize_object
from requests import Session


def call_wsaa(request, wsdl, proxy_host, proxy_port, archivo_ticket_de_acceso_afip):

    # Configurar el proxy
    session = Session()
    session.proxies = {
        'http': f'http://{proxy_host}:{proxy_port}',
        'https': f'http://{proxy_host}:{proxy_port}',
    }

    # Crear el cliente SOAP
    client = Client(wsdl, transport=Transport(session=session))

    try:
        # Llamar al método loginCms del servicio
        result = client.service.loginCms(in0=request)

        # se genera el archivo con el ticket de acceso a la afip
        with open(archivo_ticket_de_acceso_afip, "w") as response_file:
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


def create_embeded_pkcs7_signature(tra: str, cert: bytes, key: bytes) -> bytes:
    """Creates an embedded ("nodetached") PKCS7 signature.

    This is equivalent to the output of::

        openssl smime -sign -signer cert -inkey key -outform DER -nodetach < data
    """

    with open(tra, "r") as xml_login_file:
        xml_login_data = xml_login_file.read()

    # Convert the XML data to bytes using encode() method
    xml_login_bytes_data = xml_login_data.encode('utf-8')

    with open(cert, "rb") as cert_file:
        cert_data = cert_file.read()

    with open(key, "rb") as pk_file:
        pk_data = pk_file.read()

    try:
        pkey = load_pem_private_key(pk_data, None)  # mi pk está sin clave
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


def obtener_token_sign(xml_file_path):
    # Parse the XML file
    tree = ET.parse(xml_file_path)
    root = tree.getroot()

    # Encontrar el elemento "token"
    token_str = root.find('.//token').text

    # Encontrar el elemento "sign"
    sign_str = root.find('.//sign').text

    return token_str, sign_str


def crear_soap_envelope(
        id_persona,
        cuit_representada,
        archivo_ticket_de_acceso_afip
):

    # obtengo token y sign del archivo_ticket_de_acceso_afip
    token, sign = obtener_token_sign(archivo_ticket_de_acceso_afip)

    # Crear el elemento raíz con los nombres de espacio
    envelope = ET.Element('soapenv:Envelope', attrib={
        'xmlns:soapenv': 'http://schemas.xmlsoap.org/soap/envelope/',
        'xmlns:a4': 'http://a4.soap.ws.server.puc.sr/'
    })

    # Crear los elementos Header y Body
    header = ET.SubElement(envelope, 'soapenv:Header')
    body = ET.SubElement(envelope, 'soapenv:Body')

    # Crear el elemento getPersona dentro del Body
    get_persona = ET.SubElement(body, 'a4:getPersona')

    # Añadir los elementos token, sign, cuitRepresentada e idPersona
    token_element = ET.SubElement(get_persona, 'token')
    token_element.text = token

    sign_element = ET.SubElement(get_persona, 'sign')
    sign_element.text = sign

    cuit_representada_element = ET.SubElement(get_persona, 'cuitRepresentada')
    cuit_representada_element.text = cuit_representada

    id_persona_element = ET.SubElement(get_persona, 'idPersona')
    id_persona_element.text = id_persona

    # Convertir el árbol XML a una cadena
    xml_str = ET.tostring(envelope, encoding='unicode', method='xml')

    return xml_str


def call_ws_sr_padron_a4(
        id_persona,
        cuit_representada,
        wsdl_padron_a4,
        proxy_host,
        proxy_port,
        archivo_ticket_de_acceso_afip
):

    # Configurar el proxy
    session = Session()
    session.proxies = {
        'http': f'http://{proxy_host}:{proxy_port}',
        'https': f'http://{proxy_host}:{proxy_port}',
    }

    # Crear el cliente SOAP
    client = Client(wsdl_padron_a4, transport=Transport(session=session))

    try:

        # obtengo token y sign del archivo_ticket_de_acceso_afip
        token, sign = obtener_token_sign(archivo_ticket_de_acceso_afip)

        result = client.service.getPersona(
            sign=sign,
            token=token,
            cuitRepresentada=cuit_representada,
            idPersona=id_persona
        )

        return result

    except Fault as fault:
        print(f"SOAP Fault: {fault.code}\n{fault.message}\n")
        return None


def main():
    ####################################################################################
    # Constantes: definición. Se obtienen del config.ini
    ####################################################################################
    BASE_DIR = Path(__file__).resolve().parent.parent
    config = configparser.RawConfigParser()
    config.read(BASE_DIR / "config.ini")

    INTRANET = config.getboolean('ENTORNO', 'INTRANET')
    DESARROLLO = config.getboolean('ENTORNO', 'DESARROLLO')
    TESTING = config.getboolean('ENTORNO', 'TESTING')

    DEBUG = DESARROLLO

    WSDL_WSAA = config.get('HOMOLOGACION', 'WSDL_WSAA')
    WSDL_PADRON_A4 = config.get('HOMOLOGACION', 'WSDL_PADRON_A4')
    ARCHIVO_CERTIFICADO_X509 = config.get('HOMOLOGACION', 'ARCHIVO_CERTIFICADO_X509')
    ARCHIVO_CERTIFICADO_CLAVEPRIVADA = config.get('HOMOLOGACION', 'ARCHIVO_CERTIFICADO_CLAVEPRIVADA')
    PASSPHRASE = config.get('HOMOLOGACION', 'PASSPHRASE')
    PROXY_HOST = config.get('HOMOLOGACION', 'PROXY_HOST')
    PROXY_PORT = config.getint('HOMOLOGACION', 'PROXY_PORT')
    SERVICIO = config.get('HOMOLOGACION', 'SERVICIO')
    ARCHIVO_TRA = config.get('HOMOLOGACION', 'ARCHIVO_TRA')
    ARCHIVO_TICKET_DE_ACCESO_AFIP = config.get('HOMOLOGACION', 'ARCHIVO_TICKET_DE_ACCESO_AFIP')
    CUIT_REPRESENTADA = config.get('HOMOLOGACION', 'CUIT_REPRESENTADA')
    ARCHIVO_RESPUESTA_GETPERSONA = config.get('HOMOLOGACION', 'ARCHIVO_RESPUESTA_GETPERSONA')

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

    if not os.path.exists(WSDL_WSAA):
        print(
            f"No se pudo abrir el WSDL_WSAA, que debe estar ubicado en "
            f"{WSDL_WSAA}"
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

        call_wsaa(request, WSDL_WSAA, PROXY_HOST, PROXY_PORT, ARCHIVO_TICKET_DE_ACCESO_AFIP)
    else:
        print(f"El ticket de acceso a la AFIP está vigente, está en el archivo {ARCHIVO_TICKET_DE_ACCESO_AFIP}")

    # en este punto ya tenemos el ticket de acceso a la AFIP en el archivo ARCHIVO_TICKET_DE_ACCESO_AFIP
    # vamos a recorrer los cuits de prueba de la AFIP para generar las respuestas las
    # id_personas = [
    #     20002307554,
    #     20002460123,
    #     20188192514,
    #     20221062583,
    #     20200083394,
    #     20220707513,
    #     20221124643,
    #     20221064233,
    #     20201731594,
    #     20201797064
    # ]

    cuites_personas_fisicas = [
        20002307554,
        20002460123,
        20188192514,
        20221062583,
        20200083394,
        20220707513,
        20221124643,
        20221064233,
        20201731594,
        20201797064
    ]

    cuiles_personas_fisicas = [
        20203032723,
        20168598204,
        20188153853,
        20002195624,
        20002400783,
        20187850143,
        20187908303,
        20187986843,
        20188027963,
        20187387443
    ]

    cuites_personas_juridicas = [
        30202020204,
        30558515305,
        30558521135,
        30558525025,
        30558525645,
        30558529535,
        30558535365,
        30558535985,
        30558539565,
        30558564675
    ]

    id_personas = cuites_personas_fisicas + cuiles_personas_fisicas + cuites_personas_juridicas

    for id_persona in id_personas:

        respuesta = call_ws_sr_padron_a4(id_persona, CUIT_REPRESENTADA, WSDL_PADRON_A4, PROXY_HOST, PROXY_PORT, ARCHIVO_TICKET_DE_ACCESO_AFIP)
        if respuesta is None:
            print(f"No se obtuvo respuesta del padron_a4 para el CUIT {id_persona}")
        else:

            # se genera el archivo con la respuesta del padron_a
            # conversión de la respuesta a dictionary
            # la respuesta vuelve con el tipo <class 'zeep.objects.personaReturn'>

            # Convertir el objeto zeep a un diccionario
            result_dict = serialize_object(respuesta)

            # Convertir el diccionario a una cadena JSON
            result_json = json.dumps(result_dict, indent=4, default=str)

            archivo_respuesta_id_persona = f"{ARCHIVO_RESPUESTA_GETPERSONA}-cuit={id_persona}.json"
            # Escribir la cadena JSON a un archivo
            with open(archivo_respuesta_id_persona, 'w') as file:
                file.write(result_json)

            print(f"La respuesta de la AFIP del webservice del padron_a4 para el CUIT {id_persona} está en el archivo {archivo_respuesta_id_persona}")

if __name__ == "__main__":
    main()
