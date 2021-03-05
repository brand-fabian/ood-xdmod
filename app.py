import requests
import base64
import zlib
import re
from urllib.parse import quote, unquote
import urllib3
from flask import Flask, redirect, request, Response
from uuid import uuid4
from textwrap import wrap
from lxml import etree
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
xdmod = Flask(__name__)

OOD_URL = "https://ood.example.org/pun/dev/xdmod"
XDMOD_URL = "https://xdmod.example.org"
EXCL_HEADERS = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
VERIFY=False
REPLACE_URI = [ r'/rest', r'/gui']
PRIVATE_KEY = "PRIVATE_KEY" 
CERT = "CERT"


def _pem_format(value, is_key=True):
    if is_key:
        return '-----BEGIN PRIVATE KEY-----\n' + '\n'.join(wrap(value, 64)) + '\n-----END PRIVATE KEY-----\n'
    else:
        return '-----BEGIN CERTIFICATE-----\n' + '\n'.join(wrap(value, 64)) + '\n-----END CERTIFICATE-----\n'


def sign_xml(
    value,
    key = PRIVATE_KEY,
    cert = CERT,
    namespaces={
        'saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
        'samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
        'md': 'http://schemas.xmlsoap.org/soap/envelope/',
        'xs': 'urn:oasis:names:tc:SAML:2.0:metadata',
        'xsi': 'http://www.w3.org/2001/XMLSchema',
        'xenc': 'http://www.w3.org/2001/XMLSchema-instance',
        'ds': 'http://www.w3.org/2000/09/xmldsig#',
    }
):
    import xmlsec
    sign_algorithm_transform = xmlsec.Transform.RSA_SHA256
    digest_algorithm_transform = xmlsec.Transform.SHA256
    sig = value.xpath('/samlp:Response/ds:Signature', namespaces=namespaces)[0]
    sig.getparent().remove(sig)

    signature = xmlsec.template.create(value, xmlsec.Transform.EXCL_C14N,
                                       sign_algorithm_transform, ns='dsig')

    issuer = value.xpath('/samlp:Response/saml:Issuer', namespaces=namespaces)
    if len(issuer) > 0:
        issuer = issuer[0]
        root = issuer.getparent()
        root.insert(root.index(issuer)+1, signature)
        elem_to_sign = root
    else:
        raise Exception("No issuer found in xml.")

    elem_id = elem_to_sign.get('ID', None)
    if elem_id is not None:
        if elem_id:
            elem_id = '#' + elem_id
    else:
        elem_id = '#' + uuid4().hex

    xmlsec.tree.add_ids(elem_to_sign, ["ID"])
    
    ref = xmlsec.template.add_reference(signature, digest_algorithm_transform,
                                        uri=elem_id)
    xmlsec.template.add_transform(ref, xmlsec.Transform.ENVELOPED)
    xmlsec.template.add_transform(ref, xmlsec.Transform.EXCL_C14N)
    key_info = xmlsec.template.ensure_key_info(signature)
    xmlsec.template.add_x509_data(key_info)

    dsig_ctx = xmlsec.SignatureContext()
    sign_key = xmlsec.Key.from_memory(_pem_format(key), xmlsec.KeyFormat.PEM, None)
    sign_key.load_cert_from_memory(_pem_format(cert, is_key=False), xmlsec.KeyFormat.PEM)

    dsig_ctx.key = sign_key
    dsig_ctx.sign(signature)

    return etree.tostring(value)


def decode_to_etree(value):
    saml_resp  = base64.b64decode(unquote(value))
    return etree.fromstring(saml_resp)


def decode_and_inflate(value):
    compressed = base64.b64decode(value)
    return zlib.decompress(compressed, -15)


def deflate_and_encode(value):
    return base64.b64encode(zlib.compress(value.encode())[2:-4])


def _proxy_url(path):
    base_url = '{}/{}'.format(XDMOD_URL, path)
    if len(request.args) > 0:
        arguments = []
        for key, value in request.args.items():
            if key.lower() == 'returnto':
                arguments.append('{}={}'.format(
                    key, quote(unquote(value).strip('"'), safe='')
                ))
            else:
                arguments.append('{}={}'.format(key, value))
        base_url += '?' + '&'.join(arguments)
    return base_url


def _proxy(path, *args, **kwargs):
    # Handle incoming login data
    data = request.get_data().decode()
    if 'SAMLResponse' in data:
        match = re.search(r"SAMLResponse=(.*?)&", data)
        if match:
            saml_resp = match.group(1)
            saml_str = base64.b64decode(unquote(saml_resp)).decode()
            saml_str = saml_str.replace(OOD_URL, XDMOD_URL)
            saml_str = quote(base64.b64encode(saml_str.encode()))
            saml_str = sign_xml(decode_to_etree(saml_str))
            saml_str = quote(base64.b64encode(saml_str))
            data = data.replace(saml_resp, saml_str)
    if 'RelayState' in data:
        data = data.replace(
            quote(OOD_URL + '/', safe=''),
            quote(XDMOD_URL + '/', safe=''),
        )
    data = data.encode()

    # Make backend request
    resp = requests.request(
        method=request.method,
        url=_proxy_url(path),
        headers={key: value for (key, value) in request.headers if key != 'Host'},
        data=data,
        cookies=request.cookies,
        allow_redirects=False,
        verify=VERIFY,
    )
    headers = [(name, value) for (name, value) in resp.raw.headers.items()
               if name.lower() not in EXCL_HEADERS]

    # Replace absolute URL's in javascript and php/html files
    if path.endswith('js') or path.endswith('html') or path.endswith('php'):
        content = resp.content.decode()
        for rep in REPLACE_URI:
            content = content.replace(rep, rep[1:])
        content = content.encode()

        # Hack XDMod login
        if path.endswith('index.php'):
            new_content = []
            for line_no, line in enumerate(content.decode().split('\n')):
                new_content.append(line.strip())
                if line_no == 15:
                    new_content.append('<script type="text/javascript" src="static/login.js"></script>')
            content = '\n'.join(new_content).encode()
        elif path.endswith('login.php'):
            new_content = []
            for line_no, line in enumerate(content.decode().split('\n')):
                if '/index.php' in line:
                    new_content.append(line.replace(
                        '/index.php',
                        OOD_URL + '/index.php',
                    ))
                else:
                    new_content.append(line)
            content = '\n'.join(new_content).encode()
    else:
        content = resp.content

    # Handle login redirects
    if resp.status_code == 302:
        headers_302 = []
        for name, value in headers:
            if name == 'Location':
                match = re.search(r"SAMLRequest=(.*?)&", value)
                if match:
                    req = match.group(1)
                    val = decode_and_inflate(unquote(req)).decode()
                    val = val.replace(XDMOD_URL, OOD_URL)
                    val = deflate_and_encode(val)
                    val = quote(val, safe='')
                    target = value.replace(req, val)
                else:
                    target = value

                if XDMOD_URL in target:
                    target = target.replace(XDMOD_URL, OOD_URL)
                elif quote(XDMOD_URL + '/', safe='') in target:
                    target = target.replace(
                        quote(XDMOD_URL + '/', safe=''),
                        quote(OOD_URL + '/', safe=''),
                    )

                # Strip simplesaml/module... part of the url
                if target.endswith('gui/general/login.php'):
                    target = OOD_URL + '/gui/general/login.php'
            else:
                target = value
            headers_302.append((name, target))
        headers = headers_302
    elif resp.status_code == 303:
        headers_303 = []
        for name, value in headers:
            if name == 'Location':
                if value.endswith('gui/general/login.php'):
                    target = OOD_URL + '/gui/general/login.php'
                elif XDMOD_URL in value:
                    target = value.replace(XDMOD_URL, OOD_URL)
                else:
                    target = value
            else:
                target = value
            headers_303.append((name, target))
        headers = headers_303
    response = Response(content, resp.status_code, headers)
    return response


@xdmod.route("/<path:path>", methods=['GET', 'POST', 'DELETE', 'PUT', 'PATCH'])
def proxy(path):
    return _proxy(path)

@xdmod.route("/")
def default():
    return redirect('index.php')

if __name__ == "__main__":
    xdmod.run()
