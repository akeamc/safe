import grpc
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import load_der_x509_certificate

from safe.stubs import safe_pb2, safe_pb2_grpc

issuer = "hellothere2"
secret = "ZFlAzk57MC2lx6:y4terIStio69SYopvbdTsvDPX94b0a39uvX8m38N9RzgSiUb1oxS5iJ2"

channel = grpc.insecure_channel("localhost:8001")
stub = safe_pb2_grpc.SafeStub(channel)

private_key = ec.generate_private_key(ec.SECP384R1())
spki = private_key.public_key().public_bytes(
    encoding=serialization.Encoding.DER,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)
cert = stub.SignCertificate(
    safe_pb2.SignCertificateRequest(
        issuer=issuer,
        secret=secret,
        spki=spki,
    )
)

cert = load_der_x509_certificate(cert.der)

print("Certificate:", cert.subject)
