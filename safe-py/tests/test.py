import grpc
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from safe.stubs import safe_pb2, safe_pb2_grpc

issuer = "my-issuer"
secret = "Dmra2AFQRPzyM8:12iHei7AvUFqkrXqcjkDd7GC1oaVJvOivZqWhEpYEuipjJOLYlpPa2Z2"

channel = grpc.insecure_channel("localhost:8001")
stub = safe_pb2_grpc.SafeStub(channel)

key = ec.generate_private_key(ec.SECP256R1())
# csr = (
#     x509.CertificateSigningRequestBuilder()
#     .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "🍃")]))
#     .sign(key, hashes.SHA256())
# )

cert = stub.SignCertificate(
    safe_pb2.SignCertificateRequest(
        issuer=issuer,
        secret=secret,
        spki=key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ),
        common_name="🍃🍃🍃🍃🍃🍃🍃",
        # csr=csr.public_bytes(encoding=serialization.Encoding.DER),
    )
)

cert = x509.load_der_x509_certificate(cert.der)

print(cert.public_bytes(serialization.Encoding.PEM).decode("utf-8"))

# # colon-separated hexadecimal representation of the serial number
# serial_hex = cert.serial_number.to_bytes(
#     (cert.serial_number.bit_length() + 7) // 8, "big"
# ).hex()
# serial_hex = ":".join(serial_hex[i : i + 2] for i in range(0, len(serial_hex), 2))

# stub.RevokeCertificate(
#     safe_pb2.RevokeCertificateRequest(
#         issuer=issuer,
#         secret=secret,
#         serial=serial_hex,
#         reason=safe_pb2.RevocationReason.SUPERSEDED,
#         # reason_code=safe_pb2.RevocationReason.KEY_COMPROMISE,
#         # invalidity_date=dt.datetime.now(dt.timezone.utc).isoformat(),
#     )
# )

# stub.UpdateCrl(
#   safe_pb2.UpdateCrlRequest(
#     secret=secret,
#     issuer=issuer,
#   )
# )
