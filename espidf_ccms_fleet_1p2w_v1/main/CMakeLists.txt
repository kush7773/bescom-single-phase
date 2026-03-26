idf_component_register(
    SRCS "ccms_fleet_1p2w_v1.c"
    INCLUDE_DIRS "."
    EMBED_TXTFILES
        "../certs/AmazonRootCA1.pem"
        "../certs/claim_certificate.pem.crt"
        "../certs/claim_private.pem.key"
)
