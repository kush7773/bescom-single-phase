idf_component_register(
    SRCS "ccms_fleet_3p4w_v81.c"
    INCLUDE_DIRS "."
    EMBED_TXTFILES
        "../certs/AmazonRootCA1.pem"
        "../certs/claim_certificate.pem.crt"
        "../certs/claim_private.pem.key"
)
