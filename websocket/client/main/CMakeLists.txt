idf_component_register(SRCS "main.c"
                    INCLUDE_DIRS "."
                    EMBED_TXTFILES "certs/echows_root.crt"
                                   "certs/client.crt"
                                   "certs/client_priv.key")
