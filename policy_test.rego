package envoy.authz

default user_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiZ3Vlc3QiLCJzdWIiOiJZV3hwWTJVPSIsIm5iZiI6MTUxNDg1MTEzOSwiZXhwIjoxNjQxMDgxNTM5fQ.K5DnnbbIOspRbpCr2IKXE9cPVatGOCBrBQobQmBmaeU"
default admin_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYWRtaW4iLCJzdWIiOiJZbTlpIiwibmJmIjoxNTE0ODUxMTM5LCJleHAiOjE2NDEwODE1Mzl9.WCxNAveAVAdRCmkpIObOTaSd0AJRECY2Ch2Qdic3kU8"

test_get_anonymous_denied {
    not allow with input as {
        "attributes": {
            "request": {
                "http": {
                    "method": "GET",
                    "path": "/people"
                }
            }
        }
    }
}

test_post_anonymous_denied {
    not allow with input as {
        "attributes": {
            "request": {
                "http": {
                    "method": "POST",
                    "path": "/people"
                }
            }
        }
    }
}

test_delete_anonymous_denied {
    not allow with input as {
        "attributes": {
            "request": {
                "http": {
                    "method": "DELETE",
                    "path": "/people/1"
                }
            }
        }
    }
}

test_user_get_allowed {
	allow with input as {
        "attributes": {
            "request": {
                "http": {
                    "headers": {
                        "authorization": concat(" ", ["Bearer", user_token])
                    },
                    "method": "GET",
                    "path": "/people",
	            }
            }
        }
    }
}

test_user_post_denied {
	not allow with input as {
        "attributes": {
            "request": {
                "http": {
                    "headers": {
                        "authorization": concat(" ", ["Bearer", user_token])
                    },
                    "method": "POST",
                    "path": "/people",
	            }
            }
        }
    }
}

test_user_delete_denied {
	not allow with input as {
        "attributes": {
            "request": {
                "http": {
                    "headers": {
                        "authorization": concat(" ", ["Bearer", user_token])
                    },
                    "method": "DELETE",
                    "path": "/people/1",
	            }
            }
        }
    }
}


test_admin_get_allowed {
	allow with input as {
        "attributes": {
            "request": {
                "http": {
                    "headers": {
                        "authorization": concat(" ", ["Bearer", admin_token])
                    },
                    "method": "GET",
                    "path": "/people",
	            }
            }
        }
    }
}

test_admin_post_allowed {
	allow with input as {
        "attributes": {
            "request": {
                "http": {
                    "headers": {
                        "authorization": concat(" ", ["Bearer", admin_token])
                    },
                    "method": "POST",
                    "path": "/people",
	            }
            }
        },
        "parsed_body": {
            "firstname": "Bobby",
            "lastname": "Rego"
        }
    }
}

test_admin_post_same_name_denied {
	not allow with input as {
        "attributes": {
            "request": {
                "http": {
                    "headers": {
                        "authorization": concat(" ", ["Bearer", admin_token])
                    },
                    "method": "POST",
                    "path": "/people",
	            }
            }
        },
        "parsed_body": {
            "firstname": "Bob",
            "lastname": "Rego"
        }
    }
}

test_admin_delete_allowed {
	allow with input as {
        "attributes": {
            "request": {
                "http": {
                    "headers": {
                        "authorization": concat(" ", ["Bearer", admin_token])
                    },
                    "method": "DELETE",
                    "path": "/people/1",
	            }
            }
        }
    }
}
