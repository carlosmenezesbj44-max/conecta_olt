VENDOR_RULES = {
    "Huawei": {
        "authorization_modes": ["serial"],
        "profile_fields": ["line_profile", "service_profile"],
        "move_supported": True,
        "collection_protocols": ["native", "mock", "json-file", "command", "api"],
    },
    "ZTE": {
        "authorization_modes": ["serial", "loid"],
        "profile_fields": ["line_profile", "service_profile"],
        "move_supported": True,
        "collection_protocols": ["mock", "json-file", "command", "api"],
    },
    "FiberHome": {
        "authorization_modes": ["serial"],
        "profile_fields": ["template", "vlan"],
        "move_supported": True,
        "collection_protocols": ["mock", "json-file", "command", "api"],
    },
}


def get_vendor_catalog():
    catalog = []
    for vendor, rules in VENDOR_RULES.items():
        catalog.append(
            {
                "name": vendor,
                "authorization_modes": rules["authorization_modes"],
                "profile_fields": rules["profile_fields"],
                "move_supported": rules["move_supported"],
                "collection_protocols": rules["collection_protocols"],
            }
        )
    return catalog
