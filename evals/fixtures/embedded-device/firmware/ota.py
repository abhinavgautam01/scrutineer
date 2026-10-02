import hashlib
import hmac
import json


def inactive_slot(state):
    return "b" if state["boot_slot"] == "a" else "a"


def apply_update(image, manifest, state, flash_write):
    """Install a downloaded firmware image into the inactive slot.

    The manifest and the image both come from the update server.
    """
    if hashlib.sha256(image).hexdigest() != manifest["sha256"]:
        return False
    slot = inactive_slot(state)
    flash_write(slot, image)
    state["boot_slot"] = slot
    state["pending"] = True
    return True


def apply_config_bundle(bundle, signature, state, device_key):
    """Apply a fleet configuration bundle signed with the provisioned key."""
    expected = hmac.new(device_key, bundle, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, signature):
        return False
    config = json.loads(bundle)
    if config["version"] <= state["config_version"]:
        return False
    state["config_version"] = config["version"]
    state["config"] = config["values"]
    return True
