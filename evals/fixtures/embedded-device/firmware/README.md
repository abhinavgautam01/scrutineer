# Sensor firmware

`boot.py` joins Wi-Fi at power-up. `main.py` polls the update server and applies
what it downloads. `ota.py` holds the update and configuration logic and has no
hardware imports, so it can be exercised on a desktop.

The device provisions `DEVICE_KEY` at the factory. Configuration bundles are
signed with the matching fleet key and carry a monotonic version.
