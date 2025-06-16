# Steam Deck Firewall Configuration for WarpDeck

SteamOS on the Steam Deck does not have a firewall enabled by default. For WarpDeck to function correctly, especially for wireless connectivity and discovery, you may need to enable and configure the firewall. This guide provides instructions on how to set up `firewalld`, which is available on SteamOS.

## 1. Switch to Desktop Mode

First, you need to switch your Steam Deck to Desktop Mode. You can do this by pressing the `STEAM` button, navigating to `Power`, and selecting `Switch to Desktop`.

## 2. Open the Konsole Terminal

In Desktop Mode, open the Application Launcher (the icon in the bottom-left corner of the screen) and find `Konsole` under the `System` category. This will open a terminal window.

## 3. Set a `sudo` Password (if you haven't already)

To make system-level changes, you need administrator privileges. If you haven't set a password for the `deck` user, you'll need to do so. Type the following command in the Konsole and follow the prompts:

```bash
passwd
```

## 4. Enable and Start `firewalld`

By default, `firewalld` is not running. Use the following commands to enable it to start on boot and to start it immediately:

```bash
sudo systemctl enable firewalld
sudo systemctl start firewalld
```

You can check the status to make sure it's running:

```bash
sudo systemctl status firewalld
```

## 5. Configure Firewall Rules for WarpDeck

WarpDeck requires specific ports to be open for discovery (mDNS) and for data transfer. Run the following commands to add the necessary rules to your firewall.

### Allow mDNS (for device discovery)

```bash
sudo firewall-cmd --add-service=mdns --permanent
```

This command adds a permanent rule to allow mDNS traffic, which is essential for discovering other devices on the network.

### Allow WarpDeck Ports

WarpDeck uses a range of TCP ports for communication. The following command will open the default port range (54321-54325):

```bash
sudo firewall-cmd --add-port=54321-54325/tcp --permanent
```

### Reload Firewall to Apply Changes

After adding the new rules, you need to reload the firewall for the changes to take effect:

```bash
sudo firewall-cmd --reload
```

## 6. Verify the Rules

You can list the active rules to ensure they have been applied correctly:

```bash
sudo firewall-cmd --list-all
```

You should see `mdns` in the `services` list and `54321-54325/tcp` in the `ports` list.

## Conclusion

Your Steam Deck's firewall is now configured to allow WarpDeck to connect with other devices on your local network. You can now return to Gaming Mode by double-clicking the "Return to Gaming Mode" icon on the desktop. 