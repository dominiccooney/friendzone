# Guest network isolation and recovery

**Do this before giving an agent untrusted input or valuable credentials.**
`HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`, a trusted CA, and a passing
`fz doctor` do **not** confine a VM. A process can ignore those variables,
and a guest administrator can remove guest firewall rules or add a route.
Enforce the restriction on the host, virtual switch, or an external gateway
that the guest cannot configure.

Friendzone does not install these network rules for you. The Hyper-V example
below is based on Microsoft's documented extended ACL cmdlets; its syntax
was checked against the installed module, but the ACLs were **not applied or
validated against a live VM** during development. Treat the negative tests
below as deployment requirements, not optional diagnostics.

## Two separate boundaries

1. **Guest egress:** the guest may connect only to two host listener ports.
2. **Management isolation:** neither direct guest traffic **nor requests via
   the proxy** may reach the UI/API. It controls approvals, permissions,
   imported host files, and credentials; it is a privileged local interface,
   not an authenticated multi-user service.

| Guest destination | Protocol | Policy | Purpose |
|---|---|---|---|
| Broker's guest-facing IP, port 8080 | TCP | Allow | Explicit HTTP/HTTPS proxy |
| Same IP, port 8082 | TCP | Allow | CA/binary/env bootstrap, health, guest announcement, MCP forwards |
| Any address, UI port 8081 | Any | Deny | Host management only |
| Internet, LAN, other host ports, other guests | Any | Deny | Prevent direct bypass and host access |
| Direct DNS (53), DoT (853), QUIC (UDP/443), SSH (22), other UDP | Any | Deny | No alternate guest egress |
| IPv6 | Any | Deny unless explicitly configured with equivalent rules | No IPv6/link-local bypass |

Use the actual configured ports, not these defaults if you changed them.
With today's architecture, **"only through the proxy" also needs the narrow
8082 exception**. Blocking it prevents setup/recovery and direct MCP access.
It is not the management port. `/api/containers` and other management routes
are not exposed on the bootstrap listener.

The host broker itself still needs Internet/DNS access for inference,
upstream HTTP requests, MCP, and OAuth. Do not apply the guest egress deny to
the host process or the whole host. The guest can use a numeric broker IP;
the broker resolves upstream names, so normal proxied HTTPS does not require
guest DNS. ARP needed to reach the IPv4 host on-link is not Internet egress.
If your platform requires DHCP or IPv6 neighbor discovery, that is additional
explicit infrastructure policy; the static IPv4 example below needs no DHCP.

### Management and loopback protection in this build

`fz broker` now rejects non-loopback `--ui-addr` and requires its fixed port
to differ from the proxy/bootstrap ports. The proxy rejects HTTP requests
and CONNECTs to that management destination port **on every hostname/IP**,
including aliases. This deliberately also denies unrelated Internet servers
using that port; using a dedicated UI port such as 8081 is recommended.

Older builds could proxy an approved guest's request to
`http://127.0.0.1:8081/api/containers`: loopback binding alone was insufficient.
Upgrade before treating the UI as isolated, and test both paths below.

The proxy also rejects requests to loopback destinations except on the port
configured by `--bootstrap-addr` (8082 by default). The same rule covers HTTP,
HTTPS CONNECT, and decrypted requests: `127.0.0.0/8`, `localhost` and names
ending in `.localhost`, `::1`, and IPv4-mapped/compatible IPv6 loopback.
Numeric aliases such as `127.1`, `2130706433`, and `0x7f000001` are normalized
for this check. A stray guest Cline hub probe to `127.0.0.1:25463/health`
returns **403** and is logged as blocked, with no upstream connection and no
approvable Inbox item. Client `NO_PROXY` settings are not needed to enforce it.

The bootstrap exception follows the configured port, not a hardcoded 8082;
it never overrides guest approval/IP/Kill gates or management-port denial.
It does not redirect the destination or make a guest-facing-only bootstrap
listener reachable at loopback. Bind the bootstrap listener appropriately
or use its guest-facing IP. When configured with port zero, no loopback
exception is granted. Listener configuration changes take effect on restart.
Keep guest `NO_PROXY`/`no_proxy` exclusions and restart stale guest processes
as well: correct clients should contact their own hub directly, not get 403s.

Do not publish the UI via portproxy, SSH forwarding accessible to the guest,
a reverse proxy, WSL localhost forwarding, or another port: a relay would
defeat a destination-port guard. The broker is **not a general SSRF-safe
public-only proxy**: these guards protect its management port and recognized
loopback destinations, not every local/LAN service reachable from the broker.
In particular, arbitrary DNS names resolving/rebinding to loopback, host LAN
addresses, and relays are not covered by the loopback-name check. Host service
isolation, DNS/connector address pinning, and proxy destination restrictions
need a broader security review before using it as a hardened sandbox. A network allowlist also does
not prevent malicious traffic over otherwise permitted HTTPS. Current proxy
policies are deliberately incomplete; see the README's scope limitations.

## Stage deployment so a broken setup is recoverable

### A. Build a clean image (not an agent session)

- Start with a trusted VM and **no autonomous agent/untrusted tasks running**.
- Install OS updates, build tools, `fz`, Git, Cline, and diagnostic tools.
  Build the correct guest OS/architecture binary before removing build-time
  Internet access. You can alternatively supply it via ISO/offline transfer.
- Keep a known-good `fz` binary and CA/env files available offline. Host
  `/bootstrap/fz` is the host binary, not necessarily executable in Linux.
- Make a clean snapshot/clone. Do not snapshot real provider secrets into it.
- Open **VMConnect / hypervisor console** and prove login works. SSH over the
  network you are about to block is not a recovery plan.
- Save current NIC/switch/rule settings on the **host**; retain a host admin
  terminal. Decide stable guest/host IPs and a subnet that does not collide
  with LAN, VPN, Docker or WSL routes.

Temporary unrestricted networking is only for preparing this clean image.
If an agent has already handled hostile material, stop it and recover from
a clean image instead of reconnecting that guest to unrestricted networking.

### B. Test Friendzone before sealing

Run the broker with guest-facing proxy/bootstrap addresses and loopback UI.
Run setup, approve the guest, source its env file, and test:

- direct bootstrap `/health` and CA fetch;
- an HTTPS request through the proxy with CA verification enabled;
- Git fetch/clone and an actual small inference request;
- the generated guest MCP configuration, including its Basic header;
- host OAuth callback and automatic refresh, independent of guest login.

Do not assume a TCP-only doctor pass proves any of these. For guests with
different networking after the switch change, repeat setup against the new
host address. Changing a guest IP may require updating its approval pin.

### C. Seal on the host, while the guest is shut down

Attach it only to an isolated, host-managed network. Apply allow rules for
the two service ports, then final default denies, then boot using the console.
Remove/disconnect secondary NICs, default/shared NAT/external switch paths,
USB NIC passthrough, VPN/tunnel paths, and forwarding relays. Apply rules to
**every** guest interface; recheck after cloning or adding a NIC.

Do not run hostile workloads during this transition. A clean shutdown/boot
also avoids relying on how the platform treats connections established before
new rules were installed. Disable guest autorun agents until verification.

### D. Verify, then run the agent

Repeat positive and negative tests after lockdown and after a reboot. Record
the policy/rule output and packet-counter evidence. Only then enable the agent.
Broker down should mean Internet access fails closed, not direct fallback.
Recovery should remain possible via the host console and the narrow bootstrap
port when the broker comes back.

## Hyper-V: dedicated internal switch, static IPv4, extended ACLs

Run these commands yourself in an **elevated PowerShell on the Windows host**.
They are an example for a clean VM with one adapter and no pre-existing ACLs,
not an automatic migration script. `scratch-kali` here is the Hyper-V VM name,
which may differ from the Friendzone container name. Check it first.

The example uses host `172.30.240.1/30` and guest `172.30.240.2/30`. Do not use
that subnet if it overlaps anything on your host. Reserve one small subnet/
internal switch per guest if guests must not share layer-2 access. The Hyper-V
**Default Switch provides shared/NAT networking and is not this isolation**.

### Inventory and backup (read-only)

```powershell
$vm = 'scratch-kali'
$switch = 'Friendzone-scratch-kali'
$hostIP = '172.30.240.1'
$guestIP = '172.30.240.2'
$backup = Join-Path $env:USERPROFILE 'friendzone-network-backup'
New-Item -ItemType Directory -Path $backup -Force | Out-Null
Get-VM -Name $vm
Get-VMNetworkAdapter -VMName $vm | Format-List Name,SwitchName,MacAddress,IPAddresses
Get-VMNetworkAdapter -VMName $vm | Export-Clixml (Join-Path $backup 'adapters.xml')
Get-VMNetworkAdapterExtendedAcl -VMName $vm | Export-Clixml (Join-Path $backup 'extended-acls.xml')
Get-VMNetworkAdapterAcl -VMName $vm | Export-Clixml (Join-Path $backup 'acls.xml')
Get-VMSwitch
Get-NetNat
Get-NetIPAddress
```

Review IP routing, Internet Connection Sharing, RRAS, bridging, and portproxy
settings too. No NAT/routing must forward traffic from the isolated switch.
Do not disable networking/firewall globally to make this work.

### Create the isolated attachment (VM already shut down)

```powershell
$ErrorActionPreference = 'Stop'
if ((Get-VM -Name $vm).State -ne 'Off') { throw 'Shut down the clean VM through its console first.' }
$nics = @(Get-VMNetworkAdapter -VMName $vm)
if ($nics.Count -ne 1) { throw 'Review every adapter; this example requires exactly one.' }
$nic = $nics[0]
if (@(Get-VMNetworkAdapterExtendedAcl -VMNetworkAdapter $nic).Count -or
    @(Get-VMNetworkAdapterAcl -VMNetworkAdapter $nic).Count) {
    throw 'Existing policy needs review; do not overwrite or mix it with this example.'
}
if (Get-VMSwitch -Name $switch -ErrorAction SilentlyContinue) { throw 'Use a new, dedicated switch name.' }
New-VMSwitch -Name $switch -SwitchType Internal | Out-Null
$hostInterface = "vEthernet ($switch)"
New-NetIPAddress -InterfaceAlias $hostInterface -IPAddress $hostIP -PrefixLength 30 | Out-Null
Connect-VMNetworkAdapter -VMNetworkAdapter $nic -SwitchName $switch
Set-VMNetworkAdapter -VMNetworkAdapter $nic -MacAddressSpoofing Off -DhcpGuard On -RouterGuard On
```

**Do not create a NAT, bridge, external uplink, or default gateway for this
switch.** This is host-to-guest connectivity, not Internet sharing.

### Apply the VM's port allowlist

ACL direction is from the **VM's perspective**. Higher weights win; the
stateful allow admits return traffic. The terminal denies match all IPv4
and IPv6 destinations and all protocols (protocol omitted). These aren't
Windows Firewall precedence rules; don't transplant the weights into those.

```powershell
$nic = Get-VMNetworkAdapter -VMName $vm -Name $nic.Name
Add-VMNetworkAdapterExtendedAcl -VMNetworkAdapter $nic -Direction Outbound -Action Allow `
    -LocalIPAddress "$guestIP/32" -RemoteIPAddress "$hostIP/32" -Protocol TCP -RemotePort 8080 `
    -Weight 65030 -Stateful $true -IdleSessionTimeout 3600
Add-VMNetworkAdapterExtendedAcl -VMNetworkAdapter $nic -Direction Outbound -Action Allow `
    -LocalIPAddress "$guestIP/32" -RemoteIPAddress "$hostIP/32" -Protocol TCP -RemotePort 8082 `
    -Weight 65020 -Stateful $true -IdleSessionTimeout 3600
Add-VMNetworkAdapterExtendedAcl -VMNetworkAdapter $nic -Direction Outbound -Action Deny `
    -RemoteIPAddress ANY -Weight 64900
Add-VMNetworkAdapterExtendedAcl -VMNetworkAdapter $nic -Direction Inbound -Action Deny `
    -RemoteIPAddress ANY -Weight 64890
Get-VMNetworkAdapterExtendedAcl -VMNetworkAdapter $nic | Format-List *
```

Keep the VM off if any command fails; inspect partial rules before retrying.
The allow rules also constrain the guest's source IPv4 address. MAC spoofing
off is not by itself an IP-spoofing defense. Other guests must not be able to
take this guest's source address; per-guest networks and host-enforced source
policy matter because Friendzone identity is not a password-based secret.

If host Windows Firewall blocks inbound service connections, add a narrow
rule for these ports, addresses, and interface—never the UI or all ports:

```powershell
New-NetFirewallRule -Name 'Friendzone-scratch-kali-services' `
    -DisplayName 'Friendzone scratch-kali proxy and bootstrap only' `
    -Direction Inbound -Action Allow -Protocol TCP -LocalPort 8080,8082 `
    -LocalAddress $hostIP -RemoteAddress $guestIP -InterfaceAlias $hostInterface -Profile Any
```

Enterprise rules may override local policy. Check the effective policy;
an explicit broad Windows Firewall block is not bypassed by a narrow allow.

Boot from VMConnect. Configure the guest adapter's static IPv4 to
`172.30.240.2/30`, with **no gateway and no DNS server**, using its console/
NetworkManager. The ACL intentionally denies DHCP and IPv6; a stale DHCP
configuration will not acquire this address. Do not add another NAT NIC to
"fix" it. Run the broker on `172.30.240.1:8080` and `172.30.240.1:8082`, UI
`127.0.0.1:8081`, and rerun guest setup with `http://172.30.240.1:8082`.

This example uses switch ACLs for a conventional Hyper-V VM. Windows 11
`New-NetFirewallHyperVRule` / WSL `VMCreatorId` settings are a different
interface; **do not paste a WSL GUID as though it were your VM ID**. WSL's
loopback forwarding can grant host access outside ordinary per-port rules;
it needs its own deployment-specific review.

## Verification from the guest

Use the actual isolated host IP and container name. Read-only probes below
do not change approvals or permissions. For this example:

```sh
export FZ_HOST=172.30.240.1
export FZ_PROXY=http://scratch-kali:x@172.30.240.1:8080

# Must succeed directly: required for setup/recovery, even before approval.
curl --noproxy '*' --connect-timeout 3 --max-time 5 -i "http://$FZ_HOST:8082/health"

# Must succeed after approval/CA setup: uses the proxy, not direct egress.
curl --noproxy '' --proxy "$FZ_PROXY" --connect-timeout 3 --max-time 15 \
  --cacert /home/kali/.config/friendzone/friendzone-ca.pem -I https://example.com/

# Must not connect directly to the host UI.
curl --noproxy '*' --connect-timeout 3 --max-time 5 -i "http://$FZ_HOST:8081/api/state"

# Must be denied by Friendzone, not return management JSON through the proxy.
curl --noproxy '' --proxy "$FZ_PROXY" --connect-timeout 3 --max-time 5 \
  -i http://127.0.0.1:8081/api/state
curl --noproxy '' --proxy "$FZ_PROXY" --connect-timeout 3 --max-time 5 \
  --proxytunnel -i http://127.0.0.1:8081/api/state

# Must return 403 (even if nothing listens): guest loopback must not hit a host hub.
curl --noproxy '' --proxy "$FZ_PROXY" --connect-timeout 3 --max-time 5 \
  -i http://127.0.0.1:25463/health
curl --noproxy '' --proxy "$FZ_PROXY" --connect-timeout 3 --max-time 5 \
  --proxytunnel -i http://127.0.0.1:25463/health

# Bootstrap listener must not serve management routes (expect 404).
curl --noproxy '*' --connect-timeout 3 --max-time 5 -i "http://$FZ_HOST:8082/api/state"

# Direct-IP Internet egress must fail, regardless of proxy env variables.
curl --noproxy '*' --connect-timeout 3 --max-time 5 -I http://1.1.1.1/
curl --noproxy '*' --connect-timeout 3 --max-time 5 -I 'http://[2606:4700:4700::1111]/'

# Direct DNS must fail (install dig in the clean image, before lockdown).
dig +time=2 +tries=1 @1.1.1.1 example.com
dig +tcp +time=2 +tries=1 @1.1.1.1 example.com
```

Also probe a **known listening, host-controlled** TCP service on a disallowed
port and a receiver for UDP/443, UDP/53, IPv6, and guest-to-guest traffic.
Inspect host/switch counters or packet captures: a curl timeout to a server
that was never reachable, or `nc -u`'s "success", is not proof of enforcement.
Check every adapter, address family, host IP/alias and any management relay.
Repeat after reboot. Confirm that changing proxy variables or guest routes
cannot defeat the host policy. Keep CA validation enabled; `curl -k` would
hide a broken setup instead of validating it.

`fz doctor` still does **not** verify default-deny egress, CA trust across
runtimes, or MCP/inference operation. Its TCP checks cannot replace this
acceptance matrix. In a maintenance window with the agent stopped, verify
broker failure leaves no direct Internet fallback. Do not stop an active
shared broker just to test this without scheduling the interruption.

## Recovery without opening an escape hatch

- First stop the agent, then use VMConnect/host console. Check static IP,
  switch attachment, broker bind address, service-port ACLs, approval/IP pin,
  CA path and environment. Re-fetch/re-source through the allowed bootstrap
  port; supply a replacement guest binary via ISO/offline transfer if needed.
- If the broker is down, restart/repair it from the host. The VM being unable
  to reach the Internet in the meantime is the intended fail-closed behavior.
- Keep an offline clean snapshot and host-side backup. Roll back **while the
  VM is shut down or its NIC is disconnected**, never by auto-opening egress
  on a timer while an agent may be running.
- Include the broker's `containers.json` in the host policy backup. Approval,
  explicit IP pins, kill state and removals survive restart; observed traffic
  and pending unreviewed joins do not. Restore/repair malformed policy while
  the broker is stopped rather than deleting it and guessing the previous
  restrictions. Never copy this writable policy into a guest. A restart does
  not repin a moved guest or resume a killed guest. If a policy write fails,
  the API reports failure and the old policy remains; use host VM controls to
  stop the guest if Kill cannot be saved.
- A temporary unrestricted build/update session belongs in a fresh trusted
  clone, without real keys or hostile workloads. Seal and re-test that image
  before using it as an agent guest.

For the exact Hyper-V example above, remove only its rules while the VM is
off. Leave the isolated switch attachment in place until you've decided on
a safe recovery network; never remove all host firewall rules:

```powershell
if ((Get-VM -Name $vm).State -ne 'Off') { throw 'Stop the VM before policy rollback.' }
$nic = Get-VMNetworkAdapter -VMName $vm -Name $nic.Name
foreach ($weight in 65030,65020,64900) {
    Remove-VMNetworkAdapterExtendedAcl -VMNetworkAdapter $nic -Direction Outbound -Weight $weight
}
Remove-VMNetworkAdapterExtendedAcl -VMNetworkAdapter $nic -Direction Inbound -Weight 64890
Remove-NetFirewallRule -Name 'Friendzone-scratch-kali-services'
```

These weights are safe to remove only because this recipe refused an adapter
with existing policy. Use the recorded backup if you chose a different plan.

## Other platforms

- **Tart/softnet:** use host-managed default-deny policy and explicit broker
  allowances. Softnet's documented default permits globally routable IPv4
  and host-gateway traffic: enabling softnet alone is **not** lockdown.
  An address-only `@host` allow can expose every host port; add port-level
  enforcement outside the guest. Verify your installed version's IPv6,
  source-address, DNS/DHCP and policy-reload semantics. Control sockets and
  host firewall configuration must not be exposed in guest mounts.
- **Linux container/VM host:** enforce at the host bridge/veth/netns boundary
  and separately at host INPUT, not only guest OUTPUT or host FORWARD. Docker
  and other managers can reorder/bypass naive rules; cover IPv6 and alternate
  interfaces. No privileged container, host network mode, Docker socket, or
  host configuration mounts. A VM is preferable when the agent can become
  root. No tested universal nftables/iptables recipe is provided here.
- **WSL:** shared host integration/loopback and per-creator Hyper-V Firewall
  need separate configuration; don't assume the ordinary Hyper-V VM recipe
  covers WSL.

## References

- [Microsoft: Add-VMNetworkAdapterExtendedAcl](https://learn.microsoft.com/en-us/powershell/module/hyper-v/add-vmnetworkadapterextendedacl)
- [Microsoft: Remove-VMNetworkAdapterExtendedAcl](https://learn.microsoft.com/en-us/powershell/module/hyper-v/remove-vmnetworkadapterextendedacl)
- [Microsoft: Hyper-V Firewall (including WSL loopback policy)](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/hyper-v-firewall)
- [Softnet isolation and dynamic policy](https://github.com/cirruslabs/softnet)