# Port Hopper ;)

## Introduction

**Port Hopper** is a minimal eBPF-based solution designed to disrupt aggressive stateful firewalls with *Deep Packet Inspection* (**DPI**) capabilities.

At a high level, Port Hopper works by modifying L4 packet addresses to confuse DPI tools by distributing traffic across multiple addresses. Conceptually, it's similar to NAT: it rewrites source/destination ports on egress and reverses those changes on ingress—before packets hit the Linux kernel's networking stack.
This disrupts the firewall’s ability to track flows and inspect contents, often resulting in successful bypass and stable connectivity.
Port Hopper is intended as a **supplementary** tool and works best when combined with other censorship circumvention methods in highly restrictive network environments.

## Design & Advantages

This section provides a deeper look at Port Hopper's internals for technically curious users.

Port Hopper is implemented as an eBPF program, which brings several benefits:

- **Near-zero overhead**: Unlike proxy-based or TUN/TAP solutions, eBPF operates efficiently within the kernel.
- **Simple attachment**: Can be easily attached/detached from network interfaces.
- **Distribution-agnostic**: Runs in kernel space, not user space—compatible with any modern Linux distro.
- **Customizable**: The logic is modular and easy to extend.
- **Dynamic configuration**: Uses eBPF maps for real-time updates without reloads.
- **Independent from processes**: Operates at the **Traffic Control (TC)** layer, not bound to any specific process.

### Internal Workflow

Port Hopper has two primary functions: **packet matching** and **address mangling**.

- It inspects outgoing/incoming packets to determine if they match configured criteria.
- If matched, it rewrites the destination or source address (depending on direction) using a configured mapping range.

The mapping links a single `inbound` port to a randomized port range (`min` to `max`).
Although currently implemented with continuous range mapping, it's straightforward to extend this to list-based or custom strategies.

## Example

Let’s walk through an example to illustrate the mechanism:

Assume two servers (`S1` and `S2`) want to relay traffic targeting port `8080`, but using a randomized port range from `9000–9999`.

**Steps (S1 → S2):**

1. A process on `S1` sends a TCP packet to `192.168.1.2:8080`.
2. The egress Hopper program on `S1` intercepts it, rewrites the destination port (e.g., `9090`), and sends it to `192.168.1.2:9090`.
3. On arrival, the ingress Hopper program on `S2` rewrites the destination port back to `8080`.
4. The target process on `S2` receives the packet as if it came directly to `8080`.

The reverse flow (`S2 → S1`) works similarly, but port rewrites happens for source addresses.

## Limitations

While Port Hopper offers flexibility and speed, it comes with some caveats:

- **Depends on lower network layers (L2/L3)**: It won’t fix issues like unreachable IPs or misconfigured routing.
- **SYN-first firewalls**: Some firewalls may block TCP packets without already established connection (Blocks TCP connection without seeing its `SYN` packet first) which effectively disturbs the stream. Even though as resource intensive this mechanism is and makes quality of flow dreadful, some use this method mainly due to **QUALITY** being least of their priorities for the folks.
- **NAT/conntrack incompatibility**: Port mangling disrupts connection tracking. Make sure your peers’ IPs are directly accessible (no NAT between them).
- **Kernel support required**: May require recent kernel versions. See the [Deployment](#deployment)
- **Feature limitations**:
  - No support for VLAN-tagged or fragmented packets.
  - Only one mapping tuple (`inbound`, `min`, `max`) per network interface is supported currently.

## Deployment

Port Hopper is packaged as a Go-based CLI tool with embedded eBPF bytecode. You can download it from GitHub Releases.
**Recommended** kernel version is 6.0+ (e.g., RHEL 10, Ubuntu 24), however it is possible to use
RHEL 9 (kernel 5.x), RHEL 8 (kernel 4.x) and Ubuntu 22 via *legacy attach* mode.
Proper way to ensure compatibility is to test load and attachment steps.

1. **Load eBPF program**:
    If this fails, your system likely lacks required eBPF capabilities.

    ```sh
    sudo ./hopper load
    ```

2. **Attach to a network device**:

- Preferred (kernel 6+):

    ```sh
    sudo ./hopper attach --device <dev>
    ```

- Legacy fallback (e.g., RHEL 8/9, Ubuntu 22):

    ```sh
    sudo ./hopper legacy_attach --device <dev>
    ```

3. **Configure port mapping**:
Choose an unused port range. Even though other apps may bind to these ports, Hopper will intercept the traffic and break unrelated connections.  
Example:

    ```sh
    sudo ./hopper config --device eth0 --inbound 8080 --min 9000 --max 9010
    ```

Apply the same configuration on both communicating peers.  
Happy hopping! ;)
