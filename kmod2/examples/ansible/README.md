# Ansible deploy of vcachefs to a compute cluster

Push `vcachefs.ko` + an auto-mount systemd unit to every compute node from one
control node, NFS-mount the ciphertext from the storage server, and present the
decrypted view — no per-node login. Topology: 1 storage server (ciphertext only,
no key) + N compute nodes (each decrypts locally; the key lives in the `.ko`).

## One-time prep (on the control node)
1. Build the module for the nodes' kernel, with the project key baked in:
   ```bash
   cmake -S kmod2 -B build -DKMOD2_KEYFILE=/secure/project.key.hex -DKMOD2_CC=<node-kernel-gcc>
   cmake --build build
   cp kmod2/module/vcachefs.ko kmod2/examples/ansible/files/vcachefs.ko
   ```
   `vermagic` (`modinfo vcachefs.ko`) MUST match the nodes' `uname -r`. Build one
   `.ko` per distinct kernel if the cluster is heterogeneous.
2. Pack the install tree once with the SAME key and put the `.enc` tree on the
   storage server's NFS export (`shared/vcache-pack.py`).
3. Edit `inventory.ini`: node list + `enc_src`/`enc_mnt`/`app_mnt`/`ko_dest`.
4. SSH: the control node needs key-based SSH + sudo to every node.

## Deploy
```bash
cd kmod2/examples/ansible
ansible compute -m ping                 # 1. connectivity to all nodes
ansible-playbook deploy-vcachefs.yml     # 2. configure all nodes in parallel
```
The systemd unit then mounts on every boot automatically (survives reboots).

## Notes
- The `.ko` carries the key, so it goes to each node's LOCAL disk (never onto the
  shared storage — keep the storage server ciphertext-only). `files/vcachefs.ko`
  is git-ignored for that reason; supply it at deploy time.
- vcachefs is read-only. If apps write into the mounted tree, add a local
  writable overlay (see the writable-overlay notes) — don't write to the NFS
  ciphertext.
- Order your app's service `After=vcachefs-mount.service` so it starts once the
  decrypted view is up.
- Updating the `.ko` later: `ansible compute -m systemd -a "name=vcachefs-mount state=stopped"`
  (stop apps first — a busy module can't be removed), re-copy, then start.
