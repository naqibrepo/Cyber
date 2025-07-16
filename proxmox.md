
===============================================================================
# CLI
```
---------------------------
# VM Management

qm						# qemu manager
man qm
qm list						# list VMs
qm start/shutdown/reboot... <id>		# start/stop VMs
qm reset/stop <id>				# hard reboot/stop
qm config <id>					# VM info

----------------------------
# set VM options

qm config <id>					# VM info
qm set --<optoin>/-<option> <value> <id>
qm set --onboot 0 101				# set the Start at boot to "no"

----------------------------
# Container Commands

same commands as VM:
pct list					# list containers
pct start/shutdown <id>
pct config					# containers info

pct enter <id>					# get inside the container (getting a shell)

pct set --<optoin>/-<option> <value> <id>
```

===============================================================================
# VM Migration
```
vmware-vdiskmanager -r vmname.vmdk -t 0 vmname-single.vmdk


qemu-img convert -f vmdk -O raw vmname-single.vmdk vm-999-disk-0.raw
qm create 999 --name ubuntu-migrated --memory 2048 --net0 virtio,bridge=vmbr0 --ostype l26 --scsihw virtio-scsi-pci
qm set 999 --scsi0 local-lvm:20
dd if=/var/lib/vz/images/999/vm-999-disk-0.raw of=/dev/pve/vm-999-disk-0 bs=4M status=progress



```
